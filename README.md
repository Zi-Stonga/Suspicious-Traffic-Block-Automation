# Auto IP Blocker for AWS

Detects and blocks malicious source IPs at the network layer using GuardDuty,
Step Functions, and AWS Network Firewall. Fully automated, no human in the loop,
under 60 seconds from finding to DROP rule.

---

## What this does and why it exists

If you run anything externally facing on AWS long enough, you will eventually
watch the same IP addresses hammer your endpoints repeatedly. Port scanners,
brute-force tools, credential stuffers, badly behaved crawlers. The traffic is
identifiable, the source is known, and blocking it is the right call. The
question is who does the blocking and how fast.

Manual block workflows require an engineer to receive an alert, evaluate it,
and apply a rule. That works fine when attacks are slow and infrequent. It
breaks down when volume spikes, when it happens at 3am, or when the same pattern
repeats faster than people can respond. This project automates the entire
sequence so engineers are informed but not required.

---

## How the pipeline works

The architecture is event-driven and entirely serverless.

```
GuardDuty detects suspicious activity
   (port probes, brute force, bot abuse)
          |
          v
AWS Security Hub
   (normalizes and aggregates the finding)
          |
          v
Amazon EventBridge
   (filters: HIGH and CRITICAL severity, ACTIVE state, NEW workflow only)
          |
          v
AWS Step Functions State Machine
          |
          +-- [State 1] record_ip Lambda
          |       Validates the source IP
          |       Checks DynamoDB for an active duplicate (idempotency)
          |       Writes an audit record with configurable TTL expiry
          |
          +-- [State 2] block_traffic Lambda
          |       Re-validates the IP
          |       Checks rule group capacity
          |       Picks the lowest available priority slot
          |       Adds a stateless DROP rule to Network Firewall
          |       Uses UpdateToken for optimistic concurrency safety
          |
          +-- [State 3] notify Lambda
                  Publishes a structured JSON alert to SNS
                  Engineers see what was blocked, when, and when it expires
                  No action required from them

On any failure: routes to NotifyFailure state, publishes a FAILURE alert,
and Step Functions execution history captures the full trace for diagnosis.
```

---

## What gets deployed

| Resource | Purpose |
|---|---|
| AWS Network Firewall Rule Group | Stateless DROP rules for blocked IPs |
| AWS Step Functions State Machine | Orchestrates the three-step workflow |
| 3x Lambda Functions | record_ip, block_traffic, notify |
| DynamoDB Table | Audit log with TTL-enforced automatic expiry |
| EventBridge Rule | Filters HIGH/CRITICAL GuardDuty findings from Security Hub |
| SNS Topic | Delivers block notifications and CloudWatch alarms |
| KMS Customer Managed Key | Encrypts everything at rest |
| SQS Dead-Letter Queue | Captures events that fail to trigger the state machine |
| CloudWatch Alarms | Fires on SFN failures, DLQ depth, and per-Lambda errors |
| 5x IAM Roles | One per service, scoped to exact actions and resource ARNs |

---

## Security design decisions

**One IAM role per service, no shared roles.** record_ip can read and write DynamoDB.
It cannot touch the firewall. block_traffic can update the rule group. It cannot read
DynamoDB or publish to SNS. notify can publish to one SNS topic only. A compromise of
any one component does not cascade to the others.

**KMS policy lists specific IAM role ARNs.** An earlier version granted the
lambda.amazonaws.com service principal decrypt access, which meant any Lambda in any
AWS account could use the key. The policy now explicitly lists the four role ARNs that
need access.

**Blocks expire automatically.** Every DynamoDB record carries a TTL. Every block
expires. The default is 24 hours. You can change it but you cannot set it to zero
without modifying the code. Permanent automated blocks accumulate, get forgotten, and
eventually block legitimate traffic with no obvious cause.

**HIGH and CRITICAL findings only.** Running MEDIUM and LOW findings through an
automated block pipeline is how you accidentally block a CDN during a noisy scan.
GuardDuty's high-confidence findings are the correct trigger. To extend to MEDIUM,
insert a human-approval state in the Step Functions definition first.

**IP validation rejects private and reserved ranges.** The validator refuses RFC-1918,
loopback, link-local, and RFC-5737 documentation ranges before any action is taken.
This is a hard guard against a finding that contains an internal source IP causing you
to block your own infrastructure.

**Lowest-available priority, not max+1.** An earlier version always assigned
max_priority+1 to new rules. This caused priorities to grow monotonically toward the
AWS hard limit of 65535, with gaps never reclaimed after cleanup. The current version
finds the first free slot starting from priority 2.

**No shell data in Python source.** The cleanup script previously interpolated AWS API
responses directly into Python heredocs via shell variable substitution. This is a code
injection vulnerability. All data is now written to temp files and read by Python via
json.load(). File paths are passed as argv arguments. Temp directories are cleaned up
via a trap on EXIT.

**Dynamic rules isolated from static rules.** The automation manages exactly one
dedicated rule group. Your baseline firewall rules live in separate groups. A bug in
this code cannot modify or delete your existing security policy.

---

## Prerequisites

- AWS CLI v2 configured with credentials for the target account
- Terraform 1.5 or newer
- Python 3.12 (for pre-deploy syntax validation in deploy.sh)
- GuardDuty enabled in the target account and region
- Security Hub enabled with the GuardDuty integration active
- AWS Network Firewall already deployed in your VPC with a firewall policy

The last point matters. This stack creates and populates a rule group. It does not
create the firewall itself. You need to attach the rule group to your firewall policy
after deployment.

---

## Deployment

**Step 1: Configure**

```bash
git clone https://github.com/your-org/aws-auto-ip-blocker
cd aws-auto-ip-blocker
cp terraform/terraform.tfvars.example terraform/terraform.tfvars
```

Edit terraform.tfvars. The required fields are alert_email and aws_region.
Add terraform.tfvars to your .gitignore before committing.

**Step 2: Deploy**

```bash
chmod +x scripts/deploy.sh scripts/test_workflow.sh scripts/cleanup_rules.sh
./scripts/deploy.sh prod your-aws-profile
```

The script validates Lambda syntax, cleans pycache for deterministic zips, runs
terraform plan, and asks for confirmation before applying. Pass --auto-approve as the
third argument to skip the prompt in CI.

```bash
./scripts/deploy.sh prod ci-profile --auto-approve
```

**Step 3: Confirm your email subscription**

AWS sends a confirmation message to alert_email. Click the link. Nothing will be
delivered until you do.

**Step 4: Attach the rule group to your firewall policy**

In the AWS console go to Network Firewall, open your firewall policy, and add the rule
group starting with auto-ip-blocker-dynamic-prod. Set the priority so it evaluates
before your stateless default-pass rule.

**Step 5: Test end-to-end**

```bash
./scripts/test_workflow.sh your-aws-profile prod
```

Injects a synthetic finding, confirms the state machine succeeds, checks DynamoDB for
the audit record, then cleans up all test data.

---

## Running tests

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

All unit tests are isolated and require no AWS credentials.

---

## Configuration

| Variable | Default | Notes |
|---|---|---|
| aws_region | us-east-1 | Region to deploy into |
| environment | prod | prod, staging, or dev |
| alert_email | required | Receives block notifications |
| block_ttl_hours | 24 | Block duration, 1 to 720 hours |
| max_firewall_rules | 1000 | Rule group capacity, up to 30000 |
| log_retention_days | 90 | CloudWatch log retention |

---

## Day-to-day operations

**Check the active block list**

```bash
aws dynamodb scan \
  --table-name AutoBlockedIPs-prod \
  --filter-expression "expiry_time > :now" \
  --expression-attribute-values "{\":now\":{\"N\":\"$(date +%s)\"}}" \
  --output table
```

**Unblock an IP immediately**

```bash
# Find the sort key
aws dynamodb query \
  --table-name AutoBlockedIPs-prod \
  --key-condition-expression "source_ip = :ip" \
  --expression-attribute-values "{\":ip\":{\"S\":\"1.2.3.4\"}}" \
  --output json

# Delete the record (substitute the actual blocked_at value)
aws dynamodb delete-item \
  --table-name AutoBlockedIPs-prod \
  --key '{"source_ip":{"S":"1.2.3.4"},"blocked_at":{"S":"2025-01-01T00:00:00+00:00"}}'

# Sync the firewall
./scripts/cleanup_rules.sh your-aws-profile prod
```

**Prune expired rules**

```bash
./scripts/cleanup_rules.sh your-aws-profile prod
```

Run this on a schedule. The recommended approach is an EventBridge Scheduler rule
or a nightly cron in your CI system. Without regular cleanup the rule group fills
up and the capacity alarm fires.

---

## Monitoring

Four CloudWatch alarms are pre-configured, all pointing to the same SNS topic:

- State machine execution failures
- DLQ depth above zero (missed finding events)
- Lambda errors for each of the three functions

---

## Project layout

```
aws-auto-ip-blocker/
  src/
    lambda/
      record_ip/handler.py      Step 1: validate and write to DynamoDB
      block_traffic/handler.py  Step 2: update Network Firewall rule group
      notify/handler.py         Step 3: publish SNS alert
  tests/
    unit/
      test_record_ip_handler.py
      test_block_traffic_handler.py
      test_notify_handler.py
  terraform/
    main.tf                   Core infrastructure and all resource definitions
    iam.tf                    All IAM roles and least-privilege policies
    variables.tf              Input variable definitions with validation
    outputs.tf                Stack output values
    terraform.tfvars.example  Copy and fill in before deploying
  scripts/
    deploy.sh                 Pre-flight checks and Terraform deploy
    test_workflow.sh          End-to-end validation with cleanup
    cleanup_rules.sh          Prune expired rules from rule group
  docs/specs/
    00_system_overview.md
    01_architecture.md
    02_data_model.md
    03_workflows_and_api.md
    04_implementation_plan.md
    05_local_development.md
    06_result_schemas.md
    07_cloud_deployment.md
  .env.example
  requirements.txt
  requirements-dev.txt
  pytest.ini
```

---

## Known limitations

**IPv6 is not supported.** The Network Firewall stateless rule builder handles IPv4
sources only. GuardDuty findings with an IPv6 source fail validation and route to the
failure notification path. IPv6 support requires a separate stateful rule group.

**The stack does not deploy the firewall.** It assumes AWS Network Firewall is already
running in your VPC. Firewall creation, subnets, and routing are environment-specific
and not included here.

**GuardDuty and Security Hub must already be enabled.** If they are not, EventBridge
receives no events and the system sits idle without errors. Enforce their enablement
with AWS Config rules independently of this stack.

**Terraform state is local by default.** The remote S3 backend block is present but
commented out. Uncomment and configure it before treating this as a production
deployment.

---

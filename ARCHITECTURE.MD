GuardDuty
  |
  | finding (HIGH/CRITICAL, ACTIVE, NEW)
  v
Security Hub
  |
  | normalized finding event
  v
EventBridge Rule (filter: severity + state)
  |
  | on match: start execution; on failure: SQS DLQ
  v
Step Functions State Machine
  |
  +-- [State: RecordIP]
  |     Lambda: record_ip
  |     Reads: Security Hub finding event
  |     Writes: DynamoDB audit record with TTL
  |     Short-circuits on duplicate (idempotency)
  |
  +-- [State: BlockTraffic]
  |     Lambda: block_traffic
  |     Reads: source_ip from previous state output
  |     Writes: stateless DROP rule to Network Firewall rule group
  |     Uses UpdateToken for optimistic concurrency
  |
  +-- [State: NotifySuccess / NotifyFailure]
        Lambda: notify
        Reads: workflow output or error from $.error
        Writes: structured JSON message to SNS topic

SNS Topic
  Subscriptions: email (operator), CloudWatch alarms (same topic)

DynamoDB Table: AutoBlockedIPs-{env}
  Hash key:  source_ip (S)
  Range key: blocked_at (S)
  TTL attr:  expiry_time (N, Unix epoch)

Network Firewall Rule Group: auto-ip-blocker-{env}-dynamic
  Type: STATELESS
  Managed exclusively by block_traffic Lambda
  Priority 1: placeholder (RFC-5737 192.0.2.1/32)
  Priority 2+: Lambda-managed DROP rules

KMS CMK: alias/auto-ip-blocker-{env}
  Encrypts: DynamoDB, CloudWatch Logs, SNS, SQS, Lambda env vars

SQS DLQ: auto-ip-blocker-{env}-dlq
  Purpose: captures EventBridge delivery failures
  Retention: 14 days
  Alarm: fires on any message visible
output "state_machine_arn" {
  description = "ARN of the Step Functions state machine"
  value       = aws_sfn_state_machine.ip_blocker.arn
}

output "rule_group_arn" {
  description = "ARN of the Network Firewall dynamic block rule group"
  value       = aws_networkfirewall_rule_group.dynamic_blocks.arn
}

output "rule_group_name" {
  description = "Name of the rule group. Attach this to your firewall policy after deploy."
  value       = aws_networkfirewall_rule_group.dynamic_blocks.name
}

output "dynamodb_table_name" {
  description = "DynamoDB table holding the blocked-IP audit log"
  value       = aws_dynamodb_table.blocked_ips.name
}

output "sns_topic_arn" {
  description = "SNS topic ARN"
  value       = aws_sns_topic.alerts.arn
}

output "kms_key_arn" {
  description = "ARN of the CMK used for all encryption at rest"
  value       = aws_kms_key.main.arn
}

output "kms_key_alias" {
  description = "KMS alias"
  value       = aws_kms_alias.main.name
}

output "dlq_url" {
  description = "URL of the EventBridge dead-letter queue"
  value       = aws_sqs_queue.dlq.url
}

output "dlq_arn" {
  description = "ARN of the EventBridge dead-letter queue"
  value       = aws_sqs_queue.dlq.arn
}

output "eventbridge_rule_arn" {
  description = "ARN of the EventBridge rule watching Security Hub findings"
  value       = aws_cloudwatch_event_rule.guardduty_findings.arn
}

output "lambda_record_ip_arn" {
  description = "ARN of the record_ip Lambda"
  value       = aws_lambda_function.record_ip.arn
}

output "lambda_block_traffic_arn" {
  description = "ARN of the block_traffic Lambda"
  value       = aws_lambda_function.block_traffic.arn
}

output "lambda_notify_arn" {
  description = "ARN of the notify Lambda"
  value       = aws_lambda_function.notify.arn
}

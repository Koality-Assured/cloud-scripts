# CloudTrail Health & SQS Queue Monitor

Monitors SQS queues used for CloudTrail log ingestion, SIEM pipeline forwarding, and dead-letter queues (DLQ).

## Features
- **Queue Backlog Checks**: Reports visible messages, in-flight (unacknowledged) messages, and delayed messages.
- **Dead-Letter Queue (DLQ) Auditing**: Inspects redrive policies to automatically locate the associated DLQ and report undelivered messages.
- **CloudTrail Delivery Health**: Verifies trail logging status (`IsLogging`), latest delivery timestamp, and last delivery errors.
- **CI/CD & Monitoring Friendly**: Exits with non-zero status code when backlogs exceed user-defined thresholds or DLQ is non-empty.

## Usage

```bash
# Check queue depth with default threshold (1000 messages)
python cloudtrail_queue_health.py \
  --queue-url "https://sqs.us-east-1.amazonaws.com/123456789012/cloudtrail-events" \
  --profile "SecurityAuditor"

# Check both SQS queue and CloudTrail trail status
python cloudtrail_queue_health.py \
  --queue-url "https://sqs.us-east-1.amazonaws.com/123456789012/cloudtrail-events" \
  --trail-name "organization-audit-trail" \
  --threshold 500 \
  --format json
```

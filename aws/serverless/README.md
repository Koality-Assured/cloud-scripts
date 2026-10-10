# AWS Serverless & Automation Tooling

Production-grade serverless components for synthetic monitoring and automated event processing.

## Scripts

### 1. `canary_healthcheck_handler.py`
Standardized AWS Lambda healthcheck and canary handler:
- Tracks cold starts and container initialization durations.
- Returns structured JSON response suitable for API Gateway HTTP / REST APIs.
- Contextual logging with AWS Request ID tracking.

### 2. `eventbridge_s3_worker_pipeline.py`
Serverless orchestrator triggered by S3 ObjectCreated events via EventBridge or direct S3 notification:
- Validates incoming S3 keys against configurable prefix and glob patterns.
- Launches ephemeral EC2 compute workers from an AWS Launch Template with automatic self-termination (`InstanceInitiatedShutdownBehavior=terminate`).
- Injects target bucket and object key context into EC2 UserData and resource tags.

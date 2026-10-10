#!/usr/bin/env python3
"""Serverless Canary & Healthcheck Lambda Handler.

Production-grade healthcheck and synthetic canary handler for AWS Lambda.
Features:
- Structured JSON logging with request tracing
- Cold-start detection and initialization latency tracking
- Dynamic environment configuration
- Standardized HTTP/API Gateway 2.0 response format
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Module initialization timestamp (for cold start tracking)
INIT_TIME = time.time()
IS_COLD_START = True


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda entry point for synthetic canaries and healthchecks."""
    global IS_COLD_START
    start_time = time.time()

    request_id = getattr(context, "aws_request_id", "local-test-id")
    function_name = getattr(context, "function_name", "canary-healthcheck")
    function_version = getattr(context, "function_version", "$LATEST")

    environment_name = os.getenv("ENVIRONMENT", "development")
    service_name = os.getenv("SERVICE_NAME", "cloud-healthcheck")

    cold_start = IS_COLD_START
    IS_COLD_START = False

    execution_duration_ms = round((time.time() - start_time) * 1000, 2)
    uptime_seconds = round(time.time() - INIT_TIME, 2)

    payload = {
        "status": "healthy",
        "service": service_name,
        "environment": environment_name,
        "lambda": {
            "function_name": function_name,
            "version": function_version,
            "request_id": request_id,
            "cold_start": cold_start,
            "uptime_seconds": uptime_seconds,
            "execution_duration_ms": execution_duration_ms,
        },
    }

    logger.info("Healthcheck executed successfully: %s", json.dumps(payload))

    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
            "Cache-Control": "no-cache, no-store, must-revalidate",
        },
        "body": json.dumps(payload),
    }


if __name__ == "__main__":
    # Local CLI test verification
    class DummyContext:
        aws_request_id = "test-req-12345"
        function_name = "local-healthcheck-test"
        function_version = "1"

    print(json.dumps(lambda_handler({}, DummyContext()), indent=2))

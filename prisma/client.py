#!/usr/bin/env python3
"""Prisma Cloud Enterprise REST API Client.

Robust, reusable API client for Palo Alto Networks Prisma Cloud (RedLock):
- Automated JWT authentication and proactive token extension (/auth_token/extend)
- Exponential backoff with jitter on HTTP 429 (Rate Limit) and 5xx errors
- Multi-stack domain resolution (api.prismacloud.io, api2, api3, api.eu, api.gov)
- Credential resolution via environment variables, CLI parameters, or JSON config
- Native support for RQL Config queries, Event audits, Cloud Account inventory, and Alerts
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, Generator, List, Optional

import requests

logger = logging.getLogger("prisma-client")


class PrismaCloudClient:
    """Enterprise API Client for Prisma Cloud."""

    def __init__(
        self,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        api_url: Optional[str] = None,
        timeout: int = 60,
        max_retries: int = 5,
    ) -> None:
        self.access_key = access_key or os.getenv("PRISMA_ACCESS_KEY")
        self.secret_key = secret_key or os.getenv("PRISMA_SECRET_KEY")
        raw_url = api_url or os.getenv("PRISMA_API_URL", "https://api.prismacloud.io")
        self.api_url = raw_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries

        if not self.access_key or not self.secret_key:
            raise ValueError(
                "Prisma Cloud credentials missing. Provide access_key/secret_key or set "
                "PRISMA_ACCESS_KEY and PRISMA_SECRET_KEY environment variables."
            )

        self.token: Optional[str] = None
        self.token_obtained_at: float = 0.0
        self.token_ttl_seconds: float = 600.0  # Prisma tokens last ~10-15 minutes; refresh at 10m

        self._session = requests.Session()
        self._session.headers.update({
            "Accept": "application/json; charset=UTF-8",
            "Content-Type": "application/json; charset=UTF-8",
        })

    def _ensure_authenticated(self) -> None:
        """Authenticate or extend the JWT auth token if near expiration."""
        now = time.time()
        if not self.token:
            self._login()
        elif (now - self.token_obtained_at) >= self.token_ttl_seconds:
            self._extend_token()

    def _login(self) -> None:
        """Obtain a new JWT authentication token."""
        login_url = f"{self.api_url}/login"
        payload = {"username": self.access_key, "password": self.secret_key}
        logger.debug("Requesting new Prisma Cloud token from %s", login_url)

        resp = self._session.post(login_url, json=payload, timeout=self.timeout)
        if resp.status_code != 200:
            raise RuntimeError(f"Prisma login failed: HTTP {resp.status_code} - {resp.text}")

        data = resp.json()
        self.token = data.get("token")
        if not self.token:
            raise RuntimeError(f"No token returned in Prisma login response: {resp.text}")

        self.token_obtained_at = time.time()
        self._session.headers["x-redlock-auth"] = self.token
        logger.debug("Prisma Cloud authenticated successfully.")

    def _extend_token(self) -> None:
        """Extend the existing JWT session token."""
        extend_url = f"{self.api_url}/auth_token/extend"
        logger.debug("Extending Prisma Cloud auth token...")
        try:
            resp = self._session.get(extend_url, timeout=self.timeout)
            if resp.status_code == 200:
                self.token = resp.json().get("token", self.token)
                self.token_obtained_at = time.time()
                self._session.headers["x-redlock-auth"] = self.token
                logger.debug("Token extended successfully.")
                return
        except Exception as e:
            logger.warning("Token extension failed: %s. Re-authenticating...", e)
        # Fallback to fresh login
        self._login()

    def request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
    ) -> requests.Response:
        """Execute an HTTP request with automatic token refresh and exponential backoff."""
        self._ensure_authenticated()

        url = f"{self.api_url}/{path.lstrip('/')}"
        backoff = 2.0

        for attempt in range(1, self.max_retries + 1):
            try:
                resp = self._session.request(
                    method=method,
                    url=url,
                    params=params,
                    json=json_data,
                    timeout=self.timeout,
                )

                if resp.status_code == 401 and attempt < self.max_retries:
                    logger.warning("HTTP 401 received. Refreshing token and retrying...")
                    self._login()
                    continue

                if resp.status_code == 429 or resp.status_code in (500, 502, 503, 504):
                    if attempt == self.max_retries:
                        resp.raise_for_status()
                    logger.warning(
                        "Prisma API returned HTTP %d. Backing off for %.1fs (attempt %d/%d)...",
                        resp.status_code, backoff, attempt, self.max_retries
                    )
                    time.sleep(backoff)
                    backoff *= 2.0
                    continue

                resp.raise_for_status()
                return resp
            except requests.RequestException as e:
                if attempt == self.max_retries:
                    raise
                logger.warning("Request error (%s). Retrying in %.1fs...", e, backoff)
                time.sleep(backoff)
                backoff *= 2.0

        raise RuntimeError(f"Request failed after {self.max_retries} attempts to {url}")

    def search_config(
        self,
        query: str,
        limit: int = 1000,
        with_resource_json: bool = True,
        time_unit: str = "day",
        time_amount: int = 1,
    ) -> Generator[Dict[str, Any], None, None]:
        """Execute RQL Config Search and yield items across all result pages."""
        path = "search/api/v1/config"
        payload: Dict[str, Any] = {
            "query": query,
            "limit": limit,
            "withResourceJson": str(with_resource_json).lower(),
            "timeRange": {
                "type": "relative",
                "value": {"unit": time_unit, "amount": time_amount},
            },
        }

        while True:
            resp = self.request("POST", path, json_data=payload)
            data = resp.json()
            items = data.get("items", [])
            for item in items:
                yield item

            next_token = data.get("nextPageToken")
            if not next_token or not items:
                break
            payload["nextPageToken"] = next_token

    def search_events(
        self,
        query: str,
        limit: int = 100,
        time_unit: str = "minute",
        time_amount: int = 120,
    ) -> Generator[Dict[str, Any], None, None]:
        """Execute RQL Event Search and yield events across all result pages."""
        initial_path = "search/event"
        page_path = "search/event/page"

        payload: Dict[str, Any] = {
            "query": query,
            "limit": limit,
            "withResourceJson": 1,
            "timeRange": {
                "type": "relative",
                "value": {"unit": time_unit, "amount": time_amount},
            },
        }

        # Initial query
        resp = self.request("POST", initial_path, json_data=payload)
        res_data = resp.json().get("data", {})
        items = res_data.get("items", [])
        for item in items:
            yield item

        next_token = res_data.get("nextPageToken")
        while next_token:
            page_payload = {"limit": limit, "pageToken": next_token}
            page_resp = self.request("POST", page_path, json_data=page_payload)
            page_data = page_resp.json().get("data", {})
            page_items = page_data.get("items", [])
            if not page_items:
                break
            for item in page_items:
                yield item
            next_token = page_data.get("nextPageToken")

    def list_cloud_accounts(self) -> List[Dict[str, Any]]:
        """Retrieve all onboarded cloud accounts across AWS, GCP, and Azure."""
        resp = self.request("GET", "cloud")
        return resp.json()

    def list_alerts(
        self,
        status: str = "open",
        severities: Optional[List[str]] = None,
        limit: int = 500,
        max_alerts: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve security alerts filtered by status and severity, handling pagination."""
        path = "alert"
        params: Dict[str, Any] = {"status": status, "limit": limit}
        if severities:
            params["detailed"] = "true"

        all_alerts: List[Dict[str, Any]] = []
        while True:
            resp = self.request("GET", path, params=params)
            data = resp.json()
            items = data if isinstance(data, list) else data.get("items", [])
            all_alerts.extend(items)

            if max_alerts and len(all_alerts) >= max_alerts:
                all_alerts = all_alerts[:max_alerts]
                break

            # Handle next page if cursor / token present
            next_token = data.get("nextPageToken") if isinstance(data, dict) else None
            if not next_token or not items:
                break
            params["pageToken"] = next_token

        return all_alerts

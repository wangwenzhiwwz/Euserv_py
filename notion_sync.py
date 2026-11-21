#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Retryable Notion reminder sync for a backend-verified EUserv FREE renewal."""

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

PENDING_FILE = "notion_sync_pending.json"
PAGE_ID = "08d979471e694eee823e7834a62fe920"
NOTION_VERSION = "2022-06-28"


def main():
    if not os.path.exists(PENDING_FILE):
        print("No pending Notion reminder update.")
        return 0

    token = os.getenv("NOTION_API_TOKEN", "").strip()
    if not token:
        print("ERROR: GitHub Actions secret NOTION_API_TOKEN is not configured.")
        return 2

    with open(PENDING_FILE, "r", encoding="utf-8") as f:
        item = json.load(f)

    if (
        item.get("contract_id") != "442244"
        or item.get("verified") is not True
    ):
        print("ERROR: Pending item is not an explicitly verified FREE contract 442244.")
        return 3

    reminder_date = str(item.get("reminder_date", "")).strip()
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", reminder_date):
        print("ERROR: Invalid reminder date; refusing to update Notion.")
        return 4

    payload = {
        "properties": {
            "提醒": {
                "date": {
                    "start": reminder_date
                }
            }
        }
    }
    request = urllib.request.Request(
        f"https://api.notion.com/v1/pages/{PAGE_ID}",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Notion-Version": NOTION_VERSION,
            "Content-Type": "application/json",
        },
        method="PATCH",
    )

    last_error = None
    for attempt in range(1, 4):
        try:
            with urllib.request.urlopen(request, timeout=25) as response:
                result = json.loads(response.read().decode("utf-8"))
            saved_date = (
                result.get("properties", {})
                .get("提醒", {})
                .get("date", {})
                .get("start")
            )
            if saved_date != reminder_date:
                raise RuntimeError(
                    f"Notion response date mismatch: expected={reminder_date}, got={saved_date}"
                )
            os.remove(PENDING_FILE)
            print(f"SUCCESS: Notion EUserver reminder updated to {reminder_date}.")
            return 0
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, RuntimeError, ValueError) as exc:
            last_error = exc
            print(f"Notion sync attempt {attempt}/3 failed: {exc}")
            if attempt < 3:
                time.sleep(attempt * 5)

    print(f"ERROR: Notion sync remains pending for next scheduled retry: {last_error}")
    return 1


if __name__ == "__main__":
    sys.exit(main())

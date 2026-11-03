#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Personal Zeekr check-in, optional tasks, and reward verification."""
import argparse
import base64
import gzip
import hashlib
import json
import logging
import os
import re
import secrets
import ssl
import string
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

LOGGER = logging.getLogger("zeekr_checkin")
GATEWAY_HOST = "api-gw-toc.zeekrlife.com"
TOKEN_PREFIX = "Bearer "
SECONDS_TO_MILLISECONDS = 1000
NONCE_LENGTH = 15
EXIT_SUCCESS = 0
EXIT_PARTIAL = 2
EXIT_ERROR = 1


class ApiError(Exception):
    """An HTTP boundary failure with a public, credential-free error code."""


class NoRedirect(HTTPRedirectHandler):
    """Never forward a credential through a redirect."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ApiError("HTTP_REDIRECT_REJECTED")


def make_signature(secret, nonce, timestamp):
    """Match the public H5 signature contract; generate a fresh nonce per call."""
    material = "".join(sorted([secret, nonce, str(timestamp)]))
    return hashlib.sha1(material.encode("utf-8")).hexdigest()


def encode_step_secret(step_counts, layers=6):
    """Match the H5 client: append salt, then apply standard Base64 six times."""
    encoded = f"{step_counts}_salt".encode("utf-8")
    for _ in range(layers):
        encoded = base64.b64encode(encoded)
    return encoded.decode("ascii")


def parse_identity(authorization):
    """Read business JWT metadata; the server still authenticates the signature."""
    try:
        authorization = authorization.strip()
        if not authorization.startswith(TOKEN_PREFIX):
            raise ValueError()
        segments = authorization[len(TOKEN_PREFIX):].split(".")
        if len(segments) != 3:
            raise ValueError()
        payload = json.loads(base64.urlsafe_b64decode(segments[1] + "=" * (-len(segments[1]) % 4)))
        subject = payload["sub"]
        subject = json.loads(subject) if isinstance(subject, str) else subject
        account_id = subject["accountInfoDTO"]["accountId"]
        expiry = payload["exp"]
        if payload.get("aud") != "app" or isinstance(account_id, bool) or not str(account_id).isdigit():
            raise ValueError()
        if isinstance(expiry, bool) or not isinstance(expiry, (int, float)) or expiry <= 0:
            raise ValueError()
        return {"account_id": int(account_id), "expires_at": int(expiry)}
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeDecodeError):
        raise ApiError("INVALID_TOKEN") from None


def safe_message(value, authorization):
    """Keep useful server messages without disclosing JWTs or phone numbers."""
    text = str(value or "").replace(authorization, "[REDACTED]")
    text = re.sub(r"(?:Bearer\s+)?eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[REDACTED]", text)
    text = re.sub(r"\b1[3-9]\d{9}\b", "[PHONE]", text)
    return text[:240]


class Gateway:
    """TLS-verified, allowlisted, one-shot gateway requests using Python stdlib."""
    def __init__(self, credentials, protocol):
        self.credentials = credentials
        self.protocol = protocol
        # Keep gateway signing material out of versioned protocol configuration.
        self.signing_secret = (credentials.get("signing_secret")
                               or os.environ.get("ZEEKR_SIGNING_SECRET", "")).strip()
        if not self.signing_secret:
            raise ApiError("SIGNING_SECRET_MISSING")
        parsed = urlparse(protocol["base_url"])
        if parsed.scheme != "https" or parsed.hostname != GATEWAY_HOST or parsed.port not in (None, 443):
            raise ApiError("GATEWAY_NOT_ALLOWED")
        self.opener = build_opener(NoRedirect(), HTTPSHandler(context=ssl.create_default_context()))

    def _request(self, method, endpoint, body=None):
        endpoint_path = urlparse(endpoint).path
        if endpoint_path not in self.protocol["endpoints"].values():
            raise ApiError("ENDPOINT_NOT_ALLOWED")
        timestamp = str(int(time.time() * SECONDS_TO_MILLISECONDS))
        nonce = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(NONCE_LENGTH))
        headers = dict(self.protocol["headers"])
        headers.update({
            "Authorization": self.credentials["authorization"].strip(),
            "device_id": str(self.credentials.get("device_id", "")),
            "User-Agent": self.credentials.get("user_agent", self.protocol["user_agent"]),
            "x_ca_nonce": nonce,
            "x_ca_timestamp": timestamp,
            "riskTimeStamp": timestamp,
            "x_ca_sign": make_signature(self.signing_secret, nonce, timestamp),
        })
        encoded = None if method == "GET" else json.dumps(body or {}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        request = Request(self.protocol["base_url"] + endpoint, data=encoded, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=self.protocol["timeout_seconds"]) as response:
                raw = response.read(self.protocol["max_response_bytes"] + 1)
                if len(raw) > self.protocol["max_response_bytes"]:
                    raise ApiError("RESPONSE_TOO_LARGE")
                if response.headers.get("Content-Encoding", "").lower() == "gzip":
                    raw = gzip.decompress(raw)
                result = json.loads(raw.decode("utf-8-sig"))
                if not isinstance(result, dict):
                    raise ApiError("RESPONSE_SCHEMA_ERROR")
                return result
        except HTTPError as error:
            raise ApiError(f"HTTP_{error.code}") from None
        except (URLError, TimeoutError, OSError):
            raise ApiError("NETWORK_ERROR") from None
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ApiError("RESPONSE_NOT_JSON") from None

    def post(self, endpoint, body):
        return self._request("POST", endpoint, body)

    def get(self, endpoint, query=None):
        query_string = urlencode(query or {})
        full_endpoint = endpoint + ("?" + query_string if query_string else "")
        return self._request("GET", full_endpoint)


def daily_status(payload, protocol, authorization):
    """Require the daily task completion flag, not just the envelope success code."""
    items = (payload.get("data") or {}).get("signInZgreenInfo")
    if not isinstance(items, list):
        raise ApiError("SIGN_RESPONSE_SCHEMA_ERROR")
    summary = []
    confirmed = False
    for item in items:
        if not isinstance(item, dict):
            continue
        status = item.get("taskStatus")
        name = item.get("taskName", "")
        summary.append({"task_name": safe_message(name, authorization), "task_status": status})
        if name == protocol["daily_task_label"]:
            confirmed = status in protocol["completed_statuses"]
    return confirmed, summary


def get_rewards(gateway, protocol, account_id):
    """A failed or malformed query must never become an empty reward list."""
    response = gateway.post(protocol["endpoints"]["uncollected"], {"accountId": account_id})
    if response.get("code") != protocol["success_code"]:
        raise ApiError("REWARD_QUERY_FAILED")
    data = response.get("data")
    if not isinstance(data, dict):
        raise ApiError("REWARD_RESPONSE_SCHEMA_ERROR")
    if "accountId" in data and str(data["accountId"]) != str(account_id):
        raise ApiError("ACCOUNT_MISMATCH")
    items = data.get("uncollectedVal")
    # The live gateway omits this optional array when no rewards are pending.
    # Accept only the observed account-profile shape; arbitrary missing data fails.
    if "uncollectedVal" not in data:
        required = protocol["empty_reward_profile_fields"]
        if all(field in data for field in required) and all(
            isinstance(data[field], (int, float)) and not isinstance(data[field], bool)
            and data[field] >= 0 for field in protocol["balance_fields"]
        ):
            items = []
    if not isinstance(items, list):
        raise ApiError("REWARD_RESPONSE_SCHEMA_ERROR")
    if any(not isinstance(item, dict) or item.get("id") is None for item in items):
        raise ApiError("REWARD_RESPONSE_SCHEMA_ERROR")
    return items


def reward_summary(items):
    """Only public type/count/value aggregates go into reports, never record IDs."""
    summary = {}
    for item in items:
        kind = str(item.get("valDefineCode", "UNKNOWN"))
        summary[kind] = summary.get(kind, 0) + 1
    return summary


def _task_by_name(tasks, task_name):
    return next((task for task in tasks if isinstance(task, dict) and task.get("name") == task_name), None)


def _task_done(task):
    if not task:
        return False
    progress = task.get("taskTakeDTO") or {}
    return (progress.get("currentComplete") or 0) >= (progress.get("maxCompleteLimit") or 1)


def select_step_count(config):
    """Use an explicit count or a cryptographically strong inclusive integer range."""
    if config.get("steps") is not None:
        return config["steps"]
    if config.get("steps_min") is None and config.get("steps_max") is None:
        return None
    minimum = config.get("steps_min")
    maximum = config.get("steps_max")
    if (not isinstance(minimum, int) or isinstance(minimum, bool)
            or not isinstance(maximum, int) or isinstance(maximum, bool)
            or minimum <= 0 or maximum < minimum):
        raise ValueError("INVALID_STEPS_RANGE")
    return minimum + secrets.randbelow(maximum - minimum + 1)


def run_automations(gateway, protocol, account_id, config):
    """Run the three explicitly enabled tasks and return public statuses only."""
    result = {"steps": "disabled", "read": "disabled", "like": "disabled"}
    errors = []
    if not config or not config.get("enabled"):
        return result, errors
    try:
        steps = select_step_count(config)
    except ValueError:
        steps = "invalid"
    if steps is not None:
        if not isinstance(steps, int) or isinstance(steps, bool) or steps <= 0:
            result["steps"] = "failed"
            errors.append("INVALID_STEPS")
        else:
            try:
                response = gateway.post(protocol["endpoints"]["walk_data"], {
                    "stepCounts": steps,
                    "stepCountsSecret": encode_step_secret(steps),
                    "sourceType": protocol["automation"]["walk_source_type"],
                    "accountId": account_id,
                })
            except ApiError:
                response = None
            if response and response.get("code") == protocol["success_code"]:
                result["steps"] = "success"
                result["steps_value"] = steps
            else:
                result["steps"] = "failed"
                errors.append("STEPS_REQUEST_FAILED")
    needs_tasks = bool(config.get("read") or config.get("like"))
    tasks = []
    if needs_tasks:
        try:
            task_response = gateway.post(protocol["endpoints"]["task_msg"], protocol["automation"]["task_request"])
        except ApiError:
            task_response = None
        tasks = (((task_response.get("data") or {}).get("taskReachMsgList")
                  if task_response.get("code") == protocol["success_code"] else None)
                 if task_response else None)
        if not isinstance(tasks, list):
            if config.get("read"):
                result["read"] = "failed"
                errors.append("TASK_LIST_FAILED")
            if config.get("like"):
                result["like"] = "failed"
                errors.append("TASK_LIST_FAILED")
            return result, errors
    if config.get("read"):
        article_task = _task_by_name(tasks, protocol["automation"]["article_task_name"])
        if not article_task:
            result["read"] = "skipped_not_available"
        else:
            path = ((article_task.get("doc") or {}).get("path") or "")
            marker = protocol["automation"]["article_id_marker"]
            article_id = (parse_qs(urlparse(path).query).get(marker) or [""])[0]
            if not article_id:
                result["read"] = "failed"
                errors.append("ARTICLE_ID_MISSING")
            else:
                try:
                    response = gateway.get(protocol["endpoints"]["article_detail"], {"id": article_id})
                except ApiError:
                    response = None
                if response and response.get("code") == protocol["success_code"]:
                    result["read"] = "success"
                else:
                    result["read"] = "failed"
                    errors.append("ARTICLE_REQUEST_FAILED")
    if config.get("like"):
        like_task = _task_by_name(tasks, protocol["automation"]["like_task_name"])
        if not like_task:
            result["like"] = "skipped_not_available"
        elif _task_done(like_task):
            result["like"] = "skipped_weekly_complete"
        else:
            target = None
            list_failed = False
            for page in range(1, config["like_max_pages"] + 1):
                try:
                    response = gateway.get(protocol["endpoints"]["square_list"], {
                        "pageNo": page, "pageSize": config["like_page_size"], "sort": 0,
                    })
                except ApiError:
                    response = None
                if not response or response.get("code") != protocol["success_code"]:
                    list_failed = True
                    break
                data = response.get("data") or {}
                if not isinstance(data, dict) or not isinstance(data.get("list"), list):
                    list_failed = True
                    break
                items = data["list"]
                target = next((item for item in items if item.get("isFabulous") == 0 and item.get("id") and item.get("accountId")), None)
                if target or not items:
                    break
            if list_failed:
                result["like"] = "failed"
                errors.append("LIKE_LIST_REQUEST_FAILED")
            elif not target:
                result["like"] = "skipped_no_target"
            else:
                try:
                    response = gateway.post(protocol["endpoints"]["fabulous"], {
                        "moduleId": str(target["id"]), "accountId": account_id, "fabulousState": 1,
                        "moduleType": 1, "toAccountId": str(target["accountId"]), "invitationType": 2,
                    })
                except ApiError:
                    response = None
                if response and response.get("code") == protocol["success_code"]:
                    result["like"] = "success"
                else:
                    result["like"] = "failed"
                    errors.append("LIKE_REQUEST_FAILED")
    return result, errors


def fetch_task_list(gateway, protocol):
    """Fetch the task progress list without exposing account fields."""
    try:
        response = gateway.post(protocol["endpoints"]["task_msg"], protocol["automation"]["task_request"])
    except ApiError:
        return None
    tasks = ((response.get("data") or {}).get("taskReachMsgList")
             if response.get("code") == protocol["success_code"] else None)
    return tasks if isinstance(tasks, list) else None


def ensure_carbon_goal(gateway, protocol, account_id, config):
    """Claim carbon energy balls until the daily 2000g task is confirmed."""
    if not config.get("carbon_goal_enabled"):
        return {"status": "disabled", "value": None}, []
    goal = config.get("carbon_goal_grams")
    if not isinstance(goal, int) or isinstance(goal, bool) or goal <= 0:
        return {"status": "failed", "value": None}, ["INVALID_CARBON_GOAL"]
    wait_seconds = config.get("carbon_poll_seconds", 20)
    max_wait_seconds = config.get("carbon_max_wait_seconds", 60)
    started = time.monotonic()
    errors = []
    attempted_energy_ids = set()
    while True:
        tasks = fetch_task_list(gateway, protocol)
        task = _task_by_name(tasks or [], config.get("carbon_task_name", "减碳2000g"))
        progress = (task or {}).get("taskTakeDTO") or {}
        current = progress.get("currentStep") or 0
        if isinstance(current, (int, float)) and current >= goal:
            return {"status": "success", "value": int(current),
                    "waited_seconds": round(time.monotonic() - started)}, errors
        if tasks is None or task is None:
            return {"status": "failed", "value": int(current) if isinstance(current, (int, float)) else 0}, ["CARBON_TASK_QUERY_FAILED"]
        try:
            pending = get_rewards(gateway, protocol, account_id)
        except ApiError:
            pending = []
            errors.append("CARBON_REWARD_QUERY_FAILED")
        carbon_value_type = config.get("carbon_value_type", protocol["automation"].get("carbon_value_type", "CARBON_VALUE"))
        energy_items = [item for item in pending
                        if item.get("valDefineCode") == carbon_value_type
                        and str(item.get("id")) not in attempted_energy_ids]
        for item in energy_items:
            attempted_energy_ids.add(str(item.get("id")))
            try:
                result = gateway.post(protocol["endpoints"]["claim_energy"], {"energyIds": [item["id"]]})
            except ApiError:
                result = None
            if not result or result.get("code") != protocol["success_code"]:
                errors.append("CARBON_ENERGY_CLAIM_FAILED")
        if energy_items:
            # Re-query task progress immediately after a successful/attempted claim.
            # The server may mark the 2000g task in the same response window.
            elapsed = time.monotonic() - started
            if wait_seconds > 0 and elapsed < max_wait_seconds:
                time.sleep(min(wait_seconds, max_wait_seconds - elapsed))
            continue
        if time.monotonic() - started >= max_wait_seconds:
            return {"status": "pending", "value": int(current) if isinstance(current, (int, float)) else 0,
                    "waited_seconds": round(time.monotonic() - started)}, errors + ["CARBON_GOAL_NOT_REACHED"]
        if wait_seconds > 0:
            time.sleep(wait_seconds)


def run_once(credentials, protocol, gateway=None, now=None, claim=False, automation=None):
    """Sign, verify, optionally collect existing rewards, then verify again."""
    now = time.time() if now is None else now
    local_zone = timezone(timedelta(hours=protocol["timezone_offset_hours"]))
    report = {
        "ok": False, "day": datetime.fromtimestamp(now, local_zone).strftime("%Y-%m-%d"),
        "sign_confirmed": False, "remaining_rewards": None,
        "verified_removed_rewards": 0, "error": None,
    }
    authorization = str(credentials.get("authorization", ""))
    try:
        identity = parse_identity(authorization)
        report["expires_at"] = datetime.fromtimestamp(identity["expires_at"], local_zone).isoformat()
        if identity["expires_at"] <= now + protocol["expiry_margin_seconds"]:
            raise ApiError("TOKEN_EXPIRED")
        gateway = gateway or Gateway(credentials, protocol)
        response = gateway.post(protocol["endpoints"]["sign"], {})
        report["sign_response_code"] = response.get("code")
        if response.get("code") != protocol["success_code"]:
            report["message"] = safe_message(response.get("msg"), authorization)
            raise ApiError("SIGN_REQUEST_FAILED")
        _, report["daily_tasks"] = daily_status(response, protocol, authorization)
        verification = gateway.post(protocol["endpoints"]["sign"], {})
        if verification.get("code") != protocol["success_code"]:
            raise ApiError("SIGN_VERIFY_FAILED")
        report["sign_confirmed"], report["daily_tasks"] = daily_status(verification, protocol, authorization)
        if not report["sign_confirmed"]:
            raise ApiError("SIGN_NOT_CONFIRMED")
        automation_failed = False
        if automation and automation.get("enabled"):
            report["automation"], task_errors = run_automations(gateway, protocol, identity["account_id"], automation)
            carbon_result, carbon_errors = ensure_carbon_goal(gateway, protocol, identity["account_id"], automation)
            report["automation"]["carbon"] = carbon_result["status"]
            if carbon_result.get("value") is not None:
                report["automation"]["carbon_value"] = carbon_result["value"]
            if carbon_result.get("waited_seconds") is not None:
                report["automation"]["carbon_waited_seconds"] = carbon_result["waited_seconds"]
            task_errors = task_errors + carbon_errors
            if task_errors:
                report["automation_errors"] = task_errors
                automation_failed = True
        before = get_rewards(gateway, protocol, identity["account_id"])
        report["remaining_rewards"] = len(before)
        report["reward_types"] = reward_summary(before)
        if before and claim:
            failures = []
            for item in before:
                kind = item.get("valDefineCode")
                if item.get("sceneCode") == protocol["seven_day_scene"]:
                    endpoint = protocol["endpoints"]["claim_seven_day"]
                    body = {"record": protocol["seven_day_record"], "fixedZgreenAssetId": item["id"],
                            "optional": {"mappingMsg": True}}
                elif kind == protocol["fragment_reward_type"]:
                    if not all(isinstance(item.get(field), str) and item[field].strip()
                               for field in protocol["fragment_source_fields"]):
                        failures.append({"type": str(kind), "error": "FRAGMENT_SOURCE_FIELDS_MISSING"})
                        continue
                    endpoint = protocol["endpoints"]["claim_fragment"]
                    body = {"applyCmdList": [{
                        "record": item["eventCode"],
                        "payContent": {"bubbleAssetsId": item["id"]},
                        "applyExt": {"origin": item["sourceId"]},
                    }]}
                elif kind in protocol["claim_type_endpoints"]:
                    endpoint = protocol["endpoints"][protocol["claim_type_endpoints"][kind]]
                    body = {"energyIds": [item["id"]]}
                else:
                    failures.append({"type": str(kind), "error": "UNSUPPORTED_REWARD_REQUIRES_APP"})
                    continue
                try:
                    result = gateway.post(endpoint, body)
                except ApiError as error:
                    failures.append({"type": str(kind), "error": str(error)})
                    continue
                if result.get("code") != protocol["success_code"]:
                    failures.append({"type": str(kind), "code": result.get("code"),
                                     "message": safe_message(result.get("msg"), authorization)})
                elif endpoint == protocol["endpoints"]["claim_fragment"]:
                    entries = result.get("data")
                    if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict):
                        failures.append({"type": str(kind), "error": "FRAGMENT_RESPONSE_SCHEMA_ERROR"})
                    elif entries[0].get("success") is not True:
                        reason = next((entries[0][field] for field in protocol["failure_message_fields"]
                                       if entries[0].get(field)), "Fragment claim was not accepted")
                        failures.append({"type": str(kind), "message": safe_message(reason, authorization)})
            # A request may have succeeded server-side even if its response timed
            # out. Re-query after every attempt; never retry the claim blindly.
            report["remaining_rewards"] = None
            after = get_rewards(gateway, protocol, identity["account_id"])
            removed = {str(item["id"]) for item in before} - {str(item["id"]) for item in after}
            report["verified_removed_rewards"] = len(removed)
            report["remaining_rewards"] = len(after)
            report["reward_types"] = reward_summary(after)
            if failures:
                report["claim_attempt_errors"] = failures
        if report["remaining_rewards"]:
            raise ApiError("REWARDS_REMAIN")
        if automation_failed:
            raise ApiError("AUTOMATION_FAILED")
        report["ok"] = True
    except ApiError as error:
        report["error"] = str(error)
    except (KeyError, TypeError, ValueError):
        report["error"] = "RESPONSE_SCHEMA_ERROR"
    return report


def write_private_report(path, report):
    """Atomic local output; reports contain no credential or account profile."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + ".tmp")
    with open(temporary, "w", encoding="utf-8") as output:
        os.chmod(temporary, 0o600)
        json.dump(report, output, ensure_ascii=False, indent=2)
        output.write("\n")
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--credentials", required=True, type=Path, help="Private JSON containing authorization and device_id")
    parser.add_argument("--protocol", type=Path, default=Path(__file__).with_name("protocol.json"))
    parser.add_argument("--claim", action="store_true", help="Collect existing supported rewards and verify their removal")
    parser.add_argument("--save-report", type=Path)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    try:
        credentials = json.loads(args.credentials.read_text(encoding="utf-8-sig"))
        protocol = json.loads(args.protocol.read_text(encoding="utf-8-sig"))
        report = run_once(credentials, protocol, claim=args.claim, automation=protocol.get("automation"))
        if args.save_report:
            write_private_report(args.save_report, report)
        LOGGER.info(json.dumps(report, ensure_ascii=False, indent=2))
        return EXIT_SUCCESS if report["ok"] else (EXIT_PARTIAL if report["sign_confirmed"] else EXIT_ERROR)
    except (OSError, ValueError, TypeError):
        LOGGER.error("Configuration or report file could not be read/written; no credentials printed.")
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())

"""Offline tests: signature compatibility, verification, privacy and expiry."""
import base64
import json
import unittest
from pathlib import Path

import zeekr_checkin as app


def credentials(exp=4102444800):
    subject = json.dumps({"accountInfoDTO": {"accountId": 9000000000000000001}})
    payload = {"aud": "app", "iss": "prod", "sub": subject, "exp": exp}
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return {"authorization": f"Bearer e30.{encoded}.test-signature", "device_id": "test-device"}


def center(done):
    return {"code": "000000", "data": {"signInZgreenInfo": [
        {"taskName": "每日签到", "taskStatus": done}
    ]}}


def rewards(items):
    return {"code": "000000", "data": {"uncollectedVal": items}}


class Gateway:
    """Only the external HTTP boundary is replaced; real workflow is exercised."""
    def __init__(self, replies, get_replies=None):
        self.replies = list(replies)
        self.get_replies = list(get_replies or [])
        self.requests = []

    def post(self, endpoint, body):
        self.requests.append((endpoint, body))
        if not self.replies:
            raise AssertionError("Unexpected additional gateway request")
        response = self.replies.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    def get(self, endpoint, query):
        self.requests.append(("GET " + endpoint, query))
        if not self.get_replies:
            raise AssertionError("Unexpected additional gateway GET request")
        response = self.get_replies.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class CheckinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.protocol = json.loads(Path(__file__).with_name("protocol.json").read_text(encoding="utf-8"))

    def test_signature_matches_independent_fixture(self):
        signature = app.make_signature("unit-test-only-secret", "unit-test-nonce", "1700000000000")
        self.assertEqual(signature, "2c188f043103af7ff2dcb930478e5059819e6655")

    def test_gateway_requires_external_signing_material(self):
        from unittest.mock import patch
        with patch.dict(app.os.environ, {"ZEEKR_SIGNING_SECRET": ""}):
            with self.assertRaisesRegex(app.ApiError, "SIGNING_SECRET_MISSING"):
                app.Gateway(credentials(), self.protocol)

    def test_gateway_reads_signing_material_from_environment(self):
        from unittest.mock import patch
        with patch.dict(app.os.environ, {"ZEEKR_SIGNING_SECRET": "unit-test-env-secret"}):
            gateway = app.Gateway(credentials(), self.protocol)
        self.assertEqual(gateway.signing_secret, "unit-test-env-secret")

    def test_private_signing_material_takes_precedence_over_environment(self):
        from unittest.mock import patch
        config = {**credentials(), "signing_secret": "unit-test-file-secret"}
        with patch.dict(app.os.environ, {"ZEEKR_SIGNING_SECRET": "unit-test-env-secret"}):
            gateway = app.Gateway(config, self.protocol)
        self.assertEqual(gateway.signing_secret, "unit-test-file-secret")

    def test_account_id_keeps_all_19_digits(self):
        identity = app.parse_identity(credentials()["authorization"])
        self.assertEqual(identity["account_id"], 9000000000000000001)

    def test_expired_token_stops_before_any_http_request(self):
        gateway = Gateway([])
        report = app.run_once(credentials(exp=1), self.protocol, gateway=gateway, now=1791772618)
        self.assertEqual(report["error"], "TOKEN_EXPIRED")
        self.assertFalse(report["ok"])
        self.assertEqual(gateway.requests, [])

    def test_api_success_without_completed_daily_task_is_failure(self):
        gateway = Gateway([center(False), center(False)])
        report = app.run_once(credentials(), self.protocol, gateway=gateway)
        self.assertFalse(report["ok"])
        self.assertFalse(report["sign_confirmed"])
        self.assertEqual(report["error"], "SIGN_NOT_CONFIRMED")

    def test_completed_daily_task_and_empty_rewards_is_success(self):
        gateway = Gateway([center(True), center(True), rewards([])])
        report = app.run_once(credentials(), self.protocol, gateway=gateway)
        self.assertTrue(report["ok"])
        self.assertTrue(report["sign_confirmed"])
        self.assertEqual(report["remaining_rewards"], 0)

    def test_automation_runs_steps_read_and_like_and_reports_each_result(self):
        task_list = {"code": "000000", "data": {"taskReachMsgList": [
            {"name": "阅读文章", "doc": {"path": "/detail?acticleId=article-123"}},
            {"name": "每周点赞帖子", "taskTakeDTO": {"currentComplete": 0, "maxCompleteLimit": 1}},
        ]}}
        square_list = {"code": "000000", "data": {"list": [
            {"id": 88, "accountId": 99, "isFabulous": 0, "title": "测试帖子"}
        ]}}
        gateway = Gateway(
            [center(True), center(True), {"code": "000000", "data": {}}, task_list,
             {"code": "000000", "data": {}}, rewards([])],
            [{"code": "000000", "data": {"title": "测试文章"}}, square_list],
        )
        automation = {"enabled": True, "steps": 10000, "read": True, "like": True,
                      "like_max_pages": 3, "like_page_size": 20}
        report = app.run_once(credentials(), self.protocol, gateway=gateway, automation=automation)
        self.assertTrue(report["ok"])
        self.assertEqual(report["automation"]["steps"], "success")
        self.assertEqual(report["automation"]["read"], "success")
        self.assertEqual(report["automation"]["like"], "success")
        self.assertEqual(gateway.requests[2][1]["stepCounts"], 10000)
        self.assertEqual(gateway.requests[2][1]["stepCountsSecret"], app.encode_step_secret(10000))
        self.assertEqual(gateway.requests[4], ("GET /zeekrlife-bbs-theme/v1/invitation/pub/detail", {"id": "article-123"}))
        self.assertEqual(gateway.requests[6][1]["moduleId"], "88")

    def test_automation_chooses_step_count_inside_configured_range(self):
        gateway = Gateway([center(True), center(True), {"code": "000000", "data": {}}, rewards([])])
        automation = {"enabled": True, "steps": None, "steps_min": 10000, "steps_max": 20000,
                      "read": False, "like": False, "like_max_pages": 3, "like_page_size": 20}
        report = app.run_once(credentials(), self.protocol, gateway=gateway, automation=automation)
        self.assertTrue(report["ok"])
        selected_steps = gateway.requests[2][1]["stepCounts"]
        self.assertGreaterEqual(selected_steps, 10000)
        self.assertLessEqual(selected_steps, 20000)
        self.assertEqual(report["automation"]["steps_value"], selected_steps)

    def test_automation_accepts_a_single_value_range_for_deterministic_runs(self):
        gateway = Gateway([center(True), center(True), {"code": "000000", "data": {}}, rewards([])])
        automation = {"enabled": True, "steps": None, "steps_min": 12345, "steps_max": 12345,
                      "read": False, "like": False, "like_max_pages": 3, "like_page_size": 20}
        report = app.run_once(credentials(), self.protocol, gateway=gateway, automation=automation)
        self.assertTrue(report["ok"])
        self.assertEqual(gateway.requests[2][1]["stepCounts"], 12345)
        self.assertEqual(report["automation"]["steps_value"], 12345)

    def test_carbon_goal_is_success_when_task_already_reaches_2000g(self):
        task_list = {"code": "000000", "data": {"taskReachMsgList": [
            {"name": "减碳2000g", "taskTakeDTO": {"currentStep": 2000, "currentComplete": 1, "maxCompleteLimit": 1}},
        ]}}
        gateway = Gateway([center(True), center(True), task_list, rewards([])])
        automation = {"enabled": True, "steps": None, "read": False, "like": False,
                      "carbon_goal_enabled": True, "carbon_goal_grams": 2000,
                      "carbon_poll_seconds": 0, "carbon_max_wait_seconds": 0,
                      "like_max_pages": 3, "like_page_size": 20}
        report = app.run_once(credentials(), self.protocol, gateway=gateway, automation=automation)
        self.assertTrue(report["ok"])
        self.assertEqual(report["automation"]["carbon"], "success")
        self.assertEqual(report["automation"]["carbon_value"], 2000)

    def test_carbon_goal_claims_energy_and_rechecks_task_progress(self):
        task_pending = {"code": "000000", "data": {"taskReachMsgList": [
            {"name": "减碳2000g", "taskTakeDTO": {"currentStep": 0, "currentComplete": 0, "maxCompleteLimit": 1}},
        ]}}
        task_done = {"code": "000000", "data": {"taskReachMsgList": [
            {"name": "减碳2000g", "taskTakeDTO": {"currentStep": 2000, "currentComplete": 1, "maxCompleteLimit": 1}},
        ]}}
        energy = {"id": "energy-1", "valDefineCode": "CARBON_VALUE", "val": 2000}
        gateway = Gateway([center(True), center(True), task_pending, rewards([energy]),
                           {"code": "000000", "data": {}}, task_done, rewards([])])
        automation = {"enabled": True, "steps": None, "read": False, "like": False,
                      "carbon_goal_enabled": True, "carbon_goal_grams": 2000,
                      "carbon_poll_seconds": 0, "carbon_max_wait_seconds": 0,
                      "like_max_pages": 3, "like_page_size": 20}
        report = app.run_once(credentials(), self.protocol, gateway=gateway, automation=automation, claim=True)
        self.assertTrue(report["ok"])
        self.assertEqual(report["automation"]["carbon"], "success")
        self.assertEqual(report["automation"]["carbon_value"], 2000)
        self.assertEqual(gateway.requests[4][1], {"energyIds": ["energy-1"]})

    def test_carbon_goal_stops_when_claimed_energy_remains_pending(self):
        task_pending = {"code": "000000", "data": {"taskReachMsgList": [
            {"name": "减碳2000g", "taskTakeDTO": {"currentStep": 0, "currentComplete": 0, "maxCompleteLimit": 1}},
        ]}}
        energy = {"id": "energy-1", "valDefineCode": "CARBON_VALUE", "val": 2000}
        gateway = Gateway([center(True), center(True), task_pending, rewards([energy]),
                           {"code": "FAIL", "msg": "pending"}, task_pending, rewards([energy]),
                           rewards([])])
        automation = {"enabled": True, "steps": None, "read": False, "like": False,
                      "carbon_goal_enabled": True, "carbon_goal_grams": 2000,
                      "carbon_poll_seconds": 0, "carbon_max_wait_seconds": 0,
                      "like_max_pages": 3, "like_page_size": 20}
        report = app.run_once(credentials(), self.protocol, gateway=gateway, automation=automation, claim=True)
        self.assertFalse(report["ok"])
        self.assertEqual(report["automation"]["carbon"], "pending")
        self.assertEqual(report["error"], "AUTOMATION_FAILED")

    def test_automation_skips_like_when_weekly_task_is_already_done(self):
        task_list = {"code": "000000", "data": {"taskReachMsgList": [
            {"name": "每周点赞帖子", "taskTakeDTO": {"currentComplete": 1, "maxCompleteLimit": 1}},
        ]}}
        gateway = Gateway([center(True), center(True), task_list, rewards([])], [])
        automation = {"enabled": True, "steps": None, "read": False, "like": True,
                      "like_max_pages": 3, "like_page_size": 20}
        report = app.run_once(credentials(), self.protocol, gateway=gateway, automation=automation)
        self.assertTrue(report["ok"])
        self.assertEqual(report["automation"]["like"], "skipped_weekly_complete")
        self.assertEqual(len([request for request in gateway.requests if str(request[0]).startswith("GET ")]), 0)

    def test_automation_without_required_task_fields_is_reported_as_failure(self):
        task_list = {"code": "000000", "data": {"taskReachMsgList": [
            {"name": "阅读文章", "doc": {"path": "/detail"}},
        ]}}
        gateway = Gateway([center(True), center(True), task_list, rewards([])], [])
        automation = {"enabled": True, "steps": None, "read": True, "like": False,
                      "like_max_pages": 3, "like_page_size": 20}
        report = app.run_once(credentials(), self.protocol, gateway=gateway, automation=automation)
        self.assertFalse(report["ok"])
        self.assertEqual(report["automation"]["read"], "failed")
        self.assertEqual(report["error"], "AUTOMATION_FAILED")

    def test_automation_failure_does_not_skip_reward_collection(self):
        task_list = {"code": "000000", "data": {"taskReachMsgList": [
            {"name": "阅读文章", "doc": {"path": "/detail"}},
        ]}}
        reward = {"id": "reward-1", "valDefineCode": "ZEEKR_VALUE", "val": 10}
        gateway = Gateway([center(True), center(True), task_list, rewards([reward]),
                           {"code": "000000", "data": {}}, rewards([])], [])
        automation = {"enabled": True, "steps": None, "read": True, "like": False,
                      "like_max_pages": 3, "like_page_size": 20}
        report = app.run_once(credentials(), self.protocol, gateway=gateway, automation=automation, claim=True)
        self.assertFalse(report["ok"])
        self.assertEqual(report["error"], "AUTOMATION_FAILED")
        self.assertEqual(report["verified_removed_rewards"], 1)
        self.assertEqual(report["remaining_rewards"], 0)

    def test_like_list_request_failure_is_not_reported_as_no_target(self):
        task_list = {"code": "000000", "data": {"taskReachMsgList": [
            {"name": "每周点赞帖子", "taskTakeDTO": {"currentComplete": 0, "maxCompleteLimit": 1}},
        ]}}
        gateway = Gateway([center(True), center(True), task_list, rewards([])],
                          [{"code": "NETWORK", "msg": "temporary"}])
        automation = {"enabled": True, "steps": None, "read": False, "like": True,
                      "like_max_pages": 3, "like_page_size": 20}
        report = app.run_once(credentials(), self.protocol, gateway=gateway, automation=automation)
        self.assertFalse(report["ok"])
        self.assertEqual(report["automation"]["like"], "failed")
        self.assertIn("LIKE_LIST_REQUEST_FAILED", report["automation_errors"])

    def test_automation_transport_failure_still_collects_rewards(self):
        reward = {"id": "reward-1", "valDefineCode": "ZEEKR_VALUE", "val": 10}
        gateway = Gateway([center(True), center(True), app.ApiError("NETWORK_ERROR"),
                           rewards([reward]), {"code": "000000", "data": {}}, rewards([])])
        automation = {"enabled": True, "steps": 10000, "read": False, "like": False,
                      "like_max_pages": 3, "like_page_size": 20}
        report = app.run_once(credentials(), self.protocol, gateway=gateway, automation=automation, claim=True)
        self.assertFalse(report["ok"])
        self.assertEqual(report["error"], "AUTOMATION_FAILED")
        self.assertEqual(report["automation"]["steps"], "failed")
        self.assertEqual(report["verified_removed_rewards"], 1)
        self.assertEqual(report["remaining_rewards"], 0)

    def test_task_list_transport_failure_still_collects_rewards(self):
        reward = {"id": "reward-1", "valDefineCode": "ZEEKR_VALUE", "val": 10}
        gateway = Gateway([center(True), center(True), app.ApiError("NETWORK_ERROR"), rewards([reward]),
                           {"code": "000000", "data": {}}, rewards([])], [])
        automation = {"enabled": True, "steps": None, "read": True, "like": False,
                      "like_max_pages": 3, "like_page_size": 20}
        report = app.run_once(credentials(), self.protocol, gateway=gateway, automation=automation, claim=True)
        self.assertFalse(report["ok"])
        self.assertEqual(report["error"], "AUTOMATION_FAILED")
        self.assertEqual(report["verified_removed_rewards"], 1)

    def test_article_transport_failure_still_collects_rewards(self):
        task_list = {"code": "000000", "data": {"taskReachMsgList": [
            {"name": "阅读文章", "doc": {"path": "/detail?acticleId=article-123"}},
        ]}}
        reward = {"id": "reward-1", "valDefineCode": "ZEEKR_VALUE", "val": 10}
        gateway = Gateway([center(True), center(True), task_list, rewards([reward]),
                           {"code": "000000", "data": {}}, rewards([])], [app.ApiError("NETWORK_ERROR")])
        automation = {"enabled": True, "steps": None, "read": True, "like": False,
                      "like_max_pages": 3, "like_page_size": 20}
        report = app.run_once(credentials(), self.protocol, gateway=gateway, automation=automation, claim=True)
        self.assertFalse(report["ok"])
        self.assertEqual(report["error"], "AUTOMATION_FAILED")
        self.assertEqual(report["verified_removed_rewards"], 1)

    def test_reward_query_failure_is_not_reported_as_empty(self):
        gateway = Gateway([center(True), center(True), {"code": "FAIL", "msg": "rejected"}])
        report = app.run_once(credentials(), self.protocol, gateway=gateway)
        self.assertFalse(report["ok"])
        self.assertEqual(report["error"], "REWARD_QUERY_FAILED")
        self.assertIsNone(report["remaining_rewards"])

    def test_known_empty_gateway_profile_without_optional_list_is_success(self):
        empty_profile = {"code": "000000", "data": {
            "accountId": "9000000000000000001", "headImage": "https://example.invalid/avatar",
            "nickname": "test", "totalVal": 0, "integralTotalVal": 42
        }}
        gateway = Gateway([center(True), center(True), empty_profile])
        report = app.run_once(credentials(), self.protocol, gateway=gateway)
        self.assertTrue(report["ok"])
        self.assertEqual(report["remaining_rewards"], 0)

    def test_missing_reward_data_is_not_reported_as_empty(self):
        gateway = Gateway([center(True), center(True), {"code": "000000", "data": {}}])
        report = app.run_once(credentials(), self.protocol, gateway=gateway)
        self.assertFalse(report["ok"])
        self.assertEqual(report["error"], "REWARD_RESPONSE_SCHEMA_ERROR")

    def test_wrong_account_profile_is_rejected(self):
        wrong_profile = {"code": "000000", "data": {
            "accountId": "9999999999999999999", "headImage": "", "nickname": "test",
            "totalVal": 0, "integralTotalVal": 0, "uncollectedVal": []
        }}
        gateway = Gateway([center(True), center(True), wrong_profile])
        report = app.run_once(credentials(), self.protocol, gateway=gateway)
        self.assertFalse(report["ok"])
        self.assertEqual(report["error"], "ACCOUNT_MISMATCH")

    def test_claim_success_is_verified_with_second_reward_query(self):
        item = {"id": "reward-123", "valDefineCode": "ZEEKR_VALUE", "val": 10}
        gateway = Gateway([center(True), center(True), rewards([item]),
                           {"code": "000000", "data": {}}, rewards([])])
        report = app.run_once(credentials(), self.protocol, gateway=gateway, claim=True)
        self.assertTrue(report["ok"])
        self.assertEqual(report["verified_removed_rewards"], 1)
        self.assertEqual(gateway.requests[3][1], {"energyIds": ["reward-123"]})

    def test_daily_signin_fragment_is_claimed_and_verified(self):
        item = {"id": "fragment-1", "valDefineCode": "DEBRIS", "sceneCode": "EASY_DEBRIS",
                "eventCode": "medal_compose_easy_draw", "sourceId": "signup-2030-01-01"}
        gateway = Gateway([center(True), center(True), rewards([item]),
                           {"code": "000000", "data": [{"success": True}]}, rewards([])])
        report = app.run_once(credentials(), self.protocol, gateway=gateway, claim=True)
        self.assertTrue(report["ok"])
        self.assertEqual(report["verified_removed_rewards"], 1)
        self.assertEqual(gateway.requests[3], (
            "/zeekrlife-mp-mkt/toc/v1/apply/batchApply",
            {"applyCmdList": [{"record": "medal_compose_easy_draw",
                               "payContent": {"bubbleAssetsId": "fragment-1"},
                               "applyExt": {"origin": "signup-2030-01-01"}}]}
        ))

    def test_fragment_nested_failure_is_recorded_even_with_success_envelope(self):
        item = {"id": "fragment-1", "valDefineCode": "DEBRIS",
                "eventCode": "medal_compose_easy_draw", "sourceId": "signup-2030-01-01"}
        gateway = Gateway([center(True), center(True), rewards([item]),
                           {"code": "000000", "data": [{"success": False, "msg": "risk parameters missing"}]},
                           rewards([item])])
        report = app.run_once(credentials(), self.protocol, gateway=gateway, claim=True)
        self.assertFalse(report["ok"])
        self.assertEqual(report["remaining_rewards"], 1)
        self.assertEqual(report["claim_attempt_errors"][0]["message"], "risk parameters missing")

    def test_fragment_missing_source_fields_is_not_sent_to_claim_gateway(self):
        item = {"id": "fragment-1", "valDefineCode": "DEBRIS"}
        gateway = Gateway([center(True), center(True), rewards([item]), rewards([item])])
        report = app.run_once(credentials(), self.protocol, gateway=gateway, claim=True)
        self.assertFalse(report["ok"])
        self.assertEqual(report["claim_attempt_errors"][0]["error"], "FRAGMENT_SOURCE_FIELDS_MISSING")
        self.assertEqual(len(gateway.requests), 4)

    def test_seven_day_scene_keeps_its_distinct_claim_response_contract(self):
        item = {"id": "seven-day-1", "valDefineCode": "DEBRIS",
                "sceneCode": "SIGN_CONTINUOUS_7_LOTTERY"}
        gateway = Gateway([center(True), center(True), rewards([item]),
                           {"code": "000000", "data": {"success": True}}, rewards([])])
        report = app.run_once(credentials(), self.protocol, gateway=gateway, claim=True)
        self.assertTrue(report["ok"])
        self.assertNotIn("claim_attempt_errors", report)
        self.assertEqual(gateway.requests[3][0], "/zeekrlife-mp-mkt/toc/v1/applyV2/apply")

    def test_reward_still_present_after_claim_is_failure(self):
        item = {"id": "reward-123", "valDefineCode": "ZEEKR_VALUE", "val": 10}
        gateway = Gateway([center(True), center(True), rewards([item]),
                           {"code": "000000", "data": {}}, rewards([item])])
        report = app.run_once(credentials(), self.protocol, gateway=gateway, claim=True)
        self.assertFalse(report["ok"])
        self.assertEqual(report["error"], "REWARDS_REMAIN")

    def test_claim_transport_failure_still_verifies_prior_success(self):
        items = [{"id": "reward-1", "valDefineCode": "ZEEKR_VALUE", "val": 10},
                 {"id": "reward-2", "valDefineCode": "ZEEKR_VALUE", "val": 10}]
        gateway = Gateway([center(True), center(True), rewards(items),
                           {"code": "000000", "data": {}}, app.ApiError("NETWORK_ERROR"),
                           rewards(items[1:])])
        report = app.run_once(credentials(), self.protocol, gateway=gateway, claim=True)
        self.assertFalse(report["ok"])
        self.assertEqual(report["remaining_rewards"], 1)
        self.assertEqual(report["verified_removed_rewards"], 1)

    def test_claim_timeout_with_confirmed_removal_is_success(self):
        item = {"id": "reward-1", "valDefineCode": "ZEEKR_VALUE", "val": 10}
        gateway = Gateway([center(True), center(True), rewards([item]),
                           app.ApiError("NETWORK_ERROR"), rewards([])])
        report = app.run_once(credentials(), self.protocol, gateway=gateway, claim=True)
        self.assertTrue(report["ok"])
        self.assertEqual(report["verified_removed_rewards"], 1)

    def test_failed_post_claim_verification_reports_unknown_count(self):
        item = {"id": "reward-1", "valDefineCode": "ZEEKR_VALUE", "val": 10}
        gateway = Gateway([center(True), center(True), rewards([item]),
                           {"code": "000000", "data": {}}, {"code": "FAIL", "msg": "rejected"}])
        report = app.run_once(credentials(), self.protocol, gateway=gateway, claim=True)
        self.assertFalse(report["ok"])
        self.assertIsNone(report["remaining_rewards"])
        self.assertEqual(report["error"], "REWARD_QUERY_FAILED")

    def test_server_error_message_does_not_leak_authorization(self):
        config = credentials()
        gateway = Gateway([{"code": "FAIL", "msg": config["authorization"]}])
        report = app.run_once(config, self.protocol, gateway=gateway)
        self.assertNotIn(config["authorization"], json.dumps(report))

    def test_native_oauth_or_missing_account_is_rejected_before_http(self):
        gateway = Gateway([])
        report = app.run_once({"authorization": "Bearer opaque-native-token"}, self.protocol, gateway=gateway)
        self.assertEqual(report["error"], "INVALID_TOKEN")
        self.assertEqual(gateway.requests, [])


if __name__ == "__main__":
    unittest.main()

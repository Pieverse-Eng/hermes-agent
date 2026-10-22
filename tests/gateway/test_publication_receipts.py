"""Publication success means the host registered the original usable message."""
from gateway.interactive_messages import current_message_scope, send_current_message


def test_host_rejection_never_reports_a_usable_message():
    def reject(*args):
        return {"success": False, "error": "CARD_ACTION_UNAVAILABLE", "publication": {"status": "rejected"}}
    with current_message_scope(reject):
        result = send_current_message("Review the draft", metadata={"coachCard": {"version": 1}})
    assert result.get("success") is False
    assert result["error"] == "CARD_ACTION_UNAVAILABLE"
    assert result["publication"]["status"] == "rejected"


from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from uuid import uuid4

import pytest

from gateway.publication_receipts import AcknowledgedPublisher, PUBLICATION_OPERATION

CARD = {"coachCard": {"version": 1, "kind": "paper_practice_invite", "title": "Practice"}}


class Host:
    def __init__(self):
        self.calls = []
        self.failures = []

    def call(self, operation, payload):
        assert operation == PUBLICATION_OPERATION
        self.calls.append(payload)
        if self.failures:
            return self.failures.pop(0)
        return {"status": "ready", "publication": {
            "status": "registered", "messageId": payload["message_id"],
            "runId": str(uuid4()), "sessionId": str(uuid4()), "hash": "a" * 64,
        }}


def test_success_and_duplicate_share_registered_identity_and_one_visible_card():
    host, visible = Host(), []
    publisher = AcknowledgedPublisher(host, lambda *args: visible.append(args))
    def send():
        with current_message_scope(publisher):
            return send_current_message("Try Paper", metadata=CARD)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first, second = list(pool.map(lambda _: send(), range(2)))
    assert first["success"] and second["success"]
    assert first["message_id"] == second["message_id"] == visible[0][1]
    assert len(visible) == len(host.calls) == 1
    assert first["publication"]["status"] == "registered"
    assert first.get("duplicate") or second.get("duplicate")


def test_native_publication_returns_original_registered_resource_for_followup_save():
    class RegisteredHost(Host):
        def call(self, operation, payload):
            result = super().call(operation, payload)
            result['registered'] = {'coachCard': {'id': '72a71769-36a3-428d-a47c-00ebcddf85a6', 'kind': 'playbook_proposal', 'version': 1}}
            return result
    host, visible = RegisteredHost(), []
    # A registered acknowledgement also hands its presentation to delivery.
    with current_message_scope(AcknowledgedPublisher(host, lambda *args, **kwargs: visible.append(args))):
        first = send_current_message('Your preferences', metadata=CARD)
        retried = send_current_message('Your preferences', metadata=CARD)
    assert first['registered']['coachCard']['id'] == '72a71769-36a3-428d-a47c-00ebcddf85a6'
    assert first['registered'] == retried['registered']
    assert first['registered']['coachCard']['id'] != first['message_id']
    assert len(host.calls) == len(visible) == 1


@pytest.mark.parametrize('registered_context', [True, False])
def test_registered_acknowledgement_round_trips_beside_presented_card_scope_and_context(registered_context):
    # The visible message carries only the registered card, callback scope and
    # context; the tool result carries those and the whole bounded acknowledgement.
    registered = {'coachCard': {'id': 'card-id', 'kind': 'playbook_proposal', 'version': 1},
                  'callbackScope': {'id': 'scope-id'}, 'resources': [{'kind': 'playbook', 'id': 'resource-id'}],
                  **({'context': {'version': 2, 'execution_policy': 'pawpilot', 'host_data': {'page': 'saved'}}}
                     if registered_context else {})}
    class RegisteredHost(Host):
        def call(self, operation, payload):
            return {**super().call(operation, payload), 'registered': deepcopy(registered)}
    host, attempts = RegisteredHost(), []
    def deliver(*args, **kwargs):
        attempts.append(kwargs)
        if len(attempts) == 1:
            raise TimeoutError()
    run_context = {'version': 2, 'execution_policy': 'pawpilot'}
    with current_message_scope(AcknowledgedPublisher(host, deliver), run_context):
        unseen = send_current_message('Your preferences', metadata=CARD)
        first = send_current_message('Your preferences', metadata=CARD)
        duplicate = send_current_message('Your preferences', metadata=CARD)
    shown = {'coachCard': registered['coachCard'], 'callbackScope': registered['callbackScope'],
             'context': registered.get('context')}
    assert unseen['error'] == 'CURRENT_MESSAGE_DELIVERY_UNKNOWN'
    assert attempts == [{'presentation': shown}] * 2
    assert len(host.calls) == 1
    for result in (first, duplicate):
        assert result['success'] is True and result['message_id'] == unseen['message_id']
        assert result['registered'] == registered
        assert {key: result[key] for key in shown} == shown
        assert result['context'] != run_context
    assert duplicate['duplicate'] is True


def test_unknown_registration_retries_original_message_and_rejection_stays_failed():
    host, visible = Host(), []
    host.failures = [{"status": "error", "error": {"code": "HOST_CALL_UNKNOWN"}, "callId": "original-call"}]
    publisher = AcknowledgedPublisher(host, lambda *args: visible.append(args))
    with current_message_scope(publisher):
        unknown = send_current_message("Try Paper", metadata=CARD)
        assert unknown["error"] == "HOST_CALL_UNKNOWN" and not visible
        recovered = send_current_message("Try Paper", metadata=CARD)
    assert recovered["success"] is True
    assert unknown["message_id"] == recovered["message_id"]
    assert host.calls[0] == host.calls[1]
    host.failures = [{"status": "blocked", "reason": "CARD_INVALID", "retrySameInput": False}]
    with current_message_scope(publisher):
        failed = send_current_message("Different", metadata=CARD)
        repeated = send_current_message("Different", metadata=CARD)
    assert failed == repeated
    assert failed["success"] is False
    assert len(host.calls) == 3 and len(visible) == 1


def test_registered_but_unseen_retries_delivery_without_registration_or_new_identity():
    host, visible = Host(), []
    def deliver(*args):
        if not visible:
            visible.append("lost")
            raise TimeoutError()
        visible.append(args)
    publisher = AcknowledgedPublisher(host, deliver)
    with current_message_scope(publisher):
        failed = send_current_message("Try Paper", metadata=CARD)
        recovered = send_current_message("Try Paper", metadata=CARD)
    assert failed["error"] == "CURRENT_MESSAGE_DELIVERY_UNKNOWN"
    assert recovered["success"] is True
    assert recovered["message_id"] == failed["message_id"]
    assert len(host.calls) == 1 and len(visible) == 2


def test_separate_runs_and_plain_repeated_text_have_distinct_publications():
    visible, host = [], Host()
    for _ in range(2):
        publisher = AcknowledgedPublisher(host, lambda *args: visible.append(args))
        with current_message_scope(publisher):
            send_current_message("Try Paper", metadata=CARD)
            send_current_message("Hello")
            send_current_message("Hello")
    assert len(visible) == 6
    assert len({item[1] for item in visible}) == 6
    assert not send_current_message("Outside").get("success")


def test_mismatched_or_missing_ack_cannot_publish():
    host, visible = Host(), []
    host.failures = [{"status": "ready", "publication": {
        "status": "registered", "messageId": "someone-else", "runId": str(uuid4()),
        "sessionId": str(uuid4()), "hash": "a" * 64}}]
    with current_message_scope(AcknowledgedPublisher(host, lambda *args: visible.append(args))):
        result = send_current_message("Try Paper", metadata=CARD)
    assert result["success"] is False and not visible


def test_unknown_plain_delivery_recovers_identity_before_allowing_new_repeated_text():
    host, attempts = Host(), []
    def deliver(*args):
        attempts.append(args)
        if len(attempts) == 1:
            raise TimeoutError()
    publisher = AcknowledgedPublisher(host, deliver)
    with current_message_scope(publisher):
        unknown = send_current_message("Plain answer")
        recovered = send_current_message("Plain answer")
        another = send_current_message("Plain answer")
    assert unknown["message_id"] == recovered["message_id"]
    assert another["message_id"] != recovered["message_id"]
    assert len(host.calls) == 2


def test_publication_budget_supports_utf8_and_metadata_without_widening_other_host_tools():
    from gateway.host_tools import HostToolBroker
    host, visible = None, []
    def publish(event):
        visible.append(event)
        host.resolve(event["callId"], event["requestHash"], {"status": "ready"})
    host = HostToolBroker("run", [PUBLICATION_OPERATION, "terminal_read"], publish)
    large = {"message": {"text": "中" * 4096}, "metadata": {"content": "x" * 32000}}
    assert host.call(PUBLICATION_OPERATION, large)["status"] == "ready"
    assert host.call("terminal_read", large)["error"]["code"] == "HOST_REQUEST_INVALID"
    assert host.call(PUBLICATION_OPERATION, {"content": "x" * 65536})["error"]["code"] == "HOST_REQUEST_INVALID"
    assert len(visible) == 1
    class InvalidHost:
        def call(self, *args):
            return {"status": "error", "error": {"code": "HOST_REQUEST_INVALID"}}
    with current_message_scope(AcknowledgedPublisher(InvalidHost(), lambda *args: None)):
        failed = send_current_message("Card too large", metadata=CARD)
    assert failed["success"] is False and failed["retrySameInput"] is False


def test_host_card_correction_fields_reach_the_agent_without_publishing_or_retrying():
    host, visible = Host(), []
    correction = {"category": "invalid_request", "recovery": "correct_request", "retrySameInput": False,
                  "fields": [{"path": "metadata.coachCard.kind", "code": "invalid_union_discriminator",
                              "allowedValues": ["paper_practice_invite", "playbook_proposal"]}]}
    host.failures = [{"status": "blocked", "reason": "CARD_INVALID", "retrySameInput": False,
                      "failure": correction}]
    publisher = AcknowledgedPublisher(host, lambda *args: visible.append(args))
    with current_message_scope(publisher):
        result = send_current_message("Your preferences", metadata=CARD)
    assert result["success"] is False and not visible
    assert result.get("failure") == correction
    assert len(host.calls) == 1


def test_invalid_string_metadata_requests_an_object_instead_of_claiming_a_card_exists():
    delivered = []
    with current_message_scope(lambda *args: delivered.append(args)):
        result = send_current_message("Your preferences", metadata='{"coachCard":{"version":1}}}')
    assert result.get("success") is False
    assert result.get("code") == "HOST_METADATA_INVALID"
    assert result["failure"]["recovery"] == "correct_request"
    assert result["failure"]["fields"][0]["path"] == "metadata"
    assert delivered == []


def test_correction_feedback_is_bounded_and_ignores_unrelated_host_details():
    host, visible = Host(), []
    correction = {"category": "invalid_request", "recovery": "correct_request", "retrySameInput": False,
                  "secret": "must not cross", "fields": [{"path": "metadata.coachCard.kind", "code": "invalid_type",
                  "message": "Expected object", "stack": "must not cross"}]}
    host.failures = [{"status": "blocked", "reason": "CARD_INVALID", "retrySameInput": False,
                      "failure": correction}]
    with current_message_scope(AcknowledgedPublisher(host, lambda *args: visible.append(args))):
        result = send_current_message("Invalid card", metadata=CARD)
    assert result["failure"] == {"category": "invalid_request", "recovery": "correct_request", "retrySameInput": False,
                                  "fields": [{"path": "metadata.coachCard.kind", "code": "invalid_type", "message": "Expected object"}]}
    correction["fields"][0]["message"] = "x" * 241
    host.failures = [{"status": "blocked", "reason": "CARD_INVALID", "retrySameInput": False, "failure": correction}]
    with current_message_scope(AcknowledgedPublisher(host, lambda *args: visible.append(args))):
        rejected = send_current_message("Other invalid card", metadata=CARD)
    assert rejected["success"] is False and "failure" not in rejected and visible == []

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
from uuid import uuid4

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

"""Behavioural check for issue #1276.

What the audit trail records for a call a deny policy refused:
  * mixed batch  - refused call + a call a person approves
  * fully refused batch
Decisions are captured at the two persistence seams the gate uses.
"""
from __future__ import annotations

import queue
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

import pytest

from tests.conftest import resolve_when_pending
from turnstone.server import WebUI

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture
def web_ui() -> Iterator[WebUI]:
    WebUI._global_queue = queue.Queue()
    yield WebUI(ws_id="ws-1276")
    WebUI._global_queue = None


def _item(name: str) -> dict[str, Any]:
    return {
        "call_id": f"c-{name}",
        "header": f"Tool: {name}",
        "preview": "",
        "func_name": name,
        "approval_label": name,
        "needs_approval": True,
        "_heuristic_verdict": {
            "verdict_id": f"v-{name}",
            "call_id": f"c-{name}",
            "func_name": name,
            "risk_level": "medium",
            "recommendation": "review",
            "confidence": 0.5,
            "tier": "heuristic",
        },
    }


def _capture(web_ui: WebUI, items: list[dict[str, Any]], policies: dict[str, str], person: bool):
    """Run the gate; return {verdict_id: final user_decision} as storage would see it."""
    final: dict[str, str] = {}

    def bulk(verdicts: list[dict[str, Any]], **_kw: Any) -> None:
        for v in verdicts:
            final.setdefault(v["verdict_id"], v.get("user_decision", ""))

    def decide(pending: list[dict[str, Any]], decision: str, **_kw: Any) -> None:
        for v in pending:
            final[v["verdict_id"]] = decision

    prompt = resolve_when_pending(web_ui, True) if person else None
    if prompt:
        prompt.start()
    try:
        with (
            patch("turnstone.core.storage._registry.get_storage", return_value=MagicMock()),
            patch("turnstone.core.policy.evaluate_loaded_tool_policies", return_value=policies),
            patch.object(web_ui, "_persist_intent_verdicts_bulk", side_effect=bulk),
            patch.object(web_ui, "_persist_verdict_decisions", side_effect=decide),
        ):
            result = web_ui.approve_tools(items)
    finally:
        if prompt:
            prompt.cancel()
    return result, final


def test_mixed_batch_refused_call_is_not_stamped_with_the_persons_decision(web_ui: WebUI):
    items = [_item("bash"), _item("write_file")]
    (approved, _), final = _capture(web_ui, items, {"bash": "deny"}, person=True)
    print("mixed batch decisions:", final)
    assert approved is True
    assert items[0]["_refused_by"] == "policy"
    assert final.get("v-write_file") == "approved"
    assert final.get("v-bash") == "policy_denied"


def test_fully_refused_batch_still_records_the_refused_verdict(web_ui: WebUI):
    items = [_item("bash")]
    (approved, _), final = _capture(web_ui, items, {"bash": "deny"}, person=False)
    print("fully refused decisions:", final)
    assert approved is False
    assert final.get("v-bash") == "policy_denied"


def test_late_llm_verdict_for_the_refused_call_gets_the_terminal_decision(web_ui: WebUI):
    """An LLM verdict landing after the person resolved the sibling call."""
    items = [_item("bash"), _item("write_file")]
    _capture(web_ui, items, {"bash": "deny"}, person=True)

    stamped: dict[str, str] = {}

    def single(verdict: dict[str, Any], **_kw: Any) -> None:
        stamped.setdefault(verdict["verdict_id"], verdict.get("user_decision", "pending"))

    def decide(pending: list[dict[str, Any]], decision: str, **_kw: Any) -> None:
        for v in pending:
            stamped[v["verdict_id"]] = decision

    late = {
        "verdict_id": "v-bash-llm",
        "call_id": "c-bash",
        "func_name": "bash",
        "risk_level": "high",
        "recommendation": "deny",
        "confidence": 0.9,
        "tier": "llm",
    }
    with (
        patch.object(web_ui, "_persist_intent_verdict", side_effect=single),
        patch.object(web_ui, "_persist_verdict_decisions", side_effect=decide),
    ):
        web_ui.on_intent_verdict(late)
    print("late LLM verdict decision:", stamped)
    assert stamped.get("v-bash-llm") == "policy_denied"

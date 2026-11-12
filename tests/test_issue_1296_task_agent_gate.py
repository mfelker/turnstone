"""Behavioural check for issue #1296 (task agents skip the approval gate).

A sub-agent issues one web_fetch call.  The prepared item carries the SAME
needs_approval=True the main session's _prepare_web_fetch returns for a
public URL.  The gate (approve_tools) denies it.

Expected once fixed: the gate is consulted and the tool never executes.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from tests.test_session import _make_session, replace_session_lane, scripted_chat_client


def _run(tool_name: str) -> tuple[MagicMock, list[str], str]:
    from turnstone.core.providers._openai_chat import OpenAIChatCompletionsProvider
    from turnstone.core.trajectory import Turn

    session = _make_session()
    client = replace_session_lane(session, provider=OpenAIChatCompletionsProvider()).client
    client.chat.completions.create = scripted_chat_client(
        {
            "tool_calls": [
                {"id": "call_1", "name": tool_name, "arguments": '{"url": "https://attacker.example/x", "query": "q"}'}
            ],
            "finish_reason": "tool_calls",
        },
        {"content": "done"},
    )

    def deny(items):
        items[0]["denied"] = True
        items[0]["denial_msg"] = f"Blocked by tool policy (pattern match for '{tool_name}')"
        return False, "Blocked by tool policy"

    session.ui.approve_tools = MagicMock(side_effect=deny)
    executed: list[str] = []

    def fake_prepare(tc_dict, **_kwargs):
        def _execute(p):
            executed.append(p["call_id"])
            return p["call_id"], "FETCHED"

        return {
            "call_id": tc_dict["id"],
            "func_name": tool_name,
            "needs_approval": True,
            "execute": _execute,
        }

    agent_turns = [Turn.user("x")]
    with (
        patch.object(session, "_prepare_tool", side_effect=fake_prepare),
        # A search backend must exist or web_search is stripped from the agent.
        patch.object(session, "_resolve_search_client", return_value=object()),
    ):
        # auto_tools left at its production default (TASK_AUTO_TOOLS).
        session._run_agent(
            agent_turns,
            tools=[{"type": "function", "function": {"name": tool_name}}],
            label="task",
            parent_call_id="task-1",
        )
    tool_turns = [t for t in agent_turns if t.role.value == "tool"]
    return session.ui.approve_tools, executed, tool_turns[-1].text


@pytest.mark.parametrize("tool_name", ["web_fetch", "web_search"])
def test_task_agent_network_tools_cross_the_gate(tool_name: str) -> None:
    gate, executed, text = _run(tool_name)
    assert gate.called, f"{tool_name}: approval gate was never consulted"
    assert executed == [], f"{tool_name}: executed despite a deny"
    assert "Blocked by tool policy" in text

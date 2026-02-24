"""Week 7 Streamlit UI for G1/G2 agents and OWASP sandbox demo."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import streamlit as st

from src.agents.agent_with_memory import create_agent_with_memory
from src.agents.multiagent_system import create_initial_state, create_multiagent_workflow
from src.config.settings import Settings
from src.sandbox.owasp_sandbox import (
    append_event_to_live_log,
    event_to_analysis_text,
    generate_event,
    list_scenarios,
)

MAX_UPLOAD_MB = 10
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024


@st.cache_resource
def get_memory_agent():
    """Cache memory-enabled agent instance."""
    return create_agent_with_memory(memory_type="buffer", max_messages=12, verbose=False)


@st.cache_resource
def get_multiagent_workflow():
    """Cache compiled multiagent workflow."""
    return create_multiagent_workflow()


def _render_multiagent_result(result: Dict[str, Any]):
    """Display multiagent sections."""
    with st.expander("Log Analysis", expanded=True):
        st.write(result.get("log_analysis", ""))
    with st.expander("Threat Prediction"):
        st.write(result.get("threat_prediction", ""))
    with st.expander("Incident Response"):
        st.write(result.get("incident_response", ""))
    with st.expander("Executive Summary", expanded=True):
        st.success(result.get("final_report", ""))


def _run_single_agent(logs: str):
    """Run G1 analysis and render output."""
    with st.spinner("Analyzing logs with single agent..."):
        progress = st.progress(0)
        agent = get_memory_agent()
        progress.progress(30)
        response = agent.run(f"Analyze these logs for threats and provide recommendations:\n{logs}")
        progress.progress(100)
        st.success(response)


def _run_multiagent(logs: str):
    """Run G2 assessment and render output."""
    with st.spinner("Running multiagent workflow..."):
        progress = st.progress(0)
        workflow = get_multiagent_workflow()
        progress.progress(20)
        state = create_initial_state(logs)
        progress.progress(40)
        result = workflow.invoke(state)
        progress.progress(100)
        _render_multiagent_result(result)


def _extract_input_logs(uploaded_file, text_input: str) -> str:
    """Resolve logs from file upload or direct text input."""
    if uploaded_file is not None:
        if uploaded_file.size > MAX_UPLOAD_BYTES:
            raise ValueError(f"File too large. Maximum size is {MAX_UPLOAD_MB}MB.")
        return uploaded_file.read().decode("utf-8")
    return text_input.strip()


def _sandbox_panel():
    """Render OWASP sandbox controls and event simulation."""
    st.subheader("Educational OWASP Sandbox (Local-Only)")
    st.warning("Intentionally vulnerable educational sandbox (for training only). Do not expose publicly.")

    col1, col2, col3 = st.columns(3)
    with col1:
        scenario = st.selectbox("Scenario", list_scenarios(), format_func=lambda x: x.upper())
    with col2:
        mode = st.radio("Mode", ["safe", "vulnerable"], horizontal=True)
    with col3:
        source_ip = st.text_input("Source IP", value="127.0.0.1")

    if st.button("Simulate Attack Event", use_container_width=True):
        event = generate_event(scenario, vulnerable_mode=(mode == "vulnerable"), source_ip=source_ip.strip() or "127.0.0.1")
        log_path = append_event_to_live_log(event)
        st.success(f"Event recorded to {log_path}")
        st.code(json.dumps(event, indent=2), language="json")
        st.session_state["sandbox_last_event_text"] = event_to_analysis_text(event)

    if st.button("Analyze Last Sandbox Event", use_container_width=True):
        event_text = st.session_state.get("sandbox_last_event_text", "")
        if not event_text:
            st.info("No sandbox event available yet. Simulate one first.")
        else:
            _run_multiagent(event_text)


def main():
    """Entrypoint for Streamlit app."""
    st.set_page_config(page_title="CyberSecurity Agent", layout="wide")
    st.title("CyberSecurity Support Agent")
    st.caption("Analyze logs, detect threats, and coordinate response with single-agent or multiagent mode.")

    with st.sidebar:
        st.header("Configuration")
        mode = st.radio("Agent Mode", ["Single Agent (G1)", "Multiagent System (G2)"])
        show_sandbox = st.toggle("Enable OWASP sandbox panel", value=True)
        if st.button("Clear chat history"):
            st.session_state["chat_history"] = []
            st.success("Chat history cleared.")

    uploaded_file = st.file_uploader("Upload system log file", type=["txt", "log", "json", "jsonl"])
    log_input = st.text_area("Or paste logs directly", placeholder="Paste system logs here...", height=160)

    col_a, col_b = st.columns(2)
    with col_a:
        run_analysis = st.button("Run Analysis", use_container_width=True)
    with col_b:
        run_full = st.button("Run Full Assessment", use_container_width=True)

    if run_analysis or run_full:
        try:
            logs = _extract_input_logs(uploaded_file, log_input)
            if not logs:
                st.info("Provide logs by upload or text input.")
            elif run_full or mode == "Multiagent System (G2)":
                _run_multiagent(logs)
            else:
                _run_single_agent(logs)
        except Exception as exc:
            st.error(f"Error: {exc}")
            st.info("Please verify input format and try again.")

    st.divider()
    st.subheader("Interactive Chat")

    if "chat_history" not in st.session_state:
        st.session_state["chat_history"] = []

    for message in st.session_state["chat_history"]:
        with st.chat_message(message["role"]):
            st.write(message["content"])

    user_input = st.chat_input("Ask the security agent anything...")
    if user_input:
        st.session_state["chat_history"].append({"role": "user", "content": user_input})
        try:
            with st.spinner("Agent thinking..."):
                response = get_memory_agent().run(user_input)
            st.session_state["chat_history"].append({"role": "assistant", "content": response})
            st.rerun()
        except Exception as exc:
            st.error(f"Chat error: {exc}")

    if show_sandbox:
        st.divider()
        _sandbox_panel()


if __name__ == "__main__":
    main()


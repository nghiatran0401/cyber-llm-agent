"""Customer-facing Streamlit UI for G1/G2 analysis and OWASP sandbox."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import time
from typing import Any, Dict, List

import streamlit as st

# Ensure project root is importable when launched via `streamlit run ui/streamlit/app.py`.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.agents.g1.agent_with_memory import create_agent_with_memory
from src.agents.g2.multiagent_system import run_multiagent_with_trace
from src.config.settings import Settings
from src.sandbox.owasp_sandbox import (
    append_event_to_live_log,
    event_to_analysis_text,
    generate_event,
    list_scenarios,
)

MAX_UPLOAD_MB = 10
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024
MAX_INPUT_CHARS = 50_000
G1_STEP_ORDER = ["InputPreparation", "RoutingPolicy", "SingleAgentExecution"]
G2_STEP_ORDER = ["LogAnalyzer", "ThreatPredictor", "IncidentResponder", "Orchestrator"]


@st.cache_resource
def get_memory_agent():
    """Cache memory-enabled agent instance."""
    return create_agent_with_memory(memory_type="buffer", max_messages=12, verbose=False)


def _summarize(text: str, max_len: int = 220) -> str:
    clean = (text or "").strip().replace("\n", " ")
    return clean if len(clean) <= max_len else clean[:max_len] + "..."


def _render_multiagent_result(result: Dict[str, Any]):
    with st.expander("Log Analysis", expanded=True):
        st.write(result.get("log_analysis", ""))
    with st.expander("Threat Prediction"):
        st.write(result.get("threat_prediction", ""))
    with st.expander("Incident Response"):
        st.write(result.get("incident_response", ""))
    with st.expander("Executive Summary", expanded=True):
        st.success(result.get("final_report", ""))


def _render_trace(trace_steps: List[Dict[str, str]], title: str):
    st.subheader(title)
    for idx, step in enumerate(trace_steps, start=1):
        with st.expander(f"Step {idx}: {step.get('step', 'Unknown')}", expanded=(idx == 1)):
            st.write(step.get("what_it_does", ""))
            st.caption("Prompt sent to this agent")
            st.code(step.get("prompt_preview", ""))
            st.caption("Input to this step")
            st.code(step.get("input_summary", ""))
            st.caption("Output from this step")
            st.code(step.get("output_summary", ""))


def _render_timeline(trace_steps: List[Dict[str, str]], step_order: List[str]):
    completed = {step.get("step", "") for step in trace_steps}
    cells = st.columns(len(step_order))
    for idx, step_name in enumerate(step_order):
        is_done = step_name in completed
        symbol = "✅" if is_done else "⏳"
        with cells[idx]:
            st.caption(f"{symbol} {step_name}")


def _validate_text_input(text: str, input_name: str):
    if not text or not text.strip():
        raise ValueError(f"{input_name} is empty.")
    if len(text) > MAX_INPUT_CHARS:
        raise ValueError(
            f"{input_name} is too large ({len(text)} chars). "
            f"Please keep it under {MAX_INPUT_CHARS} characters."
        )


def _run_single_agent_with_trace(user_prompt: str) -> Dict[str, Any]:
    """Run G1 flow with live trace visualization."""
    _validate_text_input(user_prompt, "Input text")
    start_time = time.perf_counter()
    trace: List[Dict[str, str]] = []
    trace_placeholder = st.empty()
    status = st.status("Running G1 single-agent steps...", expanded=True)

    step1 = {
        "step": "InputPreparation",
        "what_it_does": "Validates and prepares your request for the single agent.",
        "prompt_preview": _summarize(user_prompt),
        "input_summary": _summarize(user_prompt),
        "output_summary": "Input accepted and formatted.",
    }
    trace.append(step1)
    status.write(f"{step1['step']}: {step1['what_it_does']}")
    with trace_placeholder.container():
        _render_timeline(trace, G1_STEP_ORDER)
        _render_trace(trace, title="Live Agent Trace (G1)")

    strong = Settings.should_use_strong_model(user_prompt)
    high_risk = Settings.is_high_risk_task(user_prompt)
    selected_model = Settings.STRONG_MODEL_NAME if strong else Settings.FAST_MODEL_NAME
    step2 = {
        "step": "RoutingPolicy",
        "what_it_does": "Chooses model profile and evidence policy before execution.",
        "prompt_preview": _summarize(
            f"routing=auto strong={strong} high_risk={high_risk} model={selected_model}"
        ),
        "input_summary": f"strong={strong}, high_risk={high_risk}",
        "output_summary": f"Selected model: {selected_model}",
    }
    trace.append(step2)
    status.write(f"{step2['step']}: {step2['output_summary']}")
    with trace_placeholder.container():
        _render_timeline(trace, G1_STEP_ORDER)
        _render_trace(trace, title="Live Agent Trace (G1)")

    response = get_memory_agent().run(user_prompt)
    step3 = {
        "step": "SingleAgentExecution",
        "what_it_does": "Runs the single agent with tools and memory.",
        "prompt_preview": _summarize(user_prompt),
        "input_summary": _summarize(user_prompt),
        "output_summary": _summarize(response),
    }
    trace.append(step3)
    status.write(f"{step3['step']}: Response generated.")
    with trace_placeholder.container():
        _render_timeline(trace, G1_STEP_ORDER)
        _render_trace(trace, title="Live Agent Trace (G1)")

    status.update(label="G1 execution complete", state="complete")
    st.caption(f"Completed in {time.perf_counter() - start_time:.2f}s")
    return {"type": "g1", "response": response, "trace": trace}


def _run_multiagent_with_trace(logs: str) -> Dict[str, Any]:
    """Run G2 flow with live trace visualization."""
    _validate_text_input(logs, "Log input")
    start_time = time.perf_counter()
    with st.spinner("Running multiagent workflow..."):
        progress = st.progress(0)
        progress.progress(20)

        live_trace: List[Dict[str, str]] = []
        trace_placeholder = st.empty()
        status = st.status("Running multiagent steps...", expanded=True)

        def _on_step(step: Dict[str, str]):
            live_trace.append(step)
            status.write(f"{step['step']}: {step['what_it_does']}")
            with trace_placeholder.container():
                _render_timeline(live_trace, G2_STEP_ORDER)
                _render_trace(live_trace, title="Live Agent Trace (G2)")

        traced = run_multiagent_with_trace(logs, on_step=_on_step)
        status.update(label="Multiagent workflow complete", state="complete")
        progress.progress(100)
        st.caption(f"Completed in {time.perf_counter() - start_time:.2f}s")
        return {"type": "g2", "result": traced["result"], "trace": traced["trace"]}


def _extract_input_logs(uploaded_file, text_input: str) -> str:
    if uploaded_file is not None:
        if uploaded_file.size > MAX_UPLOAD_BYTES:
            raise ValueError(f"File too large. Maximum size is {MAX_UPLOAD_MB}MB.")
        suffix = Path(uploaded_file.name).suffix.lower()
        if suffix not in Settings.ALLOWED_LOG_EXTENSIONS:
            raise ValueError(
                f"Unsupported file type '{suffix}'. "
                f"Allowed: {sorted(Settings.ALLOWED_LOG_EXTENSIONS)}"
            )
        try:
            payload = uploaded_file.read().decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("Uploaded file is not valid UTF-8 text.") from exc
        _validate_text_input(payload, "Uploaded log file")
        return payload
    if text_input.strip():
        _validate_text_input(text_input, "Pasted logs")
    return text_input.strip()


def _render_result(execution: Dict[str, Any], prefix: str = ""):
    if execution.get("type") == "g1":
        st.subheader(f"{prefix}Single Agent Output")
        st.success(execution.get("response", ""))
    else:
        st.subheader(f"{prefix}Multiagent Output")
        _render_multiagent_result(execution.get("result", {}))


def _run_by_mode(mode: str, text: str) -> Dict[str, Any]:
    if mode == "Single Agent (G1)":
        return _run_single_agent_with_trace(text)
    return _run_multiagent_with_trace(text)


def _sandbox_tab(mode: str):
    st.subheader("Educational OWASP Sandbox (Local-Only)")
    st.warning("Intentionally vulnerable educational sandbox (for training only). Do not expose publicly.")

    col1, col2, col3 = st.columns(3)
    with col1:
        scenario = st.selectbox("Scenario", list_scenarios(), format_func=lambda x: x.upper())
    with col2:
        run_mode = st.radio("Mode", ["safe", "vulnerable"], horizontal=True)
    with col3:
        source_ip = st.text_input("Source IP", value="127.0.0.1")

    if st.button("Simulate Attack Event", use_container_width=True):
        event = generate_event(
            scenario,
            vulnerable_mode=(run_mode == "vulnerable"),
            source_ip=source_ip.strip() or "127.0.0.1",
        )
        log_path = append_event_to_live_log(event)
        st.success(f"Event recorded to {log_path}")
        st.code(json.dumps(event, indent=2), language="json")
        st.session_state["sandbox_last_event_text"] = event_to_analysis_text(event)

    if st.button("Analyze Last Sandbox Event", use_container_width=True):
        event_text = st.session_state.get("sandbox_last_event_text", "")
        if not event_text:
            st.info("No sandbox event available yet. Simulate one first.")
        else:
            prompt = f"Analyze this sandbox security event and recommend actions:\n{event_text}"
            execution = _run_by_mode(mode, prompt if mode == "Single Agent (G1)" else event_text)
            _render_result(execution, prefix="Sandbox ")


def main():
    st.set_page_config(page_title="CyberSecurity Agent", layout="wide")
    st.title("CyberSecurity Support Agent")
    sandbox_available = Settings.sandbox_enabled()
    st.caption(
        "Production-friendly views for log analysis and chat. "
        "OWASP sandbox appears only when explicitly enabled in non-production."
    )

    with st.sidebar:
        st.header("Configuration")
        mode = st.radio("Agent Mode", ["Single Agent (G1)", "Multiagent System (G2)"])
        if st.button("Clear chat history"):
            st.session_state["chat_history"] = []
            st.success("Chat history cleared.")

    tab_names = ["Upload System Logs", "Interactive Chat"]
    if sandbox_available:
        tab_names.append("Educational OWASP Sandbox")
    tab_objects = st.tabs(tab_names)
    tab_logs = tab_objects[0]
    tab_chat = tab_objects[1]

    with tab_logs:
        st.subheader("Upload or Paste Logs")
        uploaded_file = st.file_uploader("Upload system log file", type=["txt", "log", "json", "jsonl"])
        log_input = st.text_area("Or paste logs directly", placeholder="Paste system logs here...", height=180)

        col_a, col_b = st.columns(2)
        with col_a:
            run_analysis = st.button("Run Analysis", use_container_width=True, key="run_analysis_logs")
        with col_b:
            run_full = st.button("Run Full Assessment", use_container_width=True, key="run_full_logs")

        if run_analysis or run_full:
            try:
                logs = _extract_input_logs(uploaded_file, log_input)
                if not logs:
                    st.info("Provide logs by upload or text input.")
                else:
                    prompt = f"Analyze these logs for threats and provide recommendations:\n{logs}"
                    execution = _run_by_mode(mode, prompt if mode == "Single Agent (G1)" else logs)
                    _render_result(execution)
            except Exception as exc:
                st.error(f"Error: {exc}")
                st.info("Please verify input format and try again.")

    with tab_chat:
        st.subheader("Interactive Chat")
        if "chat_history" not in st.session_state:
            st.session_state["chat_history"] = []

        for message in st.session_state["chat_history"]:
            with st.chat_message(message["role"]):
                st.write(message["content"])

        user_input = st.chat_input("Ask the security agent anything...", key="chat_input_main")
        if user_input:
            st.session_state["chat_history"].append({"role": "user", "content": user_input})
            try:
                execution = _run_by_mode(mode, user_input)
                response_text = (
                    execution.get("response", "")
                    if execution.get("type") == "g1"
                    else execution.get("result", {}).get("final_report", "")
                )
                st.session_state["chat_history"].append({"role": "assistant", "content": response_text})
                _render_result(execution, prefix="Chat ")
            except Exception as exc:
                st.error(f"Chat error: {exc}")

    if sandbox_available:
        with tab_objects[2]:
            _sandbox_tab(mode)
    else:
        st.info(
            "OWASP sandbox is disabled. Set ENABLE_SANDBOX=true in a non-production "
            "environment to enable local training mode."
        )


if __name__ == "__main__":
    main()

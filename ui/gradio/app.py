"""Minimal Gradio interface for Week 7 alternative UI."""

from __future__ import annotations

import gradio as gr

from src.agents.g1.agent_with_memory import create_agent_with_memory
from src.agents.g2.multiagent_system import create_initial_state, create_multiagent_workflow


def _single_agent_analysis(logs_text: str) -> str:
    agent = create_agent_with_memory(memory_type="buffer", max_messages=12, verbose=False)
    return agent.run(f"Analyze these logs: {logs_text}")


def _multiagent_analysis(logs_text: str) -> str:
    workflow = create_multiagent_workflow()
    result = workflow.invoke(create_initial_state(logs_text))
    return (
        f"ANALYSIS:\n{result['log_analysis']}\n\n"
        f"THREAT PREDICTION:\n{result['threat_prediction']}\n\n"
        f"INCIDENT RESPONSE:\n{result['incident_response']}\n\n"
        f"SUMMARY:\n{result['final_report']}"
    )


def analyze_logs(logs_text: str, mode: str) -> str:
    if not logs_text.strip():
        return "Please provide logs."
    if mode == "Single Agent (G1)":
        return _single_agent_analysis(logs_text)
    return _multiagent_analysis(logs_text)


def chat_with_agent(message, history):
    del history
    agent = create_agent_with_memory(memory_type="buffer", max_messages=12, verbose=False)
    return agent.run(message)


def build_app():
    with gr.Blocks(title="CyberSecurity Agent") as demo:
        gr.Markdown("# CyberSecurity Support Agent")
        with gr.Tab("Log Analysis"):
            logs_input = gr.Textbox(label="System Logs", lines=10, placeholder="Paste logs here...")
            mode = gr.Radio(["Single Agent (G1)", "Multiagent System (G2)"], value="Single Agent (G1)")
            analyze_btn = gr.Button("Analyze")
            output = gr.Textbox(label="Results", lines=16)
            analyze_btn.click(analyze_logs, [logs_input, mode], output)

        with gr.Tab("Interactive Chat"):
            gr.ChatInterface(chat_with_agent, title="Security Agent Chat")

    return demo


if __name__ == "__main__":
    build_app().launch(server_name="0.0.0.0", server_port=7860)


"""
Purpose: Tool-enabled adaptive security agent
What it does:
- Builds LangChain agents with security analysis tools
- Routes requests to fast or strong models by risk intent
"""

from typing import Any
from langchain.agents import create_agent
from langchain_openai import ChatOpenAI
from src.tools.log_parser_tool import log_parser
from src.tools.cti_tool import cti_fetch
from src.tools.rag_tools import rag_retriever
from src.agents.shared.intent_routing import is_high_risk_intent
from src.config.settings import Settings
from src.utils.logger import setup_logger
from src.utils.prompt_templates import load_prompt_template

logger = setup_logger(__name__)


def _create_tool_agent(model_name: str, verbose: bool = True):
    """Create a LangChain agent with tools and system policy."""
    llm = ChatOpenAI(
        model=model_name,
        temperature=Settings.TEMPERATURE,
        openai_api_key=Settings.OPENAI_API_KEY,
    )
    tools = [log_parser, cti_fetch]
    if Settings.ENABLE_RAG:
        tools.append(rag_retriever)
    return create_agent(
        model=llm,
        tools=tools,
        system_prompt=load_prompt_template("g1/system_prompt.txt"),
        debug=verbose,
    )


def create_simple_agent(verbose: bool = True, task_hint: str = ""):
    """Create a single tool-enabled agent with model chosen from task hint."""
    try:
        Settings.validate()
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        raise

    is_high_risk = is_high_risk_intent(task_hint)
    selected_model = Settings.STRONG_MODEL_NAME if is_high_risk else Settings.FAST_MODEL_NAME
    logger.info("Creating simple agent with model: %s (high_risk=%s)", selected_model, is_high_risk)

    try:
        agent = _create_tool_agent(selected_model, verbose=verbose)
        logger.info("Simple tool-enabled agent created successfully.")
        return agent
    except Exception as e:
        logger.error(f"Error creating agent: {e}", exc_info=True)
        raise


class AdaptiveSecurityAgent:
    """Routes requests to fast or strong model based on task risk."""

    def __init__(self, verbose: bool = True):
        Settings.validate()
        self.verbose = verbose
        self.fast_model = Settings.FAST_MODEL_NAME
        self.strong_model = Settings.STRONG_MODEL_NAME
        self.fast_agent = _create_tool_agent(self.fast_model, verbose=verbose)
        self.strong_agent = _create_tool_agent(self.strong_model, verbose=verbose)
        logger.info(
            "Initialized AdaptiveSecurityAgent (fast=%s, strong=%s, routing=%s)",
            self.fast_model,
            self.strong_model,
            Settings.AUTO_MODEL_ROUTING,
        )

    @staticmethod
    def _extract_user_text(payload: Any) -> str:
        """Extract user text from common invoke payload shapes."""
        if isinstance(payload, dict):
            if "input" in payload and isinstance(payload["input"], str):
                return payload["input"]
            if "messages" in payload and payload["messages"]:
                last_msg = payload["messages"][-1]
                if isinstance(last_msg, tuple) and len(last_msg) == 2:
                    return str(last_msg[1])
                return str(last_msg)
        return str(payload)

    def invoke(self, payload: Any):
        """Invoke with auto-routing to fast/strong model via Semantic Router."""
        user_text = self._extract_user_text(payload)

        # Use Semantic Router to determine intent
        is_high_risk = is_high_risk_intent(user_text)

        selected_agent = self.strong_agent if is_high_risk else self.fast_agent
        selected_model = self.strong_model if is_high_risk else self.fast_model

        logger.info(
            "Routing request to %s model (high_risk=%s)",
            selected_model,
            is_high_risk,
        )

        return selected_agent.invoke(payload)

"""Simple tool-enabled security agent with model routing."""

from typing import Any
from langchain.agents import create_agent
from langchain_openai import ChatOpenAI
from src.tools.security_tools import log_parser, cti_fetch
from src.config.settings import Settings
from src.utils.logger import setup_logger

logger = setup_logger(__name__)


def _build_system_prompt() -> str:
    """Build system prompt with evidence-first guidance."""
    prompt = """You are a cybersecurity expert agent. Use the available tools to analyze security logs and fetch threat intelligence.

Your tasks include:
1. Parsing system logs to identify security threats
2. Fetching Cyber Threat Intelligence (CTI) for identified threats
3. Providing recommendations based on your analysis

Evidence policy:
- Prefer tool outputs over assumptions.
- If the user asks for incident-level or high-impact actions, gather evidence first before concluding.
- If evidence is missing, state uncertainty clearly and ask for the required logs or threat context.

Always be thorough and provide actionable security recommendations."""
    return prompt


def _create_tool_agent(model_name: str, verbose: bool = True):
    """Create a LangChain agent with tools and system policy."""
    llm = ChatOpenAI(
        model=model_name,
        temperature=Settings.TEMPERATURE,
        openai_api_key=Settings.OPENAI_API_KEY,
    )
    tools = [log_parser, cti_fetch]
    return create_agent(
        model=llm,
        tools=tools,
        system_prompt=_build_system_prompt(),
        debug=verbose,
    )


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
        """Invoke with auto-routing to fast/strong model."""
        user_text = self._extract_user_text(payload)
        use_strong = Settings.should_use_strong_model(user_text)
        high_risk = Settings.is_high_risk_task(user_text)

        selected_agent = self.strong_agent if use_strong else self.fast_agent
        selected_model = self.strong_model if use_strong else self.fast_model
        logger.info(
            "Routing request to %s model (high_risk=%s)",
            selected_model,
            high_risk,
        )

        if Settings.TOOL_MANDATORY_FOR_HIGH_RISK and high_risk:
            policy_prefix = (
                "High-risk task mode: use available tools first and base your conclusions on evidence. "
                "If tool evidence is insufficient, say what data is missing before giving recommendations.\n\n"
            )
            if isinstance(payload, dict) and "messages" in payload and payload["messages"]:
                updated_payload = dict(payload)
                updated_messages = list(payload["messages"])
                last_msg = updated_messages[-1]
                if isinstance(last_msg, tuple) and len(last_msg) == 2:
                    updated_messages[-1] = (last_msg[0], policy_prefix + str(last_msg[1]))
                else:
                    updated_messages[-1] = str(last_msg) + "\n\n" + policy_prefix
                updated_payload["messages"] = updated_messages
                return selected_agent.invoke(updated_payload)
            if isinstance(payload, dict) and "input" in payload:
                updated_payload = dict(payload)
                updated_payload["input"] = policy_prefix + str(payload["input"])
                return selected_agent.invoke(updated_payload)
            return selected_agent.invoke(policy_prefix + str(payload))

        return selected_agent.invoke(payload)


def create_simple_agent(verbose: bool = True, task_hint: str = ""):
    """Create a single tool-enabled agent with model chosen from task hint."""
    try:
        Settings.validate()
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        raise

    selected_model = Settings.STRONG_MODEL_NAME if Settings.should_use_strong_model(task_hint) else Settings.FAST_MODEL_NAME
    logger.info("Creating simple agent with model: %s", selected_model)

    try:
        agent = _create_tool_agent(selected_model, verbose=verbose)
        logger.info("Simple tool-enabled agent created successfully.")
        return agent
    except Exception as e:
        logger.error(f"Error creating agent: {e}", exc_info=True)
        raise


# Test agent
if __name__ == "__main__":
    try:
        print("Creating adaptive security agent...")
        agent = AdaptiveSecurityAgent(verbose=True)
        
        # Example task 1: Parse logs
        print("\n" + "="*60)
        print("Example 1: Parse system logs")
        print("="*60)
        result1 = agent.invoke({
            "messages": [("user", "Parse the system logs from sample_logs.txt and identify any security threats.")]
        })
        print("\nResult:")
        if isinstance(result1, dict) and "messages" in result1:
            last_message = result1["messages"][-1]
            if hasattr(last_message, 'content'):
                print(last_message.content)
            else:
                print(result1)
        else:
            print(result1)
        
        # Example task 2: Fetch CTI
        print("\n" + "="*60)
        print("Example 2: Fetch CTI intelligence")
        print("="*60)
        result2 = agent.invoke({
            "messages": [("user", "Fetch CTI intelligence on ransomware threats and provide recommendations.")]
        })
        print("\nResult:")
        if isinstance(result2, dict) and "messages" in result2:
            last_message = result2["messages"][-1]
            if hasattr(last_message, 'content'):
                print(last_message.content)
            else:
                print(result2)
        else:
            print(result2)
        
        # Example task 3: Combined task
        print("\n" + "="*60)
        print("Example 3: Combined analysis")
        print("="*60)
        result3 = agent.invoke({
            "messages": [("user", "Parse the system logs and check if there's a ransomware threat. Then fetch CTI intelligence on that threat type.")]
        })
        print("\nResult:")
        if isinstance(result3, dict) and "messages" in result3:
            last_message = result3["messages"][-1]
            if hasattr(last_message, 'content'):
                print(last_message.content)
            else:
                print(result3)
        else:
            print(result3)
        
    except Exception as e:
        logger.error(f"Error running agent: {e}", exc_info=True)
        print(f"Error: {e}")
        print("Make sure OPENAI_API_KEY is set in your .env file")

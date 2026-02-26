"""
Purpose: Shared semantic intent routing for model selection
What it does:
- Defines high-risk and standard intent routes
- Lazily initializes embedding encoder and router layer
- Classifies user prompts to drive adaptive model choice
"""

from semantic_router import Route, SemanticRouter
from semantic_router.encoders import OpenAIEncoder

from src.config.settings import Settings
from src.utils.logger import setup_logger

logger = setup_logger(__name__)

# Define the "high risk" intent route
high_risk_route = Route(
    name="high_risk",
    utterances=[
        "investigate the data breach",
        "analyze this malware sample",
        "there is a ransomware infection on the network",
        "contain the ransomware",
        "what zero-day vulnerabilities affect this server",
        "someone is exfiltrating data right now",
        "give me a step-by-step incident response plan for this",
        "reverse engineer this payload",
        "we are under a ddos attack",
        "find the root cause of this intrusion",
        "our database has been dropped and an ransom note was left",
        "an employee clicked a phishing link and downloaded a virus",
        "trace the attacker's ip address",
        "perform forensics on this disk image",
        "how do i remediate this active threat",
    ],
)

# Standard route for logging, checking, or basic explanations
standard_route = Route(
    name="standard",
    utterances=[
        "hello agent",
        "can you check these logs",
        "what is the weather today",
        "what does SQL injection mean",
        "fetch cti for this ip address",
        "parse my firewall logs",
        "summarize this alienvault otx report",
        "who logged in yesterday",
        "is port 80 open on my machine",
        "what is standard symmetric encryption",
        "help me write a python script",
    ],
)

# Initialize the encoder and route layer
_encoder = None
_route_layer = None


def _get_route_layer() -> SemanticRouter:
    """Lazy initialize the route layer to avoid loading embeddings on module import."""
    global _encoder, _route_layer

    if _route_layer is None:
        logger.info("Initializing Semantic Router layer...")
        # Use a lightweight embedding model for routing
        _encoder = OpenAIEncoder(name="text-embedding-3-small", openai_api_key=Settings.OPENAI_API_KEY)
        _route_layer = SemanticRouter(encoder=_encoder, routes=[high_risk_route, standard_route])

    return _route_layer


def is_high_risk_intent(user_text: str) -> bool:
    """
    Determine if the user's prompt is high risk/complex using Semantic Router.
    This replaces the old keyword-matching approach.
    """
    if not user_text or not str(user_text).strip():
        return False

    try:
        layer = _get_route_layer()
        route_choice = layer(user_text)

        # If it matches the high risk route, return True
        is_high_risk = route_choice.name == "high_risk"

        if route_choice.name:
            logger.info(f"Semantic Router classified prompt as: {route_choice.name}")
        else:
            logger.info("Semantic Router did not confidently match a route, defaulting to standard.")

        return is_high_risk

    except Exception as e:
        logger.error(f"Error during Semantic Routing: {e}", exc_info=True)
        # Fallback to standard if routing fails
        return False

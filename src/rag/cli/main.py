import json

from ..agents.mitre_agent import run_mitre_agent
from ..agents.otx_agent import run_otx_from_text
from ..agents.router import detect_input_type
from ..agents.conversation_manager import Interaction, conversation_manager


def main() -> None:
    user_input = input("Enter log snippet, technique, or indicator:\n\n")
    input_type = detect_input_type(user_input)

    response = {}

    if input_type == "technique":
        print("\n[+] Querying MITRE RAG...\n")
        response["mitre"] = run_mitre_agent(user_input)
    elif input_type == "ip":
        print("\n[+] Querying OTX for IP intelligence...\n")
        response["otx"] = run_otx_from_text(user_input)
    elif input_type == "hash":
        print("\n[+] Querying OTX for file intelligence...\n")
        response["otx"] = run_otx_from_text(user_input)
    else:
        print("\n[+] Sending log to MITRE RAG...\n")
        response["mitre"] = run_mitre_agent(user_input)
        # Also extract IOCs and query OTX (bounded), because logs often include indicators.
        response["otx"] = run_otx_from_text(user_input)

    conversation_manager.add_interaction(
        Interaction(user_input=user_input, input_type=input_type, response=response)
    )

    print("\n========== RESULT ==========\n")
    print(json.dumps(response, indent=2))


if __name__ == "__main__":
    main()


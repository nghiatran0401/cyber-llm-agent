from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class Interaction:
    user_input: str
    input_type: str
    response: Dict[str, Any]


class ConversationManager:
    """
    Minimal in-memory conversation manager.

    Stores the last N interactions so that agents can access recent context
    when needed. For the current CLI usage we keep it simple and process
    one turn at a time, but this is ready to be extended.
    """

    def __init__(self, max_history: int = 4) -> None:
        self.max_history = max_history
        self._history: List[Interaction] = []

    def add_interaction(self, interaction: Interaction) -> None:
        self._history.append(interaction)
        if len(self._history) > self.max_history:
            self._history = self._history[-self.max_history :]

    def get_history(self) -> List[Interaction]:
        return list(self._history)


conversation_manager = ConversationManager()


from typing import Annotated, Any, Dict, List

from langgraph.graph import add_messages
from pydantic import BaseModel


class AgentState(BaseModel):
    messages: Annotated[List[Any], add_messages]
    alert_raw: Dict[str, Any]
    temp_data: Dict[str, Any]
    analyze_result: Dict[str, Any]

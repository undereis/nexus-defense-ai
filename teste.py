from langgraph.graph import StateGraph, START, END
from typing_extensions import TypedDict

class State(TypedDict):
    mensagem: str

def ola(state):
    return {"mensagem": "Nexus Defense AI Online"}

graph = StateGraph(State)
graph.add_node("ola", ola)

graph.add_edge(START, "ola")
graph.add_edge("ola", END)

app = graph.compile()

print(app.invoke({}))

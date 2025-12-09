import json
from typing import Annotated, List, Literal, Any

from langchain.agents import create_agent
from langchain_core.messages import HumanMessage
from langchain_core.runnables import RunnableConfig
from langchain_core.tools import tool
from langgraph.graph import END, StateGraph, add_messages
from langgraph.graph.state import CompiledStateGraph
from langgraph.prebuilt import ToolNode
from pydantic import BaseModel, Field

from Lib.baseplaybook import LanggraphPlaybook
from PLUGINS.LLM.llmapi import LLMAPI
# from PLUGINS.Mock.CMDB import CMDB
from PLUGINS.Mock.cmdb_test import CMDB, get_ci_context_tool, fuzzy_search_ci_tool, get_cis_by_software_tool, get_cis_by_port_tool, get_cis_by_service_tool, \
    get_cis_by_user_tool


class CMDBAgent(object):

    @staticmethod
    @tool("cmdb_query_asset")
    def query_asset(
            ip: Annotated[str, "The IP address to search for (e.g., '10.67.3.130')"],
            hostname: Annotated[str, "The hostname to search for (e.g., 'WEB-SRV-01')"],
            owner: Annotated[str, "The email or name of the asset owner."]
    ) -> Annotated[str, "A dictionary containing asset details"]:
        """
        Query internal asset information from CMDB.
        """
        logs = CMDB.query_asset(ip, hostname, owner)
        return json.dumps(logs)


AGENT_NODE = "AGENT_NODE"
TOOL_NODE = "TOOL_NODE"


class AgentState(BaseModel):
    messages: Annotated[List[Any], add_messages] = Field(default_factory=list)

    query: str = Field(
        default="",
        description="用户的查询请求"
    )
    result: str = Field(
        default="",
        description="Agent最终执行结果"
    )


class GraphAgent(LanggraphPlaybook):

    def __init__(self):
        super().__init__()  # do not delete this code
        self.init()

    def init(self):
        tools = [
            get_ci_context_tool,
            fuzzy_search_ci_tool,
            get_cis_by_software_tool,
            get_cis_by_port_tool,
            get_cis_by_service_tool,
            get_cis_by_user_tool,
        ]

        tool_node = ToolNode(tools, name=TOOL_NODE)

        def route_after_agent(state: AgentState) -> Literal[TOOL_NODE, END]:
            messages = state.messages
            last_message = messages[-1]
            if last_message.tool_calls:
                return TOOL_NODE
            return END

        def agent_node(state: AgentState):
            system_prompt_template = self.load_system_prompt_template(f"system")
            system_message = system_prompt_template.format()

            messages = [
                system_message,
                *state.messages
            ]

            llm_api = LLMAPI()

            llm = llm_api.get_model(tag="fast")

            llm_with_tools = llm.bind_tools(tools)
            response = llm_with_tools.invoke(messages)

            return {"messages": [response]}

        workflow = StateGraph(AgentState)

        workflow.add_node(AGENT_NODE, agent_node)
        workflow.add_node(TOOL_NODE, tool_node)

        workflow.set_entry_point(AGENT_NODE)
        workflow.add_conditional_edges(AGENT_NODE, route_after_agent)
        workflow.add_edge(TOOL_NODE, AGENT_NODE)

        self.graph: CompiledStateGraph = workflow.compile(checkpointer=self.get_checkpointer())

    def cmdb_query(self, query):
        self.graph.checkpointer.delete_thread(self.module_name)
        config = RunnableConfig()
        config["configurable"] = {"thread_id": self.module_name}
        self.agent_state = AgentState(messages=[HumanMessage(content=query)])
        result = self.graph.invoke(self.agent_state, config)
        print(result) # 返回的是state 的dict
        return result


def cmdb_query(
        query: Annotated[str, "The CMDB query in natural language (e.g., 'Find asset with IP 10.10.10.10')"]
) -> Annotated[str, "The query result in JSON format"]:
    """
    Query internal asset information from CMDB using natural language.
    """
    llm_api = LLMAPI()

    llm = llm_api.get_model(tag="fast")

    CMDB_AGENT_TOOLS = [
        get_ci_context_tool,
        fuzzy_search_ci_tool,
        get_cis_by_software_tool,
        get_cis_by_port_tool,
        get_cis_by_service_tool,
        get_cis_by_user_tool,
    ]
    agent = create_agent(
        model=llm,
        tools=CMDB_AGENT_TOOLS,
        system_prompt="你是一个CMDB查询助手，能够根据用户的自然语言查询请求，调用合适的CMDB工具进行查询，并返回结果。",
    )

    response = agent.invoke({"messages": [HumanMessage(content=query)]})

    result = response['messages'][-1].content
    return result


class BaseAgent(object):
    @staticmethod
    def cmdb_query_graph(
            query: Annotated[str, "The CMDB query in natural language (e.g., 'Find asset with IP 10.10.10.10')"]
    ) -> Annotated[str, "The query result in JSON format"]:
        """
        Query internal asset information from CMDB using natural language with LangGraph.
        """
        pass


if __name__ == "__main__":
    query = "查找IP地址为192.168.10.5的资产信息"
    # result = BaseAgent.cmdb_query(query)
    # print("查询结果：", result)
    agent = GraphAgent()
    result = agent.cmdb_query(query)
    print(result)

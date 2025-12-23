import json
from enum import Enum
from typing import Any, Literal

from langchain_core.messages import HumanMessage
from langgraph.graph import StateGraph, START, END
from langgraph.graph.state import CompiledStateGraph
from langgraph.prebuilt import ToolNode
from pydantic import BaseModel, Field, ConfigDict

from AGENTS.knowledge_agent import KnowledgeAgent
from Lib.baseplaybook import LanggraphPlaybook
from Lib.llmapi import AgentState
from PLUGINS.LLM.llmapi import LLMAPI
from PLUGINS.SIRP.sirpapi import Case


class ConfidenceLevel(str, Enum):
    """Confidence Level"""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class Severity(str, Enum):
    """Severity Level"""
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class AnalyzeResult(BaseModel):
    """Structure for extracting user information from text"""
    model_config = ConfigDict(use_enum_values=True)

    original_severity: Severity = Field(description="Original alert severity")
    new_severity: Severity = Field(description="Recommended new severity level")
    confidence: ConfidenceLevel = Field(description="Confidence score, only one of 'Low', 'Medium', or 'High'")
    analysis_rationale: str | None = Field(description="Analysis process and reasons", default=None)
    current_attack_stage: str | dict[str, Any] | None = Field(description="e.g., 'T1059 - Command and Control', 'Lateral Movement'", default=None)
    recommended_actions: str | dict[str, Any] | None = Field(description="e.g., 'Isolate host 10.1.1.5'", default=None)


class Playbook(LanggraphPlaybook):
    TYPE = "CASE"
    NAME = "L3 SOC Analyst Agent"

    def __init__(self):
        super().__init__()
        self.init()

    def init(self):
        # 初始化工具
        tools = [KnowledgeAgent.search, AnalyzeResult]
        tool_node = ToolNode([KnowledgeAgent.search])

        def preprocess_node(state: AgentState):
            case = Case.get_raw_data(self.param_source_rowid)
            state.case = case
            # 将Case信息作为初始消息放入
            initial_content = f"Case Data: {json.dumps(case)}"
            return {"messages": [HumanMessage(content=initial_content)]}

        def analyze_node(state: AgentState):
            system_prompt_template = self.load_system_prompt_template("L3_SOC_Analyst")
            system_message = system_prompt_template.format()

            llm_api = LLMAPI()
            # 获取支持工具调用的模型
            llm = llm_api.get_model(tag=["structured_output", "function_calling"])
            llm_with_tools = llm.bind_tools(tools)

            messages = [system_message] + state.messages
            response = llm_with_tools.invoke(messages)
            return {"messages": [response]}

        def should_continue(state: AgentState) -> Literal["tools", "output", END]:
            last_message = state.messages[-1]
            if not last_message.tool_calls:
                return END

            # 检查是否调用了最终分析工具
            for tool_call in last_message.tool_calls:
                if tool_call["name"] == "AnalyzeResult":
                    return "output"
            return "tools"

        def output_node(state: AgentState):
            last_message = state.messages[-1]

            # 从 tool_calls 中提取 AnalyzeResult 的参数
            analyze_call = next(
                tc for tc in last_message.tool_calls if tc["name"] == "AnalyzeResult"
            )
            result_data = analyze_call["args"]
            analyze_result = AnalyzeResult(**result_data)

            case_field = [
                {"id": "severity", "value": analyze_result.new_severity},
                {"id": "confidence_ai", "value": analyze_result.confidence},
                {"id": "analysis_rationale_ai", "value": analyze_result.analysis_rationale},
                {"id": "attack_stage_ai", "value": analyze_result.current_attack_stage},
                {"id": "recommended_actions_ai", "value": analyze_result.recommended_actions},
            ]
            Case.update(self.param_source_rowid, case_field)

            self.send_notice("Case_L3_SOC_Analyst_Agent Finish", f"rowid:{self.param_source_rowid}")
            self.update_playbook("Success", "Get suggestion by ai agent completed.")
            return {"analyze_result": result_data}

        # 构建图
        workflow = StateGraph(AgentState)

        workflow.add_node("preprocess_node", preprocess_node)
        workflow.add_node("analyze_node", analyze_node)
        workflow.add_node("tools", tool_node)
        workflow.add_node("output_node", output_node)

        workflow.add_edge(START, "preprocess_node")
        workflow.add_edge("preprocess_node", "analyze_node")

        # 条件路由
        workflow.add_conditional_edges(
            "analyze_node",
            should_continue,
            {
                "tools": "tools",
                "output": "output_node",
                END: END
            }
        )

        workflow.add_edge("tools", "analyze_node")
        workflow.add_edge("output_node", END)

        self.agent_state = AgentState()
        self.graph: CompiledStateGraph = workflow.compile(checkpointer=self.get_checkpointer())
        return True

    def run(self):
        self.run_graph()
        return


if __name__ == "__main__":
    params_debug = {'source_rowid': 'f0189cf8-44af-4c46-90c7-988a159bb34c', 'source_worksheet': 'case'}
    module = Playbook()
    module._params = params_debug
    module.run()

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
    """
    【最终研判报告】
    当且仅当你通过分析原始 Case 数据，并结合 KnowledgeAgent.search 搜索到的外部情报得出定论后，调用此工具。
    调用此工具将提交最终分析结果并结束任务。
    """
    model_config = ConfigDict(use_enum_values=True)

    original_severity: Severity = Field(
        description="该案件（Case）在挂载新告警之前的初始严重程度。"
    )

    new_severity: Severity = Field(
        description="""
        基于新告警证据重新评估后的严重程度。
        判定逻辑：
        1. 如果新告警显示攻击链（Kill Chain）向后期演进（如从初始访问进入到权限维持或数据外泄），应显著提升级别。
        2. 如果新告警仅是已知风险的重复（噪声），应保持或降低级别。
        """
    )

    confidence: ConfidenceLevel = Field(
        description="""
        你对该研判结果的置信度得分。
        判定逻辑：
        - High: 存在异构证据交叉验证（例如 NDR 流量告警与 EDR 进程告警指向同一行为）。
        - Medium: 证据吻合攻击逻辑，但缺乏多维数据源佐证。
        - Low: 证据模糊，可能是误报或信息极度缺失。
        """
    )

    analysis_rationale: str | None = Field(
        default=None,
        description="""
        详细的分析推理过程。需包含：
        1. 识别到的新证据及 Artifacts。
        2. 新旧告警之间的关联逻辑（Contextualization）。
        3. 搜索工具（KnowledgeAgent）返回的情报如何辅助了你的判断。
        """
    )

    current_attack_stage: str | dict[str, Any] | None = Field(
        default=None,
        description="参考 MITRE ATT&CK 框架，标注当前案件最能代表攻击进度的战术名称（例如：'T1059 - Command and Control', 'Lateral Movement'）。"
    )

    recommended_actions: str | dict[str, Any] | None = Field(
        default=None,
        description="最关键、最具体的应急响应建议。动作需具备可执行性（例如：'Isolate host 10.1.1.5', 'Reset user password'）。"
    )


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

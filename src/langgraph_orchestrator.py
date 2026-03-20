import os
import logging
import operator
from typing import Dict, Any, List, Annotated
from typing_extensions import TypedDict
from langgraph.graph import StateGraph, START, END

logger = logging.getLogger(__name__)

class GraphState(TypedDict):
    vul_data: Dict[str, Any]
    rule_id: str
    vul_id: str
    
    # 状态累加
    iteration: int
    additional_context_source: str
    current_context_text: str
    
    # 用 operator.add 聚合多次分析的大模型思考过程
    accumulated_thinking: Annotated[List[str], operator.add]
    
    # 判定结果
    verdict: str
    thinking: str
    reason: str

class AuditGraphEngine:
    """基于 LangGraph 编排代码审计漏洞分析引擎"""
    def __init__(self, context_builder, analyzer, resolver, audit_logger, max_depth: int, project_root: str):
        self.context_builder = context_builder
        self.analyzer = analyzer
        self.resolver = resolver
        self.audit_logger = audit_logger
        self.max_depth = max_depth
        self.project_root = project_root
        
        self.graph = self._build_graph()

    def _build_graph(self):
        workflow = StateGraph(GraphState)
        
        workflow.add_node("analyze_vul", self.analyze_vul_node)
        workflow.add_node("resolve_context", self.resolve_context_node)
        
        workflow.add_edge(START, "analyze_vul")
        
        workflow.add_conditional_edges(
            "analyze_vul",
            self.route_after_analysis,
            {
                "resolve": "resolve_context",
                "end": END
            }
        )
        
        workflow.add_conditional_edges(
            "resolve_context",
            self.route_after_resolve,
            {
                "reanalyze": "analyze_vul",
                "end": END
            }
        )
        
        return workflow.compile()

    def analyze_vul_node(self, state: GraphState) -> Dict:
        iteration = state.get("iteration", 0) + 1
        vul_id = state["vul_id"]
        
        logger.info(f"  [{vul_id}] - Iteration {iteration}/{self.max_depth}")
        
        current_context_text = self.context_builder.build(
            state["vul_data"].get("flow", []), 
            additional_context=state.get("additional_context_source", "")
        )
        
        analysis_result = self.analyzer.analyze_vulnerability(state["rule_id"], current_context_text)
        
        verdict = analysis_result.get("verdict", "")
        thinking = analysis_result.get("thinking", "")
        reason = analysis_result.get("reason", "")
        
        self.audit_logger.log_process(
            rule_id=state["rule_id"], vul_id=vul_id,
            llm_input=current_context_text, llm_output=analysis_result.get("raw_output", ""),
            completions_added=state.get("additional_context_source", ""), final_conclusion=verdict,
            iteration_count=iteration
        )
        
        acc_think = [f"【推理轮次 {iteration}】\n{thinking}"]
        
        return {
            "iteration": iteration,
            "current_context_text": current_context_text,
            "verdict": verdict,
            "thinking": thinking,
            "reason": reason,
            "accumulated_thinking": acc_think
        }

    def route_after_analysis(self, state: GraphState) -> str:
        if state["verdict"] == "NEED_MORE_CONTEXT":
            if state["iteration"] >= self.max_depth:
                logger.warning(f"  [{state['vul_id']}] - Max iterations reached! Forcing END.")
                return "end"
            return "resolve"
            
        logger.info(f"  [{state['vul_id']}] - Reached solid conclusion: {state['verdict']}. Ending.")
        return "end"

    def route_after_resolve(self, state: GraphState) -> str:
        if state["verdict"] != "NEED_MORE_CONTEXT":
            return "end"
        return "reanalyze"

    def resolve_context_node(self, state: GraphState) -> Dict:
        vul_id = state["vul_id"]
        logger.info(f"  [{vul_id}] - Needs Context. Triggering ContextResolver...")
        
        funcs = self.resolver.extract_function_names(state["thinking"] + " " + state["reason"])
        if not funcs:
            logger.warning(f"  [{vul_id}] - LLM asked for context but no explicit function detected. Ending loops.")
            return {
                "verdict": "TRUE POSITIVE", 
                "reason": "LLM Requested context but no function name found."
            }

        new_contexts = []
        additional_context_source = state.get("additional_context_source", "")
        
        for func in funcs:
            if func.lower() == "sink": continue  
            
            sink_file = state["vul_data"].get("file", "")
            if sink_file and not os.path.isabs(sink_file):
                 sink_file = os.path.join(self.project_root, sink_file)
                 
            found_code = self.resolver.resolve_function(func, current_file=sink_file)
            
            if "TOO_MANY_MATCHES_ABORT" in found_code:
                 logger.warning(f"  [{vul_id}] - Too many overloaded implementations matching '{func}'. Aborting sweep.")
                 return {
                     "verdict": "TRUE POSITIVE",
                     "reason": f"方法 '{func}' 存在超过 2 个同源实现，存在语义混淆风险。已强行放弃深入并判真漏。"
                 }
            
            if found_code and found_code not in additional_context_source:
                new_contexts.append(found_code)
                
        if new_contexts:
            additional_context_source += "\n\n" + "\n\n".join(new_contexts)
            logger.info(f"  [{vul_id}] - Appended new code block(s). Continuing search.")
        else:
            logger.warning(f"  [{vul_id}] - Found code is identical or empty. Anti-Loop Trap activated.")
            additional_context_source += f"\n\n/* 系统高级禁令：关于您刚才请求的函数 '{','.join(funcs)}'，工程中无法发现它更深层的源码。请强制基于现有内容给出直接结论。严禁再次返回 NEED_MORE_CONTEXT！若无把握请判断 TRUE POSITIVE。*/"
        
        return {
            "additional_context_source": additional_context_source
        }

    def run(self, vul_data: dict, rule_id: str, vul_id: str) -> dict:
        initial_state: GraphState = {
            "vul_data": vul_data,
            "rule_id": rule_id,
            "vul_id": vul_id,
            "iteration": 0,
            "additional_context_source": "",
            "current_context_text": "",
            "accumulated_thinking": [],
            "verdict": "UNKNOWN",
            "thinking": "",
            "reason": ""
        }
        
        final_state = self.graph.invoke(initial_state)
        
        if final_state["verdict"] == "NEED_MORE_CONTEXT" and final_state["iteration"] >= self.max_depth:
             final_state["verdict"] = "TRUE POSITIVE"
             final_state["reason"] = "Recursion limit exceeded while resolving unknown functions."
             self.audit_logger.log_process(rule_id, vul_id, "[MAX ITERS REACHED]", "System forced TRUE POSITIVE limit exception.", "", "TRUE POSITIVE", final_state["iteration"] + 1)
             
        return {
            "verdict": final_state["verdict"],
            "reason": final_state["reason"],
            "thinking": "\n\n".join(final_state["accumulated_thinking"]),
            "iterations": final_state["iteration"]
        }

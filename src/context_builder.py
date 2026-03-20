import json
import os
import re
from typing import List, Dict
from src.config import Config
import logging

logger = logging.getLogger(__name__)

class ContextBuilder:
    """
    负责组装 LLM 所需的严格上下文格式
    """
    def __init__(self):
        pass

    def build(self, data_flow_steps: List[Dict], additional_context: str = "") -> str:
        """
        根据提取的 flow steps 组装发送给 LLM 的最终上下文文本。
         строго遵循: 上下5-10行，sink处标记 <-- Focus Here。
        
        :param data_flow_steps: 从 SarifParser 中提取的流程节点列表
        :param additional_context: 来自补充的函数上下文
        :return: 格式化后的字符串，适用于直接通过 LLMAnalyzer 传入到 Prompt 中
        """
        if not data_flow_steps:
            return "/* Error: No data flow steps provided. */"

        lines = []
        full_code_text = ""
        
        for step_data in data_flow_steps:
            step_num = step_data.get("step")
            file_path = step_data.get("file", "UnknownFile")
            code_content = step_data.get("code", "")
            full_code_text += code_content + "\n"
            
            # 使用 Focus Here 补充到特定 step 作为段标题，增强结构化提示效果
            marker = " <-- Target Sink" if step_data.get("focus") else ""
            lines.append(f"[Step {step_num}] {file_path}{marker}")
            lines.append(code_content)
            lines.append("-" * 40) # 步骤之间的分隔线
            
        if additional_context:
            lines.append("\n[ADDITIONAL CONTEXT]")
            lines.append(additional_context)
            lines.append("-" * 40)
            
        return "\n".join(lines)

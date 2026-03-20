import os
import re
import json
import logging
import requests
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# 系统内部默认的分析 Prompt 模板
SYSTEM_PROMPT = """你是一个专业的代码安全审计专家，负责对 CodeQL 扫描出的漏洞结果进行误报分析 (False Positive Detection)。

你的核心职责是：只负责分析是否为误报，严禁重新发现漏洞或扩展分析范围。

【分析规则】
1. 完全基于提供的数据流上下文代码进行分析，重点关注含 '<-- Focus Here' 标记的 Sink 节点及其前序流程。
2. 误报判断逻辑：
   - 发现有效防御漏洞的净化/校验/参数化等函数且作用于污染数据 -> FALSE POSITIVE (误报)
   - 未发现任何净化/校验函数 -> TRUE POSITIVE (真实漏洞)
   - 发现净化函数，但未作用于污染数据 -> TRUE POSITIVE
   - 函数存在但无法看到其内部实现，且可能与安全相关 -> NEED_MORE_CONTEXT
3. 不接受“猜测”的安全。不信任类似于 sanitize(), isSafe() 的函数名，除非明确已知其可靠性。如果实现不可见，必须要求更多上下文。
4. 如果无法判断、缺少关键函数实现、或提供的代码片段不完整阻碍判断，必须返回 NEED_MORE_CONTEXT。
5. 【关键规则：函数分析范围限制】
   - 仅分析“数据流路径上”的函数调用
   - 仅关注“参数包含污点变量”的函数
   - 如果某函数的参数不包含来自 Source 的污染数据，则忽略该函数（视为与漏洞无关）
   - 不允许对无关函数进行展开或推理
6. 【函数展开与上下文请求规则】
   - 如果某个函数直接接收或处理污点变量，但其实现未提供：
     → 必须返回 NEED_MORE_CONTEXT
     → 并在 THINKING 中使用特定的包裹标签严格指出缺失源码的函数名。为防止重名，**必须包含类名或实例名**（例如 ClassName.methodName 或 instance.methodName），格式严禁包含任何括号，必须严格为： <MISSING_FUNCTION>类名.方法名</MISSING_FUNCTION>
   - 如果函数调用链较深，仅请求当前判断所必需的最小函数（避免请求全部函数）
   - 不允许因为函数嵌套较多而进行整体代码推测
7. 【严格数据流约束】
   - 只分析污点变量的传播路径（Source → Sink）
   - 忽略未参与该路径的变量和分支
   - 即使同一函数中存在安全分支，只要数据流未经过，也不能作为安全依据
【输出格式要求】
严格按照以下格式输出你的分析结论，不要输出额外的寒暄或无关内容：

[THINKING]
（在这里写出你的分析过程，比如数据从哪来到哪去，中间经过了什么，有没有净化函数）
[/THINKING]

[VERDICT]
（只能填选以下三个值之一：TRUE POSITIVE / FALSE POSITIVE / NEED_MORE_CONTEXT）
[/VERDICT]

[REASON]
（用一句话概括得出上述结论的核心原因）
[/REASON]
"""

class LLMAnalyzer:
    """
    负责调用 LLM 并按规则判断误报。
    将组装好的漏洞上下文发送给 LLM，解析其遵循严格格式的返回结果。
    """
    def __init__(self, api_key: str, model_name: str = "gpt-4o", api_url: str = "https://api.openai.com/v1/chat/completions"):
        """
        初始化 LLM 分析器。
        :param api_key: 访问大语言模型的鉴权 Key。
        :param model_name: 调用的模型名称 (默认为 gpt-4o)。
        :param api_url: API 基础 URL。
        """
        self.api_key = api_key
        self.model_name = model_name
        self.api_url = api_url
        
        if not self.api_key:
            logger.warning("LLM_API_KEY is not set. LLM analysis will fail.")

    def analyze_vulnerability(self, rule_id: str, context_text: str) -> Dict[str, Any]:
        """
        调用大语言模型进行误报判定。
        :param rule_id: 诸如 CWE-089 的漏洞编号
        :param context_text: 由 ContextBuilder 生成的代码流等上下文文本
        :return: 包含判决结果字典。格式如 {"thinking": "...", "verdict": "...", "reason": "...", "raw_output": "...", "error": "..."}
        """
        user_prompt = f"漏洞类型规则：[{rule_id}]\n请分析以下代码流上下文，判断是否为真实漏洞或误报：\n\n{context_text}"
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        # 兼容用户配置了错误的 base_url (忘记携带/chat/completions)
        actual_url = self.api_url
        if not actual_url.endswith("/chat/completions"):
            actual_url = actual_url.rstrip("/") + "/chat/completions"
        
        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt}
            ],
            # 将 temperature 设低，保证推理确定性与格式严谨性
            "temperature": 0.1 
        }

        try:
            logger.info(f"Sending context to LLM ({actual_url}) for analysis...")
            response = requests.post(actual_url, headers=headers, json=payload, timeout=60)
            response.raise_for_status()
            
            response_json = response.json()
            llm_reply = response_json.get("choices", [])[0].get("message", {}).get("content", "")
            
            logger.debug(f"LLM Raw Output:\n{llm_reply}")
            
            # 解析规范化的输出格式
            parsed_result = self._parse_llm_response(llm_reply)
            parsed_result["raw_output"] = llm_reply
            
            return parsed_result
            
        except requests.exceptions.RequestException as e:
            err_msg = f"HTTP Request to LLM API failed: {e}"
            logger.error(err_msg)
            return self._build_error_response(err_msg)
            
        except (KeyError, IndexError, ValueError) as e:
            err_msg = f"Failed to parse LLM API JSON response: {e}"
            logger.error(err_msg)
            return self._build_error_response(err_msg)
            
        except Exception as e:
            err_msg = f"Unexpected error during LLM analysis: {e}"
            logger.error(err_msg)
            return self._build_error_response(err_msg)

    def _parse_llm_response(self, text: str) -> Dict[str, Any]:
        """
        使用正则表达式或字符串操作，严格解析 LLM 返回的三段内容。
        如格式不正确，触发安全兜底返回。
        """
        result = {
            "thinking": "",
            "verdict": "UNKNOWN",
            "reason": "",
            "error": None
        }
        
        # 解析 THINKING
        thinking_match = re.search(r"\[THINKING\](.*?)\[/THINKING\]", text, re.DOTALL | re.IGNORECASE)
        if thinking_match:
            result["thinking"] = thinking_match.group(1).strip()
            
        # 解析 VERDICT
        verdict_match = re.search(r"\[VERDICT\](.*?)\[/VERDICT\]", text, re.DOTALL | re.IGNORECASE)
        if verdict_match:
            raw_verdict = verdict_match.group(1).strip().upper()
            if "TRUE POSITIVE" in raw_verdict:
                result["verdict"] = "TRUE POSITIVE"
            elif "FALSE POSITIVE" in raw_verdict:
                result["verdict"] = "FALSE POSITIVE"
            elif "NEED_MORE_CONTEXT" in raw_verdict:
                result["verdict"] = "NEED_MORE_CONTEXT"
            else:
                result["error"] = f"Invalid VERDICT value extracted: {raw_verdict}"
                result["verdict"] = "TRUE POSITIVE" # 退化策略：保守判断为真漏洞
        else:
            result["error"] = "Missing [VERDICT] block in LLM response."
            result["verdict"] = "TRUE POSITIVE" # 退化策略

        # 解析 REASON
        reason_match = re.search(r"\[REASON\](.*?)\[/REASON\]", text, re.DOTALL | re.IGNORECASE)
        if reason_match:
            result["reason"] = reason_match.group(1).strip()
        else:
            result["reason"] = "解析 REASON 字段失败。原始回复格式异常。"

        return result

    def _build_error_response(self, error_msg: str) -> Dict[str, Any]:
        """构造出现异常时的保底响应（优先认为报真漏洞，保证审计的闭环与安全）。"""
        return {
            "thinking": "系统运行期间发生了错误，无法有效分析。",
            "verdict": "TRUE POSITIVE", # 安全守则：异常时不放行
            "reason": error_msg,
            "error": error_msg,
            "raw_output": ""
        }

if __name__ == "__main__":
    # 本地跑测试用
    logging.basicConfig(level=logging.INFO)
    api_key_test = os.environ.get("OPENAI_API_KEY", "test-key-replace-me")
    analyzer = LLMAnalyzer(api_key=api_key_test)
    
    # 模拟 ContextBuilder 传入的内容
    test_context = "  12 | String user = req.getParameter('user'); /* <-- Source */ \n  15 | db.execute('SELECT * FROM tab WHERE u = ' + user); <-- Focus Here"
    # res = analyzer.analyze_vulnerability("CWE-089", test_context)
    # print(json.dumps(res, indent=2, ensure_ascii=False))

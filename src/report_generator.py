import os
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class ReportGenerator:
    """
    负责生成符合要求的结构化 Markdown (或 Txt) 报告。
    支持所有漏洞追加写入到一个单一文件中。
    """
    def __init__(self, output_dir: str = "output"):
        self.output_dir = os.path.abspath(output_dir)
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def generate_md_report(self, result_data: Dict[str, Any], filename: str = "audit_report.md") -> str:
        """
        将单条漏洞及AI分析的断言结果追加写入到指定的 md 报告文件中。
        
        :param result_data: 包含漏洞元数据 (rule_id, message, file, line, flow) 
                            以及 AI 分析结果 (verdict, reason) 的字典。
        :param filename: 输出的文件名，默认是 audit_report.md
        :return: 生成的报告文件的绝对路径
        """
        report_path = os.path.join(self.output_dir, filename)
        
        # --- 1. 提取元数据 ---
        rule_id = result_data.get("rule_id", "UNKNOWN_RULE")
        message = result_data.get("message", "未提供漏洞描述")
        file_path = result_data.get("file", "Unknown File")
        line_num = result_data.get("line", "Unknown Line")
        
        # --- 2. 提取并组装调用链 (Call Chain) ---
        flow_steps = result_data.get("flow", [])
        call_chain = []
        for step in flow_steps:
            step_file = step.get("file", "Unknown")
            step_line = step.get("line", "?")
            # 出于报告简洁性，调用链仅使用文件名 (basename)
            call_chain.append(f"{os.path.basename(step_file)}:{step_line}")
            
        call_chain_str = " → ".join(call_chain) if call_chain else "无明显调用链数据"
        
        # --- 3. 提取核心代码片段 ---
        # 倾向于提取最终标记为 Focus 的那一步 (Sink点)；如果没有则取最后一步
        code_snippet = "/* 未提取到关键代码 */"
        if flow_steps:
             # 反向检索找出被 focus 的 step (最近一个漏洞发生点)
             target_step = next((s for s in reversed(flow_steps) if s.get("focus") is True), flow_steps[-1])
             code_snippet = target_step.get("code", "/* 代码内容为空 */")
             
        # --- 4. 提取 AI 分析的最终结论 ---
        ai_verdict = result_data.get("verdict", "UNKNOWN VERDICT")
        ai_reason = result_data.get("reason", "无")
        
        # --- 5. 按照要求的格式组装 Markdown 内容 ---
        md_content = f"""----------------------------------

[{rule_id}] {message}

文件：{file_path}
行号：{line_num}

[调用链]
{call_chain_str}

[代码片段]
```java
{code_snippet}
```

[AI结论]
{ai_verdict}

[原因]
{ai_reason}

"""
        # --- 6. 追加写入文件 ---
        try:
            with open(report_path, "a", encoding="utf-8") as f:
                f.write(md_content)
            logger.debug(f"Appended vulnerability to report: {report_path}")
        except Exception as e:
            logger.error(f"Failed to append to MD report {report_path}: {e}")
            
        return report_path

if __name__ == "__main__":
    # 本地跑测试用
    logging.basicConfig(level=logging.INFO)
    generator = ReportGenerator(output_dir="output")
    
    mock_data = {
        "rule_id": "CWE-089",
        "message": "User-provided value flows to this SQL statement.",
        "file": "/backend/src/UserDao.java",
        "line": 42,
        "flow": [
            {"step": 1, "file": "/backend/src/UserController.java", "line": 15, "code": "String id = req.getParameter('id');", "focus": False},
            {"step": 2, "file": "/backend/src/UserDao.java", "line": 42, "code": "db.execute('SELECT * FROM users WHERE id=' + id); <-- Focus Here", "focus": True}
        ],
        "verdict": "TRUE POSITIVE",
        "reason": "未发现针对从 HTTP 请求传入并拼接到 SQL 语句中的 id 参数做任何类型安全防御校验。"
    }
    
    generator.generate_md_report(mock_data)
    print("Test passed. Check output/audit_report.md")

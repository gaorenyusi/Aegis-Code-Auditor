import os
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class AuditLogger:
    """
    负责规范化记录每次安全审计日志
    """
    def __init__(self, logs_base_dir: str = "logs"):
        self.logs_base_dir = os.path.abspath(logs_base_dir)
        if not os.path.exists(self.logs_base_dir):
            os.makedirs(self.logs_base_dir)

    def log_process(self, rule_id: str, vul_id: str, 
                    llm_input: str, llm_output: str, 
                    completions_added: str, final_conclusion: str, 
                    iteration_count: int):
        """
        按照规定存入 logs/<rule_id>/<vul_id>.log
        """
        rule_dir = os.path.join(self.logs_base_dir, rule_id)
        if not os.path.exists(rule_dir):
            os.makedirs(rule_dir)

        log_file = os.path.join(rule_dir, f"{vul_id}.log")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        log_entry = (
            f"[{timestamp}] ITERATION {iteration_count}\n"
            f"=== COMPLETED CONTEXT ADDED ===\n{completions_added}\n"
            f"=== LLM INPUT ===\n{llm_input}\n"
            f"=== LLM OUTPUT ===\n{llm_output}\n"
            f"=== CONCLUSION SO FAR ===\n{final_conclusion}\n"
            f"===========================================================\n\n"
        )

        try:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(log_entry)
        except Exception as e:
            logger.error(f"Failed to write log for {rule_id}/{vul_id}: {e}")

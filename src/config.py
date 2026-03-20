import os
from dotenv import load_dotenv

# 加载当前目录的 .env 文件
load_dotenv()

class Config:
    MAX_RECURSION_DEPTH = 3
    # 优先从环境变量读取，如果没有则使用默认规则路径
    CODEQL_RULES_DIR = os.environ.get("CODEQL_RULES_DIR", r"E:\Tools\CMSTools\CodeQL\ql\java\ql\src\Security\CWE")
    CODEQL_EXT_RULES_DIR = os.environ.get("CODEQL_EXT_RULES_DIR", r"E:\Tools\CMSTools\CodeQL\ql\java\ql\src\experimental\Security\CWE")
    OUTPUT_DIR = "output"
    LOGS_DIR = "logs"
    LLM_API_KEY = os.environ.get("LLM_API_KEY", "your-default-llm-api-key")
    LLM_MODEL = os.environ.get("LLM_MODEL", "gpt-4o")
    LLM_API_URL = os.environ.get("LLM_API_URL", "https://api.openai.com/v1/chat/completions")

import json
import os
import logging
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

class SarifParser:
    """
    负责解析 SARIF 文件提取数据流。
    将 CodeQL 的 SARIF 转换为 LLM 可用的数据流结构。
    """
    def __init__(self, context_lines: int = 10):
        """
        初始化解析器。
        :param context_lines: 提取上下文的行数 (上下各 n 行)
        """
        self.context_lines = context_lines

    def parse_file(self, sarif_path: str, project_root: str = "") -> List[Dict]:
        """
        读取并解析 SARIF 文件。
        :param sarif_path: SARIF 文件的绝对路径
        :param project_root: 项目根路径，用于拼接代码文件的绝对路径
        :return: 包含漏洞元数据及数据流的列表
        """
        if not os.path.exists(sarif_path):
            logger.error(f"SARIF file not found: {sarif_path}")
            return []

        try:
            with open(sarif_path, 'r', encoding='utf-8') as f:
                sarif_data = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load JSON from {sarif_path}: {e}")
            return []

        parsed_results = []

        runs = sarif_data.get("runs", [])
        for run in runs:
            results = run.get("results", [])
            for result in results:
                # 提取基本信息
                rule_id = result.get("ruleId", "UNKNOWN_RULE")
                message = result.get("message", {}).get("text", "")
                
                # 提取主问题发生的位置 (Sink)
                primary_location = self._extract_location(result.get("locations", []), project_root)
                if not primary_location:
                    logger.warning(f"No primary location found for result. rule_id: {rule_id}")
                    continue

                item = {
                    "rule_id": rule_id,
                    "message": message,
                    "file": primary_location.get("file"),
                    "line": primary_location.get("line"),
                    "flow": []
                }

                # 提取数据流 (Data Flow) / 执行流 (Code Flow)
                code_flows = result.get("codeFlows", [])
                if code_flows:
                    # 通常我们分析第一条 threadFlow (最典型的调用路径)
                    thread_flows = code_flows[0].get("threadFlows", [])
                    if thread_flows:
                        locations = thread_flows[0].get("locations", [])
                        item["flow"] = self._extract_data_flow(locations, project_root)
                
                # 如果没有数据流，或者只包含单独的 Sink，我们确保提供 Sink 周围的代码
                if not item["flow"]:
                    fallback_step = {
                        "step": 1,
                        "file": primary_location.get("file"),
                        "line": primary_location.get("line"),
                        "code": self._get_code_snippet(primary_location.get("file"), primary_location.get("line"), focus=True),
                        "focus": True
                    }
                    item["flow"].append(fallback_step)
                else:
                    # 确保最后一步 (Sink) 被标记为 focus
                    if item["flow"]:
                        item["flow"][-1]["focus"] = True
                        # 重新提取带 focus 标记的代码片段
                        last_step = item["flow"][-1]
                        last_step["code"] = self._get_code_snippet(last_step["file"], last_step["line"], focus=True)

                parsed_results.append(item)

        return parsed_results

    def _extract_location(self, locations_array: List[dict], project_root: str) -> Optional[Dict]:
        """从 locations 数组中提取物理位置信息"""
        if not locations_array:
            return None
            
        location_obj = locations_array[0].get("physicalLocation")
        if not location_obj:
            return None
            
        artifact_location = location_obj.get("artifactLocation", {})
        uri = artifact_location.get("uri", "")
        # 处理 uri 可能包含不必要的 file:// 前缀
        if uri.startswith("file://"):
            uri = uri[7:]
            
        # 尝试组装绝度路径
        file_path = uri
        if project_root and not os.path.isabs(file_path):
             # 确保 uri 开头没有多余的斜杠，防止 os.path.join 将其视为绝对路径而忽略 project_root
             safe_uri = uri.lstrip('/').lstrip('\\')
             file_path = os.path.join(project_root, safe_uri)
             
        region = location_obj.get("region", {})
        start_line = region.get("startLine", 0)
        
        return {
            "file": file_path,
            "line": start_line
        }

    def _extract_data_flow(self, thread_flow_locations: List[dict], project_root: str) -> List[Dict]:
        """
        提取数据流路径，附带上下文代码。
        """
        flow_steps = []
        for index, tfl in enumerate(thread_flow_locations):
            location_data = self._extract_location([tfl.get("location", {})], project_root)
            if not location_data:
                continue
                
            file_path = location_data["file"]
            line_num = location_data["line"]
            
            # 默认情况下，只有第一步(Source)和最后一步(Sink)的中间过程可能不需要 Focus Here 标记
            # 但在这个提取阶段，我们先统一不加 Focus，最后一步在主循环中再加
            # 除了 Source 我们也给个标记说明
            is_source = (index == 0)
            
            code_snippet = self._get_code_snippet(file_path, line_num, focus=False)
            
            if is_source and code_snippet:
                # 给第一步加一个源标记，这对 LLM 也有好处，但不强制要求
                code_snippet = code_snippet.replace(f"/* Line {line_num} */", f"/* Line {line_num} */ /* <-- Source */", 1)

            step_info = {
                "step": index + 1,
                "file": file_path,
                "line": line_num,
                "code": code_snippet,
                "focus": False # 默认 false，主函数将最后一步强制设为 True
            }
            flow_steps.append(step_info)
            
        return flow_steps

    def _get_code_snippet(self, file_path: str, target_line: int, focus: bool = False) -> str:
        """
        根据文件路径和目标行号，提取上下 5 行代码。
        如果 focus 为 True，则在目标行后追加 "<-- Focus Here" 标记。
        """
        if not file_path or target_line <= 0:
            return "/* Code not available (Invalid path or line) */"

        try:
            if not os.path.exists(file_path):
                return f"/* File not found: {file_path} */"
                
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
                
            total_lines = len(lines)
            if target_line > total_lines:
                return f"/* Target line {target_line} exceeds file length {total_lines} */"

            start_idx = max(0, target_line - 1 - self.context_lines)
            end_idx = min(total_lines, target_line + self.context_lines)

            snippet_lines = []
            for i in range(start_idx, end_idx):
                current_line_num = i + 1
                line_content = lines[i].rstrip('\n')
                
                # 构建行前缀，如 "  13 |"
                prefix = f"{current_line_num:4d} | "
                
                if current_line_num == target_line:
                    marker = " <-- Focus Here" if focus else ""
                    snippet_lines.append(f"{prefix}{line_content}{marker}")
                else:
                    snippet_lines.append(f"{prefix}{line_content}")

            return "\n".join(snippet_lines)

        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return f"/* Error reading file: {str(e)} */"

if __name__ == "__main__":
    # 本地跑测试用
    logging.basicConfig(level=logging.INFO)
    parser = SarifParser(context_lines=5)
    
    # 用法示例：
    # results = parser.parse_file("output/CWE-089.sarif", project_root="/path/to/source")
    # print(json.dumps(results, indent=2, ensure_ascii=False))

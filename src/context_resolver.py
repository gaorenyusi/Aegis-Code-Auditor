import os
import re
import logging
from typing import Optional, List, Set

logger = logging.getLogger(__name__)

class ContextResolver:
    """
    负责在上下文不足 (NEED_MORE_CONTEXT) 时，跨文件或当前文件搜索并补全函数定义。
    提取出的函数完整实现将作为 ADDITIONAL CONTEXT 追加到下一轮。
    """
    def __init__(self, project_root: str):
        self.project_root = project_root
        
        # 为了避免文件 I/O 爆炸，我们限制最大搜索的文件大小及类型
        # 这里默认只搜索一些常见后端开发语言源码
        self.allowed_extensions = {".java", ".cpp", ".c", ".h", ".cs", ".go", ".php", ".py", ".js", ".ts", ".xml", ".kt"}

    def extract_function_names(self, thinking_text: str) -> List[str]:
        """
        从 LLM 返回的结构化 XML 标签或自然语言中精准提取需要补充的函数实体名。
        支持智能容错，修复大模型可能的标签闭合截断等错误。
        """
        matches = []
        # 第一优先级：捕捉大模型按规则吐出的 <MISSING_FUNCTION> 标签，支持类名前缀匹配
        # 兼容 <MISSING_FUNCTION> 以及乱盖的 </MISSING_FUNCTION>xxx</MISSING_FUNCTION> 头
        tag_pattern = r"</?MISSING_FUNCTION>\s*([a-zA-Z0-9_\.]+)\s*</?MISSING_FUNCTION>?"
        matches.extend(re.findall(tag_pattern, thinking_text, re.IGNORECASE))
        
        # 第二优先级 (降级容错)：大模型忘写闭合标签如 <MISSING_FUNCTION>buyOrSaleNumber
        if not matches:
             alt_pattern = r"<MISSING_FUNCTION>\s*([a-zA-Z0-9_\.]+)"
             matches.extend(re.findall(alt_pattern, thinking_text, re.IGNORECASE))
             
        if matches:
            return list(set(matches))
            
        # 第三优先级：如果大模型连标签都忘了，在自然语境里找
        fallback_pattern = r"([a-zA-Z_][\w\.]*)\s*(?:\(\))?(?:的实现|方法|函数)"
        fallback_matches = re.findall(fallback_pattern, thinking_text)
        if fallback_matches:
            cleaned = []
            for m in fallback_matches:
                func_only = m.split('.')[-1]
                if func_only and func_only not in ["的实现", "方法", "函数"]:
                    cleaned.append(func_only)
            if cleaned:
                return list(set(cleaned))

        return []

    def resolve_function(self, function_name: str, current_file: Optional[str] = None) -> str:
        """
        在全局项目中搜索指定函数的实现代码。支持搜索重名函数、接口与 XML 实现在海量代码中的优先级锁定！
        """
        if not function_name:
            return "/* Error: Empty function name provided. */"

        # 解析 class_hint 和 真正的 function_name 以防止海量重名爆炸
        class_hint = ""
        actual_func_name = function_name
        if "." in function_name:
            parts = function_name.split(".")
            class_hint = parts[-2] # e.g., 'depotItemMapperEx.buyOrSaleNumber' -> 'depotItemMapperEx'
            actual_func_name = parts[-1]
            
        # 拦截机制：如果明显的指出是 Mapper 层的持久层调用，自动视为 Sink 取消递归查询
        if "mapper" in class_hint.lower() or "dao" in class_hint.lower():
            logger.info(f"Intercepted mapper method {actual_func_name}, treating directly as Sink.")
            return f"/* [SYSTEM INTERCEPT] '{function_name}' 疑似 Mapper/DAO 也就是持久层操作，无需继续深挖其 MyBatis XML 实现或其他实现。请将其视作数据库执行动作的最底层 Sink 点。若参数包含污点输入，这代表危险操作，请立刻判定为 TRUE POSITIVE。*/"

        found_snippets = []
        seen_contents = set()

        # 对于普通代码正则，必须严格是函数定义语法树！严禁误将嵌套或调用的语句抓出！
        # 特征：有修饰符 或 至少有返回类型，必须出现在前面，且用 ^[\t ]* 锚定行级别头部缩进
        # 这将完美规避像 `diEx.getMId()` 这种藏在语句中间的方法调用，从而100%防止拉错同名实现！
        pattern_str = rf"^[ \t]*(?:public|protected|private|static)?\s*(?:[\w\.<>\[\]\?]+\s+){re.escape(actual_func_name)}\s*\("
        code_regex = re.compile(pattern_str, re.MULTILINE)
        
        # 对于 MyBatis 等 XML MyBatis Mapper 语句正则
        xml_pattern_str = rf"<(select|update|delete|insert|sql)[^>]*id\s*=\s*['\"]{re.escape(actual_func_name)}['\"][^>]*>.*?</\1>"
        xml_regex = re.compile(xml_pattern_str, re.DOTALL | re.IGNORECASE)

        def _search_and_collect(fpath: str):
            if not self._is_searchable_file(fpath): return
            _, ext = os.path.splitext(fpath)
            content = ""
            try:
                with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except Exception as e:
                logger.error(f"Error reading {fpath}: {e}")
                return

            if ext.lower() == '.xml':
                for match in xml_regex.finditer(content):
                    snippet = match.group(0)
                    if snippet not in seen_contents:
                        seen_contents.add(snippet)
                        found_snippets.append(f"// --- Function Definition found deeply in XML Mapper: {fpath} ---\n{snippet}")
            else:
                for match in code_regex.finditer(content):
                    start_idx = match.start()
                    snippet = self._extract_block(content, start_idx, fpath)
                    if snippet and snippet not in seen_contents:
                        seen_contents.add(snippet)
                        found_snippets.append(snippet)
                        
        # 策略 1: 优先搜索当前文件
        if current_file and os.path.exists(current_file):
            logger.debug(f"Attempting to resolve '{function_name}' in current file: {current_file}")
            _search_and_collect(current_file)

        # 策略 2: 全项目重名过滤与优先级下放
        all_files = []
        if self.project_root and os.path.exists(self.project_root):
            for root, dirs, files in os.walk(self.project_root):
                # 排除第三方库和编译产物
                dirs[:] = [d for d in dirs if d not in {".git", ".svn", "node_modules", "target", "bin", "build", "venv", ".idea"}]
                for file in files:
                    file_path = os.path.join(root, file)
                    if file_path != current_file:
                        all_files.append((file, file_path))
                        
        # 将名字长得像调用类的文件优先级暴力调到最前头！防止大海海底捞重件！
        if class_hint:
             clean_hint = class_hint.lower().replace("ex", "").replace("impl", "")
             all_files.sort(key=lambda x: clean_hint in x[0].lower(), reverse=True)
             
        for file, file_path in all_files:
            _search_and_collect(file_path)
            if len(found_snippets) > 2: # 超过2个就没必要继续搜了，直接放弃
                break
                
        if len(found_snippets) > 2:
            return f"/* Error: TOO_MANY_MATCHES_ABORT ({len(found_snippets)}). The function '{actual_func_name}' has > 2 implementations across the codebase. Abandoning deep search to prevent hallucination. */"

        if found_snippets:
            return "\n\n".join(found_snippets)

        return f"/* Error: Could not find any implementation for function '{function_name}' across the project. */"

    def _is_searchable_file(self, file_path: str) -> bool:
        """判断文件后缀是否在允许的搜索列表中"""
        _, ext = os.path.splitext(file_path)
        return ext.lower() in self.allowed_extensions

    def _extract_block(self, content: str, start_index: int, source_file: str) -> str:
        """
        从给定的代码首索引处开始，模拟栈匹配大括号 `{` 和 `}`，以提取出完整的函数代码块。
        支持类似 Java, C, JS 等带花括号的主流语言。
        """
        # 我们从 start_index 向下寻找第一个 '{'
        first_brace_idx = content.find('{', start_index)
        if first_brace_idx == -1:
            # 如果没有找到花括号，可能是一个接口定义或者单行声明，直接截取一行返回
            end_line_idx = content.find('\n', start_index)
            if end_line_idx == -1: return content[start_index:]
            return content[start_index:end_line_idx].strip()

        # 开始栈内大括号匹配
        brace_count = 0
        end_index = -1
        
        for i in range(first_brace_idx, len(content)):
            char = content[i]
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    end_index = i + 1
                    break
        
        if end_index == -1:
            # 文件结束也没有闭合，只能全部返回（通常是语法错误的代码）
            end_index = len(content)

        # 提取整块代码代码并按行号组合上下文
        # 为了美观，我们计算此时 start_index 前面部分到底包含几行，以加行号和出处
        pre_content = content[:start_index]
        start_line_num = pre_content.count('\n') + 1
        
        raw_code = content[start_index:end_index]
        lines = raw_code.split('\n')
        
        formatted_snippet = [f"// --- Function Definition found in {source_file} (Line {start_line_num}) ---"]
        for idx, line in enumerate(lines):
            formatted_snippet.append(f"{(start_line_num + idx):4d} | {line}")

        return "\n".join(formatted_snippet)


if __name__ == "__main__":
    # 本地跑测试用
    logging.basicConfig(level=logging.DEBUG)
    # 用你项目的实际根目录实例化
    resolver = ContextResolver(project_root=".")
    
    # 模拟从 LLM 思考中提取函数名
    thinking_str = "The data flows into sanitizeHtml() but I cannot see its implementation."
    funcs = resolver.extract_function_names(thinking_str)
    print("Extracted:", funcs)
    
    # 也可以直接调用去解析 (可以拿项目里某个存在的函数名来尝试)
    # if funcs:
    #     result = resolver.resolve_function("sanitizeHtml")
    #     print(result)

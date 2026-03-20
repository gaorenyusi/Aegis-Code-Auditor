import sys
import os

# 将项目根目录加入到系统路径，这样无需配置 PYTHONPATH，Pycharm 或直接 python src/main.py 均可运行
current_dir = os.path.dirname(os.path.abspath(__file__))
project_dir = os.path.dirname(current_dir)
if project_dir not in sys.path:
    sys.path.insert(0, project_dir)

import logging
from flask import Flask, render_template, request, jsonify

# 导入所有模块定义
from src.config import Config
from src.codeql_runner import CodeQLRunner
from src.sarif_parser import SarifParser
from src.context_builder import ContextBuilder
from src.llm_analyzer import LLMAnalyzer
from src.context_resolver import ContextResolver
from src.logger import AuditLogger
from src.report_generator import ReportGenerator
from src.langgraph_orchestrator import AuditGraphEngine

# 配置主程序日志
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder='../templates')

class CodeAuditOrchestrator:
    """递归分析控制主类，协调各个模块运转"""
    def __init__(self, project_root: str, db_path: str):
        self.project_root = os.path.abspath(project_root)
        self.db_path = os.path.abspath(db_path)
        
        # 加载配置
        self.rules_dir = Config.CODEQL_RULES_DIR
        self.ext_rules_dir = Config.CODEQL_EXT_RULES_DIR
        self.output_dir = Config.OUTPUT_DIR
        self.api_key = Config.LLM_API_KEY
        self.llm_model = Config.LLM_MODEL
        self.llm_api_url = Config.LLM_API_URL
        
        # 实例化工作流链
        self.runner = CodeQLRunner(rules_base_dir=self.rules_dir, ext_rules_base_dir=self.ext_rules_dir, output_dir=self.output_dir)
        self.parser = SarifParser(context_lines=10)
        self.context_builder = ContextBuilder()
        self.analyzer = LLMAnalyzer(api_key=self.api_key, model_name=self.llm_model, api_url=self.llm_api_url)
        self.resolver = ContextResolver(project_root=self.project_root)
        self.audit_logger = AuditLogger(logs_base_dir=Config.LOGS_DIR)
        self.report_gen = ReportGenerator(output_dir=self.output_dir)
        
        self.max_depth = Config.MAX_RECURSION_DEPTH
        
        # 实例化 LangGraph 编排引擎
        self.graph_engine = AuditGraphEngine(
            context_builder=self.context_builder,
            analyzer=self.analyzer,
            resolver=self.resolver,
            audit_logger=self.audit_logger,
            max_depth=self.max_depth,
            project_root=self.project_root
        )

    def _analyze_single_vulnerability(self, vul_data: dict, rule_id: str) -> dict:
        """解决单次漏洞判定流（已升级为 LangGraph 混合编排）"""
        import uuid
        vul_file_base = os.path.basename(vul_data.get("file", "unknown"))
        vul_id = f"{vul_file_base}_{vul_data.get('line', '0')}_{uuid.uuid4().hex[:6]}"

        logger.info(f"  [{vul_id}] - Invoking LangGraph Audit Engine...")
        return self.graph_engine.run(vul_data=vul_data, rule_id=rule_id, vul_id=vul_id)

    def deduplicate_vulnerabilities(self, vul_list: list, aggressive: bool = False) -> list:
        """按 Sink 分组，并在组内按执行路径特征签名选择性去重"""
        groups = {}
        # 1. 粗分组 (Group by Sink)
        for vul in vul_list:
            sink_key = f"{vul.get('file')}:{vul.get('line')}"
            if sink_key not in groups:
                groups[sink_key] = []
            groups[sink_key].append(vul)
            
        deduped_list = []
        
        # 2. 精细去重 (Selective Deduplication)
        for sink_key, group in groups.items():
            if aggressive:
                # 粗暴过滤：无视路径差异，只要终点重叠（同一个 Sink），全只抓第一条丢给 LLM。
                deduped_list.append(group[0])
                continue

            if len(group) == 1:
                deduped_list.append(group[0])
                continue
                
            seen_signatures = set()
            for vul in group:
                flow = vul.get("flow", [])
                if not flow:
                    deduped_list.append(vul)
                    continue
                    
                # 提取签名特征：不仅首尾相同，我们将整条数据流经过的不同代码行特征全部提取。
                # 如果同一个 Sink 原先是从 if 分支(安全)走，和从 else 分支(危险)走，
                # 它们的中间执行行号会发生差异，从而成功分离为两条独立的测试流，绝不会漏判危险分支！
                path_nodes = []
                for step in flow:
                    path_nodes.append(f"{step.get('file', 'unknown')}:{step.get('line', '0')}")
                
                sig = " -> ".join(path_nodes)
                
                if sig not in seen_signatures:
                    seen_signatures.add(sig)
                    deduped_list.append(vul)
                    
        return deduped_list

    def run_full_pipeline(self, cwe_list: list = None, enable_llm_if_excessive: bool = True, aggressive_dedup: bool = False, limit_top_10: bool = False) -> list:
        """执行完整流程"""
        logger.info("=========================================")
        logger.info(f"STARTING FULL AUDIT PIPELINE")
        logger.info(f"Project ROOT: {self.project_root}")
        logger.info(f"DB Path: {self.db_path}")
        logger.info(f"Selected Rules: {cwe_list if cwe_list else 'Default All'}")
        logger.info("=========================================\n")

        report_file_path = os.path.join(self.output_dir, "audit_report.md")
        if os.path.exists(report_file_path):
             open(report_file_path, "w").close()

        logger.info("[Step 1] Running CodeQL DB Analyzer...")
        sarif_files = self.runner.run_analysis(self.db_path, cwe_list=cwe_list)
        logger.info(f"CodeQL phase completed. {len(sarif_files)} SARIF files produced.")

        all_results = []

        for sarif_file in sarif_files:
            cwe_id = os.path.basename(sarif_file).split('.')[0]
            logger.info(f"\n[Step 2] Parsing file: {os.path.basename(sarif_file)} for rule {cwe_id}...")
            
            parsed_vul_data_list = self.parser.parse_file(sarif_file, project_root=self.project_root)
            
            if not parsed_vul_data_list:
                 logger.info(f"No valid findings in {cwe_id}. Moving to next rule.")
                 continue
                 
            logger.info(f"Extracted {len(parsed_vul_data_list)} raw vulnerabilities. Deduplicating by Sink and Path signature...")
            dedup_vul_list = self.deduplicate_vulnerabilities(parsed_vul_data_list, aggressive=aggressive_dedup)
            
            logger.info("*" * 60)
            logger.info(f"🛡️ 规则 [{cwe_id}] | 扫描与去重总结：")
            logger.info(f"   - CodeQL 原始暴扫漏洞流：{len(parsed_vul_data_list)} 个")
            logger.info(f"   - 经过策略精简后交由 LLM 分析基数：{len(dedup_vul_list)} 个 !")
            logger.info("*" * 60)
            
            if limit_top_10 and len(dedup_vul_list) > 10:
                logger.info(f"   - [启用强制截断模式] 规则 [{cwe_id}] 将被强行裁剪掉尾部 {len(dedup_vul_list) - 10} 个，仅保留前 10 个独立漏洞用于成本分析。")
                dedup_vul_list = dedup_vul_list[:10]
            
            # 判断拦截器：是否因为数量庞大而短路 LLM 的燃烧？
            if not enable_llm_if_excessive and len(dedup_vul_list) > 20:
                logger.warning(f"⚠️ 规则 [{cwe_id}] 去重后余量({len(dedup_vul_list)})超过预设 20 个警戒线！基于防爆刷配置，强制跳过大模型 API 调用环节！")
                for vul_data in dedup_vul_list:
                    vul_data["verdict"] = "SKIPPED_BY_LIMIT (触发屏蔽上限)"
                    vul_data["reason"] = "由于漏洞条目数过于庞大 (>20)，用户配置了不执行LLM成本消耗拦截网。已放弃执行分析工作流。"
                    vul_data["iterations"] = 0
                    vul_data["thinking"] = "已取消消耗 API 额度进行本条分支逻辑的审阅与判定工作。"
                    self.report_gen.generate_md_report(vul_data)
                    all_results.append(vul_data)
                continue

            for i, vul_data in enumerate(dedup_vul_list):
                 logger.info(f"-> Analyzing vulnerability {i+1}/{len(dedup_vul_list)} at {vul_data.get('file')}:{vul_data.get('line')}")
                 
                 ai_final_status = self._analyze_single_vulnerability(vul_data, rule_id=cwe_id)
                 
                 vul_data.update(ai_final_status)
                 self.report_gen.generate_md_report(vul_data)
                 all_results.append(vul_data)
                 
        logger.info("=========================================")
        logger.info(f"AUDIT PIPELINE COMPLETED")
        logger.info(f"Please check final generated report at: {report_file_path}")
        logger.info("=========================================\n")
        
        return all_results

# -------- Web API 和 启动入口 --------

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def trigger_scan():
    data = request.json
    db_path = data.get("db_path")
    cwe_list = data.get("cwe_list") # 容许前端传入选中的漏洞类型
    enable_llm_if_excessive = data.get("enable_llm_if_excessive", True)
    aggressive_dedup = data.get("aggressive_dedup", False)
    limit_top_10 = data.get("limit_top_10", False)
    
    if not db_path or not os.path.exists(db_path):
         return jsonify({"status": "error", "message": "无效的 CodeQL 数据库路径！未能定位该目录。"})
    
    project_root = db_path
    
    # 从 CodeQL database 原生配置中自动推导项目真正的源码绝对路径
    cq_yml_path = os.path.join(db_path, "codeql-database.yml")
    if os.path.exists(cq_yml_path):
        try:
            with open(cq_yml_path, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.startswith("sourceLocationPrefix:"):
                        # 截取、去除首尾空格以及可能存在的引号
                        prefix = line.split("sourceLocationPrefix:")[1].strip().strip('"').strip("'")
                        if os.path.exists(prefix):
                            project_root = prefix
                        break
        except Exception as e:
            logger.warning(f"Error reading codeql-database.yml: {e}")
            
    # 如果没推导出来，启用备用策略
    if project_root == db_path:
        db_src_path = os.path.join(db_path, "src")
        if os.path.exists(db_src_path) and os.path.isdir(db_src_path):
            project_root = db_src_path
        
    try:
        if not Config.LLM_API_KEY or Config.LLM_API_KEY in ["your-default-llm-api-key", "your_actual_api_key_here"]:
            logger.warning("[!] WARNING: LLM_API_KEY is not configured properly in .env! \n")
            
        logger.info("API trigger received. Initializing Orchestrator Engine.")
        orchestrator = CodeAuditOrchestrator(
            project_root=project_root,
            db_path=db_path
        )
        
        # 将前端传入的数组列表喂给流水线
        selected_cwes = cwe_list if isinstance(cwe_list, list) and len(cwe_list) > 0 else None
        results = orchestrator.run_full_pipeline(
            cwe_list=selected_cwes,
            enable_llm_if_excessive=enable_llm_if_excessive,
            aggressive_dedup=aggressive_dedup,
            limit_top_10=limit_top_10
        )
        
        return jsonify({"status": "success", "results": results})
        
    except Exception as e:
        logger.error(f"Error during scan: {str(e)}")
        return jsonify({"status": "error", "message": str(e)})

if __name__ == "__main__":
    logger.info("===================================================")
    logger.info("Web Dashboard Engine Started at http://127.0.0.1:5000")
    logger.info("===================================================")
    # 本地跑可不走生产服务器架构，直接启动 Flask App
    app.run(host="0.0.0.0", port=5000, debug=False)

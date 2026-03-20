import os
import subprocess
import logging
from typing import List, Optional

logger = logging.getLogger(__name__)

class CodeQLRunner:
    """
    CodeQL 执行模块
    负责运行 CodeQL 规则并生成 SARIF 结果文件。
    """
    
    DEFAULT_CWE_LIST = [
        "CWE-078",
        "CWE-079",
        "CWE-089",
        "CWE-094",
        "CWE-502",
        "CWE-611",
        "CWE-918"
    ]

    def __init__(
        self, 
        rules_base_dir: str = r"E:\Tools\CMSTools\CodeQL\ql\java\ql\src\Security\CWE",
        ext_rules_base_dir: str = r"E:\Tools\CMSTools\CodeQL\ql\java\ql\src\experimental\Security\CWE",
        output_dir: str = "./results",
        codeql_bin: str = "codeql"
    ):
        """
        初始化 CodeQL 运行器
        
        :param rules_base_dir: CodeQL QL查询规则的基础目录
        :param ext_rules_base_dir: CodeQL QL查询的扩展/实验性规则目录
        :param output_dir: SARIF 文件的输出目录
        :param codeql_bin: 系统调用 codeql 的命令
        """
        self.rules_base_dir = rules_base_dir
        self.ext_rules_base_dir = ext_rules_base_dir
        self.output_dir = os.path.abspath(output_dir)
        self.codeql_bin = codeql_bin
        
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def run_analysis(self, db_path: str, cwe_list: Optional[List[str]] = None) -> List[str]:
        """
        执行 CodeQL 扫描
        
        :param db_path: CodeQL 数据库绝对路径
        :param cwe_list: 需要扫描的 CWE 列表，若为 None 则扫描默认的全部 CWE
        :return: 生成的 SARIF 文件绝对路径列表
        """
        db_path_abs = os.path.abspath(db_path)
        if not os.path.exists(db_path_abs):
            logger.error(f"CodeQL database not found at: {db_path_abs}")
            raise FileNotFoundError(f"Database not found: {db_path_abs}")

        cwes_to_scan = cwe_list if cwe_list is not None else self.DEFAULT_CWE_LIST
        generated_sarif_files = []

        for cwe in cwes_to_scan:
            is_ext = cwe.endswith("-ext")
            base_cwe = cwe.replace("-ext", "") if is_ext else cwe
            
            # 根据是否是扩展规则，选择不同的目录
            if is_ext:
                query_path = os.path.join(self.ext_rules_base_dir, base_cwe)
            else:
                query_path = os.path.join(self.rules_base_dir, base_cwe)
            
            if not os.path.exists(query_path):
                logger.warning(f"Rule path does not exist for {cwe}: {query_path}, skipping...")
                continue

            output_file = os.path.join(self.output_dir, f"{cwe}.sarif")
            
            # codeql database analyze <db_path> <query_path> --format=sarif-latest --output=<output>
            command = [
                self.codeql_bin,
                "database",
                "analyze",
                db_path_abs,
                query_path,
                "--format=sarif-latest",
                f"--output={output_file}"
            ]
            
            logger.info(f"Starting CodeQL analysis for {cwe}...")
            
            try:
                process = subprocess.run(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False
                )
                
                if process.returncode == 0:
                    logger.info(f"Successfully generated SARIF for {cwe}")
                    generated_sarif_files.append(output_file)
                else:
                    logger.error(f"Failed to analyze {cwe}. Return code: {process.returncode}")
                    logger.error(f"Error output:\n{process.stderr.strip()}")
                    
            except Exception as e:
                logger.error(f"Exception occurred while running CodeQL for {cwe}: {str(e)}")

        return generated_sarif_files

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    runner = CodeQLRunner()
    # runner.run_analysis("path/to/db")

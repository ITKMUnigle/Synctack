import configparser
import argparse
import os

class ConfigManager:
    def __init__(self):
        self.config = {
            "source_dir": None,
            "target_dir": None,
            "interval": 5,
            "mode": "sync",
            "log_file": "folder_monitor.log",
            "log_level": "INFO",
            "thread_count": 0,  # 0表示自动计算
            "max_threads": 32,  # 最大线程数
            "progress_update_interval": 10,  # 进度更新间隔（MB）
            "filter_suffixes": [],  # 需要过滤的文件后缀列表
            
            # 跨系统同步配置
            "enable_network_sync": False,  # 是否启用跨系统同步
            "sync_mode": "client",  # 同步模式：client（客户端）或 server（服务器）
            "sync_host": "127.0.0.1",  # 同步服务器地址
            "sync_port": 8080,  # 同步服务器端口
            "ssl_enabled": False,  # 是否启用SSL加密
            "cert_file": "",  # 证书文件路径
            "key_file": "",  # 私钥文件路径
            "ca_cert": "",  # CA证书文件路径
            "conflict_resolution": "newest",  # 冲突解决策略：newest（最新优先）、largest（最大优先）、manual（手动）
            "chunk_size": 4096,  # 文件分块大小（字节）
            "resume_enabled": True  # 是否启用断点续传
        }
        self.parser = argparse.ArgumentParser(description="文件夹内容监视程序")
        self._setup_argparse()
    
    def _setup_argparse(self):
        """设置命令行参数解析"""
        self.parser.add_argument("-c", "--config", help="配置文件路径")
        self.parser.add_argument("-s", "--source", help="源文件夹路径")
        self.parser.add_argument("-t", "--target", help="目标文件夹路径")
        self.parser.add_argument("-i", "--interval", type=int, help="扫描间隔（秒）")
        self.parser.add_argument("-m", "--mode", choices=["sync", "move"], help="操作模式")
        self.parser.add_argument("--log-file", help="日志文件路径")
        self.parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="日志级别")
        self.parser.add_argument("--thread-count", type=int, help="线程数量，0表示自动计算")
        self.parser.add_argument("--max-threads", type=int, help="最大线程数")
        self.parser.add_argument("--progress-update-interval", type=int, help="进度更新间隔（MB）")
        self.parser.add_argument("--filter-suffixes", help="需要过滤的文件后缀，以逗号分隔，如：.txt,.jpg,.png")
        
        # 跨系统同步相关参数
        self.parser.add_argument("--enable-network-sync", action="store_true", help="启用跨系统同步")
        self.parser.add_argument("--sync-mode", choices=["client", "server"], help="同步模式：client（客户端）或 server（服务器）")
        self.parser.add_argument("--sync-host", help="同步服务器地址")
        self.parser.add_argument("--sync-port", type=int, help="同步服务器端口")
        self.parser.add_argument("--ssl-enabled", action="store_true", help="启用SSL加密")
        self.parser.add_argument("--cert-file", help="证书文件路径")
        self.parser.add_argument("--key-file", help="私钥文件路径")
        self.parser.add_argument("--ca-cert", help="CA证书文件路径")
        self.parser.add_argument("--conflict-resolution", choices=["newest", "largest", "manual"], help="冲突解决策略")
        self.parser.add_argument("--chunk-size", type=int, help="文件分块大小（字节）")
        self.parser.add_argument("--resume-enabled", action="store_true", help="启用断点续传")
    
    def load_config(self, config_file: str = None) -> dict:
        """加载配置
        
        Args:
            config_file: 配置文件路径
            
        Returns:
            dict: 配置字典
        """
        # 解析命令行参数
        args = self.parser.parse_args()
        
        # 如果命令行提供了配置文件路径，则使用它
        if args.config:
            config_file = args.config
        # 否则，默认使用当前目录下的config.ini文件
        elif not config_file:
            config_file = "config.ini"
        
        # 加载配置文件
        if os.path.exists(config_file):
            cp = configparser.ConfigParser()
            cp.read(config_file, encoding="utf-8")
            
            if "monitor" in cp:
                monitor_section = cp["monitor"]
                if "source_dir" in monitor_section:
                    self.config["source_dir"] = monitor_section["source_dir"]
                if "target_dir" in monitor_section:
                    self.config["target_dir"] = monitor_section["target_dir"]
                if "interval" in monitor_section:
                    self.config["interval"] = int(monitor_section["interval"])
                if "mode" in monitor_section:
                    self.config["mode"] = monitor_section["mode"]
                if "log_file" in monitor_section:
                    self.config["log_file"] = monitor_section["log_file"]
                if "log_level" in monitor_section:
                    self.config["log_level"] = monitor_section["log_level"]
                if "thread_count" in monitor_section:
                    self.config["thread_count"] = int(monitor_section["thread_count"])
                if "max_threads" in monitor_section:
                    self.config["max_threads"] = int(monitor_section["max_threads"])
                if "progress_update_interval" in monitor_section:
                    self.config["progress_update_interval"] = int(monitor_section["progress_update_interval"])
                if "filter_suffixes" in monitor_section:
                    filter_suffixes_str = monitor_section["filter_suffixes"].strip()
                    if filter_suffixes_str:
                        # 解析逗号分隔的后缀列表，去除空格和空字符串
                        self.config["filter_suffixes"] = [
                            suffix.strip() for suffix in filter_suffixes_str.split(",") if suffix.strip()
                        ]
                    else:
                        self.config["filter_suffixes"] = []
                
        
        # 读取[server]部分的跨系统同步配置
        if "server" in cp:
            server_section = cp["server"]
            if "enable_network_sync" in server_section:
                self.config["enable_network_sync"] = server_section["enable_network_sync"].lower() in ["true", "yes", "1"]
            if "sync_mode" in server_section:
                self.config["sync_mode"] = server_section["sync_mode"]
            if "sync_host" in server_section:
                self.config["sync_host"] = server_section["sync_host"]
            if "sync_port" in server_section:
                self.config["sync_port"] = int(server_section["sync_port"])
            if "ssl_enabled" in server_section:
                self.config["ssl_enabled"] = server_section["ssl_enabled"].lower() in ["true", "yes", "1"]
            if "cert_file" in server_section:
                self.config["cert_file"] = server_section["cert_file"]
            if "key_file" in server_section:
                self.config["key_file"] = server_section["key_file"]
            if "ca_cert" in server_section:
                self.config["ca_cert"] = server_section["ca_cert"]
            if "conflict_resolution" in server_section:
                self.config["conflict_resolution"] = server_section["conflict_resolution"]
            if "chunk_size" in server_section:
                self.config["chunk_size"] = int(server_section["chunk_size"])
            if "resume_enabled" in server_section:
                self.config["resume_enabled"] = server_section["resume_enabled"].lower() in ["true", "yes", "1"]
        
        # 保持向后兼容性：如果server部分不存在，尝试从monitor部分读取
        elif "monitor" in cp:
            monitor_section = cp["monitor"]
            if "enable_network_sync" in monitor_section:
                self.config["enable_network_sync"] = monitor_section["enable_network_sync"].lower() in ["true", "yes", "1"]
            if "sync_mode" in monitor_section:
                self.config["sync_mode"] = monitor_section["sync_mode"]
            if "sync_host" in monitor_section:
                self.config["sync_host"] = monitor_section["sync_host"]
            if "sync_port" in monitor_section:
                self.config["sync_port"] = int(monitor_section["sync_port"])
            if "ssl_enabled" in monitor_section:
                self.config["ssl_enabled"] = monitor_section["ssl_enabled"].lower() in ["true", "yes", "1"]
            if "cert_file" in monitor_section:
                self.config["cert_file"] = monitor_section["cert_file"]
            if "key_file" in monitor_section:
                self.config["key_file"] = monitor_section["key_file"]
            if "ca_cert" in monitor_section:
                self.config["ca_cert"] = monitor_section["ca_cert"]
            if "conflict_resolution" in monitor_section:
                self.config["conflict_resolution"] = monitor_section["conflict_resolution"]
            if "chunk_size" in monitor_section:
                self.config["chunk_size"] = int(monitor_section["chunk_size"])
            if "resume_enabled" in monitor_section:
                self.config["resume_enabled"] = monitor_section["resume_enabled"].lower() in ["true", "yes", "1"]
        
        # 命令行参数覆盖配置文件
        if args.source:
            self.config["source_dir"] = args.source
        if args.target:
            self.config["target_dir"] = args.target
        if args.interval is not None:
            self.config["interval"] = args.interval
        if args.mode:
            self.config["mode"] = args.mode
        if args.log_file:
            self.config["log_file"] = args.log_file
        if args.log_level:
            self.config["log_level"] = args.log_level
        if args.thread_count is not None:
            self.config["thread_count"] = args.thread_count
        if args.max_threads is not None:
            self.config["max_threads"] = args.max_threads
        if args.progress_update_interval is not None:
            self.config["progress_update_interval"] = args.progress_update_interval
        if args.filter_suffixes is not None:
            if args.filter_suffixes.strip():
                # 解析逗号分隔的后缀列表，去除空格和空字符串
                self.config["filter_suffixes"] = [
                    suffix.strip() for suffix in args.filter_suffixes.split(",") if suffix.strip()
                ]
            else:
                self.config["filter_suffixes"] = []
        
        # 跨系统同步配置
        if args.enable_network_sync:
            self.config["enable_network_sync"] = True
        if args.sync_mode:
            self.config["sync_mode"] = args.sync_mode
        if args.sync_host:
            self.config["sync_host"] = args.sync_host
        if args.sync_port is not None:
            self.config["sync_port"] = args.sync_port
        if args.ssl_enabled:
            self.config["ssl_enabled"] = True
        if args.cert_file:
            self.config["cert_file"] = args.cert_file
        if args.key_file:
            self.config["key_file"] = args.key_file
        if args.ca_cert:
            self.config["ca_cert"] = args.ca_cert
        if args.conflict_resolution:
            self.config["conflict_resolution"] = args.conflict_resolution
        if args.chunk_size is not None:
            self.config["chunk_size"] = args.chunk_size
        if args.resume_enabled:
            self.config["resume_enabled"] = True
        
        # 验证和修正配置
        self._validate_config()
        
        return self.config
    
    def _validate_config(self):
        """验证和修正配置"""
        # 确保源文件夹和目标文件夹路径存在
        if self.config["source_dir"] and not os.path.exists(self.config["source_dir"]):
            raise ValueError(f"源文件夹不存在: {self.config['source_dir']}")
        
        if self.config["target_dir"] and not os.path.exists(self.config["target_dir"]):
            # 目标文件夹不存在则创建
            os.makedirs(self.config["target_dir"], exist_ok=True)
        
        # 确保扫描间隔不小于1秒
        if self.config["interval"] < 1:
            self.config["interval"] = 1
        
        # 确保模式合法
        if self.config["mode"] not in ["sync", "move"]:
            self.config["mode"] = "sync"
        
        # 确保日志级别合法
        if self.config["log_level"] not in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            self.config["log_level"] = "INFO"
        
        # 确保线程相关配置合法
        if self.config["thread_count"] < 0:
            self.config["thread_count"] = 0
        if self.config["max_threads"] < 1:
            self.config["max_threads"] = 32
        if self.config["progress_update_interval"] < 1:
            self.config["progress_update_interval"] = 10
        
        # 确保跨系统同步配置合法
        if self.config["sync_mode"] not in ["client", "server"]:
            self.config["sync_mode"] = "client"
        
        if self.config["sync_port"] < 1 or self.config["sync_port"] > 65535:
            self.config["sync_port"] = 8080
        
        if self.config["conflict_resolution"] not in ["newest", "largest", "manual"]:
            self.config["conflict_resolution"] = "newest"
        
        if self.config["chunk_size"] < 1024 or self.config["chunk_size"] > 1048576:
            self.config["chunk_size"] = 4096
        
        # 如果启用了SSL，确保证书文件存在（服务器模式）
        if self.config["ssl_enabled"] and self.config["sync_mode"] == "server":
            if self.config["cert_file"] and not os.path.exists(self.config["cert_file"]):
                self.logger.warning(f"证书文件不存在: {self.config['cert_file']}, 将禁用SSL")
                self.config["ssl_enabled"] = False
            if self.config["key_file"] and not os.path.exists(self.config["key_file"]):
                self.logger.warning(f"私钥文件不存在: {self.config['key_file']}, 将禁用SSL")
                self.config["ssl_enabled"] = False
        
        # 如果是客户端模式且启用了SSL，确保CA证书存在
        if self.config["ssl_enabled"] and self.config["sync_mode"] == "client":
            if self.config["ca_cert"] and not os.path.exists(self.config["ca_cert"]):
                self.logger.warning(f"CA证书文件不存在: {self.config['ca_cert']}, 将禁用SSL")
                self.config["ssl_enabled"] = False
    
    def get_config(self) -> dict:
        """获取配置
        
        Returns:
            dict: 配置字典
        """
        return self.config

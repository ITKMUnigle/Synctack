import logging
import os

class Logger:
    def __init__(self, log_file: str = "folder_monitor.log", log_level: str = "INFO"):
        self.logger = logging.getLogger("FolderMonitor")
        self.logger.setLevel(getattr(logging, log_level.upper()))
        
        # 检查日志文件夹是否存在，不存在则创建
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # 移除已存在的处理器，避免重复日志
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
            handler.close()
        
        # 创建控制台处理器
        console_handler = logging.StreamHandler()
        console_handler.setLevel(getattr(logging, log_level.upper()))
        
        # 创建文件处理器
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(getattr(logging, log_level.upper()))
        
        # 创建更详细的日志格式，包括线程ID、文件名和行号
        detailed_formatter = logging.Formatter('%(asctime)s - %(levelname)s - [Thread:%(thread)d] - %(filename)s:%(lineno)d - %(message)s')
        console_handler.setFormatter(detailed_formatter)
        file_handler.setFormatter(detailed_formatter)
        
        # 添加处理器到日志记录器
        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)
    
    def debug(self, message: str):
        self.logger.debug(message)
    
    def info(self, message: str):
        self.logger.info(message)
    
    def warning(self, message: str):
        self.logger.warning(message)
    
    def error(self, message: str):
        self.logger.error(message)
    
    def critical(self, message: str):
        self.logger.critical(message)

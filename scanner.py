import os
import stat
import time

class Scanner:
    def __init__(self, source_dir: str, logger, filter_suffixes: list = None):
        """初始化扫描器
        
        Args:
            source_dir: 源文件夹路径
            logger: 日志管理器实例
            filter_suffixes: 需要过滤的文件后缀列表，如 [".txt", ".jpg"]
        """
        self.source_dir = source_dir
        self.logger = logger
        self.filter_suffixes = filter_suffixes or []
        
        # 确保所有后缀都以点开头
        self.filter_suffixes = [
            suffix if suffix.startswith('.') else f'.{suffix}'
            for suffix in self.filter_suffixes
        ]
        
        self.logger.info(f"文件后缀过滤配置: {self.filter_suffixes}")
    
    def scan(self) -> dict:
        """执行扫描
        
        Returns:
            dict: 扫描结果，包含文件/文件夹的元数据
        """
        self.logger.info(f"开始扫描文件夹: {self.source_dir}")
        scan_result = {}
        
        try:
            # 使用os.walk递归扫描文件夹
            for root, dirs, files in os.walk(self.source_dir):
                # 处理文件夹
                for dir_name in dirs:
                    dir_path = os.path.join(root, dir_name)
                    try:
                        stat_info = os.stat(dir_path)
                        scan_result[dir_path] = {
                            "type": "folder",
                            "create_time": stat_info.st_ctime,
                            "modify_time": stat_info.st_mtime,
                            "size": 0
                        }
                    except Exception as e:
                        self.logger.error(f"无法获取文件夹信息: {dir_path}, 错误: {e}")
                
                # 处理文件
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    
                    # 检查文件后缀是否需要过滤
                    if self.filter_suffixes:
                        _, file_extension = os.path.splitext(file_name)
                        if file_extension.lower() in self.filter_suffixes:
                            self.logger.debug(f"跳过过滤的文件: {file_path}, 后缀: {file_extension}")
                            continue
                    
                    try:
                        stat_info = os.stat(file_path)
                        scan_result[file_path] = {
                            "type": "file",
                            "create_time": stat_info.st_ctime,
                            "modify_time": stat_info.st_mtime,
                            "size": stat_info.st_size
                        }
                    except Exception as e:
                        self.logger.error(f"无法获取文件信息: {file_path}, 错误: {e}")
        except Exception as e:
            self.logger.error(f"扫描文件夹时发生错误: {self.source_dir}, 错误: {e}")
        
        self.logger.info(f"扫描完成，共发现 {len(scan_result)} 个项目")
        return scan_result
    
    def detect_new_items(self, previous_scan: dict, current_scan: dict) -> list:
        """检测新增项目
        
        Args:
            previous_scan: 上一次扫描结果
            current_scan: 当前扫描结果
            
        Returns:
            list: 新增项目列表
        """
        new_items = []
        
        # 遍历当前扫描结果，找出上一次扫描中没有的项目
        for item_path, item_info in current_scan.items():
            if item_path not in previous_scan:
                new_items.append({
                    "path": item_path,
                    "type": item_info["type"],
                    "create_time": item_info["create_time"],
                    "modify_time": item_info["modify_time"],
                    "size": item_info["size"]
                })
        
        self.logger.info(f"检测到 {len(new_items)} 个新增项目")
        return new_items
    
    def detect_changed_items(self, current_scan: dict, target_dir: str) -> list:
        """检测变更项目
        
        Args:
            current_scan: 当前扫描结果
            target_dir: 目标文件夹路径
            
        Returns:
            list: 变更项目列表
        """
        changed_items = []
        
        # 遍历当前扫描结果，检查每个文件是否需要更新到目标文件夹
        for item_path, current_item in current_scan.items():
            if current_item["type"] == "file":
                # 计算目标文件路径
                rel_path = os.path.relpath(item_path, self.source_dir)
                target_path = os.path.join(target_dir, rel_path)
                
                # 检查目标文件是否存在
                if os.path.exists(target_path):
                    # 获取目标文件的元数据
                    try:
                        target_stat = os.stat(target_path)
                        target_modify_time = target_stat.st_mtime
                        target_size = target_stat.st_size
                        
                        # 检查变更条件：修改时间晚于目标文件或大小大于目标文件
                        if (current_item["modify_time"] > target_modify_time or 
                            current_item["size"] > target_size):
                            changed_items.append({
                                "path": item_path,
                                "type": current_item["type"],
                                "create_time": current_item["create_time"],
                                "modify_time": current_item["modify_time"],
                                "size": current_item["size"]
                            })
                    except Exception as e:
                        self.logger.error(f"无法获取目标文件信息: {target_path}, 错误: {e}")
        
        self.logger.info(f"检测到 {len(changed_items)} 个变更项目")
        return changed_items
    
    def detect_bidirectional_changes(self, local_scan: dict, remote_scan: dict, local_dir: str, remote_dir: str) -> tuple:
        """检测双向文件变化
        
        Args:
            local_scan: 本地扫描结果
            remote_scan: 远程扫描结果
            local_dir: 本地文件夹路径
            remote_dir: 远程文件夹路径
            
        Returns:
            tuple: (本地新增文件列表, 本地修改文件列表, 本地删除文件列表, 远程新增文件列表, 远程修改文件列表, 远程删除文件列表)
        """
        # 转换为相对路径映射，方便比较
        local_rel_map = {}
        remote_rel_map = {}
        
        # 构建本地相对路径映射
        for item_path, item_info in local_scan.items():
            if item_info["type"] == "file":
                rel_path = os.path.relpath(item_path, local_dir)
                local_rel_map[rel_path] = {
                    "full_path": item_path,
                    **item_info
                }
        
        # 构建远程相对路径映射
        for item_path, item_info in remote_scan.items():
            if item_info["type"] == "file":
                rel_path = os.path.relpath(item_path, remote_dir)
                remote_rel_map[rel_path] = {
                    "full_path": item_path,
                    **item_info
                }
        
        # 检测本地新增文件：本地有，远程没有
        local_new_files = []
        # 检测本地修改文件：本地和远程都有，但本地更新
        local_modified_files = []
        # 检测本地删除文件：本地没有，远程有
        local_deleted_files = []
        # 检测远程新增文件：远程有，本地没有
        remote_new_files = []
        # 检测远程修改文件：本地和远程都有，但远程更新
        remote_modified_files = []
        # 检测远程删除文件：远程没有，本地有
        remote_deleted_files = []
        
        # 遍历本地文件，比较远程文件
        for rel_path, local_item in local_rel_map.items():
            if rel_path not in remote_rel_map:
                # 本地新增文件
                local_new_files.append(local_item)
            else:
                # 比较文件是否修改
                remote_item = remote_rel_map[rel_path]
                if (local_item["modify_time"] > remote_item["modify_time"] or 
                    local_item["size"] != remote_item["size"]):
                    # 本地文件比远程新，需要同步到远程
                    local_modified_files.append(local_item)
        
        # 遍历远程文件，比较本地文件
        for rel_path, remote_item in remote_rel_map.items():
            if rel_path not in local_rel_map:
                # 远程新增文件，需要同步到本地
                remote_new_files.append(remote_item)
            else:
                # 比较文件是否修改
                local_item = local_rel_map[rel_path]
                if (remote_item["modify_time"] > local_item["modify_time"] or 
                    remote_item["size"] != local_item["size"]):
                    # 远程文件比本地新，需要同步到本地
                    remote_modified_files.append(remote_item)
        
        # 检测本地删除文件：远程有，本地没有
        local_deleted_files = [remote_item for rel_path, remote_item in remote_rel_map.items() 
                              if rel_path not in local_rel_map]
        
        # 检测远程删除文件：本地有，远程没有
        remote_deleted_files = [local_item for rel_path, local_item in local_rel_map.items() 
                              if rel_path not in remote_rel_map]
        
        self.logger.info(f"双向变化检测结果: 本地新增={len(local_new_files)}, 本地修改={len(local_modified_files)}, 本地删除={len(local_deleted_files)}, 远程新增={len(remote_new_files)}, 远程修改={len(remote_modified_files)}, 远程删除={len(remote_deleted_files)}")
        
        return (local_new_files, local_modified_files, local_deleted_files,
                remote_new_files, remote_modified_files, remote_deleted_files)

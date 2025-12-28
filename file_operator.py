import os
import shutil
import hashlib
import time
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import psutil
import math

class Operator:
    def __init__(self, source_dir: str, target_dir: str, mode: str, logger, thread_count: int = 0, max_threads: int = 32, progress_update_interval: int = 10):
        """初始化操作器
        
        Args:
            source_dir: 源文件夹路径
            target_dir: 目标文件夹路径
            mode: 操作模式（sync/move）
            logger: 日志管理器实例
            thread_count: 线程数量，0表示自动计算
            max_threads: 最大线程数
            progress_update_interval: 进度更新间隔（MB）
        """
        self.source_dir = source_dir
        self.target_dir = target_dir
        self.mode = mode
        self.logger = logger
        self.block_size = 1024 * 1024  # 1MB块大小
        
        # 进度跟踪
        self.total_files = 0
        self.completed_files = 0
        self.total_size = 0
        self.transferred_size = 0
        self.start_time = 0
        
        # 线程安全控制
        self.lock = threading.Lock()
        
        # 多线程配置
        self.thread_count_config = thread_count
        self.max_threads = max_threads
        self.progress_update_interval = progress_update_interval * 1024 * 1024  # 转换为字节
        
        # 动态线程数量：根据CPU核心数和可用内存调整
        self._set_optimal_thread_count()
        
        # 线程池
        self.executor = None
        
        # 操作类型映射
        self.operation_map = {
            "sync": self.sync_item,
            "move": self.move_item
        }
    
    def _set_optimal_thread_count(self):
        """根据系统资源设置最佳线程数量"""
        # 如果配置了具体的线程数量，直接使用
        if self.thread_count_config > 0:
            self.thread_count = min(self.thread_count_config, self.max_threads)
            self.logger.info(f"使用配置的线程数: {self.thread_count}")
            return
        
        try:
            # 获取CPU核心数
            cpu_count = psutil.cpu_count() or 4
            
            # 获取可用内存（GB）
            available_memory = psutil.virtual_memory().available / (1024 ** 3)
            
            # 基于CPU核心数和可用内存计算最佳线程数
            # 公式：线程数 = CPU核心数 + (可用内存GB数 * 0.5)
            thread_count = min(max(1, cpu_count + math.floor(available_memory * 0.5)), self.max_threads)
            
            self.logger.info(f"系统CPU核心数: {cpu_count}, 可用内存: {available_memory:.2f}GB, 最大线程数限制: {self.max_threads}, 设置线程数: {thread_count}")
            self.thread_count = thread_count
        except Exception as e:
            self.logger.warning(f"无法获取系统资源信息，使用默认线程数: 4, 错误: {e}")
            self.thread_count = min(4, self.max_threads)
    
    def execute(self, new_items: list) -> None:
        """执行操作
        
        Args:
            new_items: 新增项目列表
        """
        self.logger.info(f"开始执行{self.mode}操作，共{len(new_items)}个项目")
        
        # 初始化进度跟踪
        self._init_progress(new_items)
        
        # 筛选出文件项目，文件夹单独处理
        file_items = []
        folder_items = []
        for item in new_items:
            if item["type"] == "file":
                file_items.append(item)
            else:
                folder_items.append(item)
        
        # 先处理文件夹（顺序执行，因为文件夹创建有依赖关系）
        for item in folder_items:
            item_path = item["path"]
            item_type = item["type"]
            try:
                if self.mode == "sync":
                    self.sync_item(item_path, item_type)
                else:  # move
                    self.move_item(item_path, item_type)
                self.completed_files += 1
            except Exception as e:
                self.logger.error(f"处理文件夹时发生错误: {item_path}, 错误: {e}")
        
        # 处理文件（并行执行）
        if file_items:
            self.logger.info(f"开始并行处理{len(file_items)}个文件，使用{self.thread_count}个线程")
            
            # 创建总进度条
            with tqdm(total=len(file_items), desc=f"{self.mode}操作进度", unit="项", dynamic_ncols=True) as overall_pbar:
                # 保存进度条引用
                self.overall_pbar = overall_pbar
                
                # 创建线程池
                with ThreadPoolExecutor(max_workers=self.thread_count) as executor:
                    self.executor = executor
                    
                    # 提交所有文件操作任务
                    future_to_item = {
                        executor.submit(
                            self._process_item,
                            item["path"],
                            item["type"]
                        ): item for item in file_items
                    }
                    
                    # 处理完成的任务
                    for future in as_completed(future_to_item):
                        item = future_to_item[future]
                        try:
                            future.result()  # 获取任务结果，触发异常
                        except Exception as e:
                            self.logger.error(f"处理文件时发生错误: {item['path']}, 错误: {e}")
                        finally:
                            # 更新总进度条
                            with self.lock:
                                self.completed_files += 1
                            overall_pbar.update(1)
                            self._show_progress_status()
        
        self.logger.info(f"{self.mode}操作完成")
    
    def _process_item(self, item_path: str, item_type: str) -> bool:
        """处理单个项目（线程安全）
        
        Args:
            item_path: 项目路径
            item_type: 项目类型
            
        Returns:
            bool: 操作是否成功
        """
        try:
            operation_func = self.operation_map[self.mode]
            return operation_func(item_path, item_type)
        except Exception as e:
            self.logger.error(f"线程处理项目时发生错误: {item_path}, 错误: {e}")
            return False
    
    def _init_progress(self, new_items: list) -> None:
        """初始化进度跟踪
        
        Args:
            new_items: 新增项目列表
        """
        self.total_files = len(new_items)
        self.completed_files = 0
        self.total_size = 0
        self.transferred_size = 0
        self.start_time = time.time()
        
        # 计算总文件大小
        for item in new_items:
            if item["type"] == "file":
                self.total_size += item["size"]
    
    def _show_progress_status(self) -> None:
        """显示实时进度状态（线程安全）"""
        with self.lock:
            elapsed_time = time.time() - self.start_time
            if elapsed_time == 0:
                return
            
            # 计算速度和剩余时间
            speed = self.transferred_size / elapsed_time  # B/s
            if speed > 0:
                remaining_size = self.total_size - self.transferred_size
                remaining_time = remaining_size / speed
            else:
                remaining_time = 0
            
            # 格式化输出
            status = f"状态: {self.mode} | 已完成: {self.completed_files}/{self.total_files} 文件 | "
            status += f"已传输: {self._format_size(self.transferred_size)}/{self._format_size(self.total_size)} | "
            status += f"速度: {self._format_size(speed)}/s | 剩余时间: {self._format_time(remaining_time)}"
            
        # 安全更新进度条描述
        if hasattr(self, 'overall_pbar'):
            self.overall_pbar.set_description(desc=status)
    
    def _format_size(self, size: int) -> str:
        """格式化文件大小
        
        Args:
            size: 文件大小（字节）
            
        Returns:
            str: 格式化后的文件大小
        """
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"
    
    def _format_time(self, seconds: float) -> str:
        """格式化时间
        
        Args:
            seconds: 时间（秒）
            
        Returns:
            str: 格式化后的时间
        """
        if seconds < 60:
            return f"{seconds:.2f}s"
        elif seconds < 3600:
            minutes, seconds = divmod(seconds, 60)
            return f"{int(minutes)}m{int(seconds)}s"
        else:
            hours, remainder = divmod(seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            return f"{int(hours)}h{int(minutes)}m{int(seconds)}s"
    
    def sync_item(self, item_path: str, item_type: str) -> bool:
        """同步项目
        
        Args:
            item_path: 项目路径
            item_type: 项目类型（file/folder）
            
        Returns:
            bool: 操作是否成功
        """
        try:
            # 计算目标路径
            rel_path = os.path.relpath(item_path, self.source_dir)
            target_path = os.path.join(self.target_dir, rel_path)
            
            if item_type == "folder":
                # 创建目标文件夹
                os.makedirs(target_path, exist_ok=True)
                self.logger.info(f"同步文件夹: {item_path} -> {target_path}")
            else:  # file
                # 确保目标文件夹存在
                target_dir = os.path.dirname(target_path)
                os.makedirs(target_dir, exist_ok=True)
                
                # 复制文件
                if os.path.exists(target_path):
                    self.logger.warning(f"目标文件已存在，将覆盖: {target_path}")
                
                # 使用分块复制处理大文件，带进度显示
                if not self.copy_large_file(item_path, target_path):
                    return False
                
                # 验证文件完整性
                if not self.verify_file_integrity(item_path, target_path):
                    self.logger.error(f"文件完整性验证失败: {item_path} -> {target_path}")
                    return False
                
                self.logger.info(f"同步文件: {item_path} -> {target_path}")
            
            return True
        except Exception as e:
            self.logger.error(f"同步项目时发生错误: {item_path}, 错误: {e}")
            return False
    
    def move_item(self, item_path: str, item_type: str) -> bool:
        """移动项目
        
        Args:
            item_path: 项目路径
            item_type: 项目类型（file/folder）
            
        Returns:
            bool: 操作是否成功
        """
        try:
            # 计算目标路径
            rel_path = os.path.relpath(item_path, self.source_dir)
            target_path = os.path.join(self.target_dir, rel_path)
            
            if item_type == "folder":
                # 确保目标文件夹不存在
                if os.path.exists(target_path):
                    self.logger.warning(f"目标文件夹已存在: {target_path}")
                    return False
                
                # 创建目标文件夹的父目录
                target_parent = os.path.dirname(target_path)
                os.makedirs(target_parent, exist_ok=True)
                
                # 获取文件夹大小
                folder_size = self._get_folder_size(item_path)
                
                # 移动文件夹
                shutil.move(item_path, target_path)
                self.logger.info(f"移动文件夹: {item_path} -> {target_path}")
                
                # 更新传输大小
                self.transferred_size += folder_size
            else:  # file
                # 确保目标文件夹存在
                target_dir = os.path.dirname(target_path)
                os.makedirs(target_dir, exist_ok=True)
                
                # 确保目标文件不存在
                if os.path.exists(target_path):
                    self.logger.warning(f"目标文件已存在，将覆盖: {target_path}")
                    os.remove(target_path)
                
                # 使用分块复制处理大文件，带进度显示，然后删除源文件
                if self.copy_large_file(item_path, target_path):
                    # 删除源文件
                    os.remove(item_path)
                    self.logger.info(f"移动文件: {item_path} -> {target_path}")
                else:
                    return False
            
            return True
        except Exception as e:
            self.logger.error(f"移动项目时发生错误: {item_path}, 错误: {e}")
            return False
    
    def _get_folder_size(self, folder_path: str) -> int:
        """获取文件夹大小
        
        Args:
            folder_path: 文件夹路径
            
        Returns:
            int: 文件夹大小（字节）
        """
        total_size = 0
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                total_size += os.path.getsize(file_path)
        return total_size
    
    def copy_large_file(self, src: str, dst: str) -> bool:
        """复制大文件（分块复制），带进度显示
        
        Args:
            src: 源文件路径
            dst: 目标文件路径
            
        Returns:
            bool: 操作是否成功
        """
        try:
            # 获取文件大小
            file_size = os.path.getsize(src)
            
            # 创建文件复制进度条
            with open(src, 'rb') as fsrc, open(dst, 'wb') as fdst:
                # 不使用tqdm嵌套，避免UI混乱
                transferred = 0
                while True:
                    block = fsrc.read(self.block_size)
                    if not block:
                        break
                    fdst.write(block)
                    
                    # 更新已传输大小
                    block_size = len(block)
                    transferred += block_size
                    
                    # 线程安全地更新全局传输大小
                    with self.lock:
                        self.transferred_size += block_size
                    
                    # 定期显示进度
                    if transferred % self.progress_update_interval == 0:  # 按配置的间隔更新
                        self._show_progress_status()
            
            return True
        except Exception as e:
            self.logger.error(f"复制大文件时发生错误: {src} -> {dst}, 错误: {e}")
            # 清理目标文件
            if os.path.exists(dst):
                os.remove(dst)
            return False
    
    def verify_file_integrity(self, src: str, dst: str) -> bool:
        """验证文件完整性
        
        Args:
            src: 源文件路径
            dst: 目标文件路径
            
        Returns:
            bool: 文件是否完整
        """
        try:
            src_hash = self._calculate_hash(src)
            dst_hash = self._calculate_hash(dst)
            return src_hash == dst_hash
        except Exception as e:
            self.logger.error(f"验证文件完整性时发生错误: {src} -> {dst}, 错误: {e}")
            return False
    
    def _calculate_hash(self, file_path: str) -> str:
        """计算文件的MD5哈希值
        
        Args:
            file_path: 文件路径
            
        Returns:
            str: 文件的MD5哈希值
        """
        hasher = hashlib.md5()
        with open(file_path, 'rb') as f:
            while True:
                block = f.read(self.block_size)
                if not block:
                    break
                hasher.update(block)
        return hasher.hexdigest()
    
    def verify_integrity(self) -> bool:
        """验证目标文件夹完整性
        
        Returns:
            bool: 完整性检查是否通过
        """
        self.logger.info("开始执行目标文件夹完整性校验")
        
        # 扫描源文件夹
        source_scan = self._scan_folder(self.source_dir)
        # 扫描目标文件夹
        target_scan = self._scan_folder(self.target_dir)
        
        # 获取源文件的相对路径集合
        source_rel_paths = set()
        for path in source_scan:
            if source_scan[path]["type"] == "file":
                rel_path = os.path.relpath(path, self.source_dir)
                source_rel_paths.add(rel_path)
        
        # 获取目标文件的相对路径集合
        target_rel_paths = set()
        for path in target_scan:
            if target_scan[path]["type"] == "file":
                rel_path = os.path.relpath(path, self.target_dir)
                target_rel_paths.add(rel_path)
        
        # 检查文件数量
        source_file_count = len(source_rel_paths)
        target_file_count = len(target_rel_paths)
        self.logger.info(f"源文件夹文件数量: {source_file_count}, 目标文件夹文件数量: {target_file_count}")
        
        # 检查文件一致性
        missing_files = source_rel_paths - target_rel_paths
        extra_files = target_rel_paths - source_rel_paths
        
        # 记录结果
        is_valid = True
        
        if missing_files:
            is_valid = False
            self.logger.error(f"目标文件夹缺少以下文件: {missing_files}")
        
        if extra_files:
            self.logger.warning(f"目标文件夹存在额外文件: {extra_files}")
        
        if missing_files or extra_files:
            self.logger.error(f"完整性校验失败: 源文件数量={source_file_count}, 目标文件数量={target_file_count}, 缺少文件={len(missing_files)}, 额外文件={len(extra_files)}")
        else:
            self.logger.info("完整性校验通过: 源文件和目标文件完全一致")
        
        return is_valid
    
    def _scan_folder(self, folder_path: str) -> dict:
        """扫描文件夹，获取文件/文件夹元数据
        
        Args:
            folder_path: 文件夹路径
            
        Returns:
            dict: 扫描结果，包含文件/文件夹的元数据
        """
        scan_result = {}
        
        try:
            # 使用os.walk递归扫描文件夹
            for root, dirs, files in os.walk(folder_path):
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
            self.logger.error(f"扫描文件夹时发生错误: {folder_path}, 错误: {e}")
        
        return scan_result

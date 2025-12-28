import time
from config import ConfigManager
from logger import Logger
from scanner import Scanner
from file_operator import Operator
from network_sync import SyncManager

def main():
    """主函数"""
    try:
        # 1. 初始化配置管理器
        config_manager = ConfigManager()
        config = config_manager.load_config()
        
        # 2. 验证必要的配置项
        if not config["source_dir"] or not config["target_dir"]:
            print("错误：源文件夹和目标文件夹路径必须提供")
            return
        
        # 3. 初始化日志管理器
        logger = Logger(log_file=config["log_file"], log_level=config["log_level"])
        logger.info("文件夹监视程序已启动")
        logger.info(f"配置信息：源文件夹={config['source_dir']}, 目标文件夹={config['target_dir']}, 扫描间隔={config['interval']}秒, 操作模式={config['mode']}")
        
        # 4. 初始化扫描器
        scanner = Scanner(
            source_dir=config["source_dir"], 
            logger=logger,
            filter_suffixes=config["filter_suffixes"]
        )
        
        # 5. 初始化操作器
        operator = Operator(
            source_dir=config["source_dir"],
            target_dir=config["target_dir"],
            mode=config["mode"],
            logger=logger,
            thread_count=config["thread_count"],
            max_threads=config["max_threads"],
            progress_update_interval=config["progress_update_interval"]
        )
        
        # 6. 初始化跨系统同步管理器（如果启用）
        sync_manager = None
        if config["enable_network_sync"]:
            sync_manager = SyncManager(logger)
            sync_manager.set_sync_config(config)
            
            # 根据同步模式启动服务
            if config["sync_mode"] == "server":
                # 服务器模式：启动同步服务器
                sync_manager.network_sync.start_server(config["sync_host"], config["sync_port"])
            else:
                # 客户端模式：连接到同步服务器
                sync_manager.network_sync.connect_to_server(config["sync_host"], config["sync_port"])
            
            # 启动跨系统同步
            sync_manager.start_sync()
        
        # 6. 首次扫描，建立初始状态
        previous_scan = scanner.scan()
        
        # 7. 执行目标文件夹完整性校验
        integrity_result = operator.verify_integrity()
        
        # 8. 如果完整性校验失败，手动同步所有文件
        if not integrity_result:
            # 将首次扫描结果转换为可执行的项目列表
            initial_items = []
            for item_path, item_info in previous_scan.items():
                initial_items.append({
                    "path": item_path,
                    "type": item_info["type"],
                    "create_time": item_info["create_time"],
                    "modify_time": item_info["modify_time"],
                    "size": item_info["size"]
                })
            
            # 执行同步操作
            operator.execute(initial_items)
        
        # 7. 定期扫描循环
        while True:
            try:
                # 等待指定的扫描间隔
                time.sleep(config["interval"])
                
                # 执行扫描
                current_scan = scanner.scan()
                
                # 检测新增项目
                new_items = scanner.detect_new_items(previous_scan, current_scan)
                
                # 检测变更项目
                changed_items = scanner.detect_changed_items(current_scan, config["target_dir"])
                
                # 合并新增和变更项目
                all_items = new_items + changed_items
                
                # 执行本地操作
                if all_items:
                    operator.execute(all_items)
                
                # 执行跨系统同步（如果启用）
                if sync_manager:
                    try:
                        logger.info("开始跨系统同步")
                        
                        # 扫描远程目录（这里简化处理，实际应该通过网络获取远程扫描结果）
                        # 对于客户端模式，应该向服务器请求远程扫描结果
                        # 对于服务器模式，应该等待客户端连接
                        
                        # 检测文件变化
                        local_scan = current_scan
                        # 假设远程扫描结果通过网络获取，这里简化处理
                        remote_scan = {}  # 实际应该从网络获取
                        
                        new_files, modified_files, deleted_files = sync_manager.detect_file_changes(local_scan, remote_scan)
                        
                        # 执行同步
                        if new_files or modified_files or deleted_files:
                            sync_manager.sync_files(new_files, modified_files, deleted_files)
                        
                        logger.info("跨系统同步完成")
                    except Exception as sync_e:
                        logger.error(f"跨系统同步失败: {sync_e}")
                
                # 更新上一次扫描结果
                previous_scan = current_scan
                
            except KeyboardInterrupt:
                # 用户按下Ctrl+C，退出程序
                logger.info("用户中断，程序退出")
                break
            except Exception as e:
                # 捕获并记录其他异常，继续执行
                logger.error(f"扫描循环中发生错误: {e}")
                continue
        
    except ValueError as e:
        print(f"配置错误: {e}")
    except Exception as e:
        print(f"程序启动失败: {e}")

if __name__ == "__main__":
    main()

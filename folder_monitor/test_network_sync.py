#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
跨系统文件同步功能测试脚本
"""

import os
import sys
import time
import tempfile
import shutil
from config import ConfigManager
from logger import Logger
from network_sync import NetworkSync, SyncManager


def test_network_sync():
    """测试跨系统文件同步功能"""
    # 创建临时目录用于测试
    temp_dir = tempfile.mkdtemp(prefix="network_sync_test_")
    
    try:
        # 配置日志
        logger = Logger(log_file=os.path.join(temp_dir, "test.log"), log_level="DEBUG")
        logger.info(f"开始测试跨系统文件同步功能，临时目录: {temp_dir}")
        
        # 测试1: 初始化NetworkSync和SyncManager
        logger.info("=== 测试1: 初始化NetworkSync和SyncManager ===")
        network_sync = NetworkSync(logger)
        sync_manager = SyncManager(logger)
        logger.info("✅ NetworkSync和SyncManager初始化成功")
        
        # 测试2: 测试文件哈希计算
        logger.info("=== 测试2: 测试文件哈希计算 ===")
        test_file = os.path.join(temp_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("This is a test file for network sync.")
        
        file_hash = network_sync.calculate_file_hash(test_file)
        if file_hash:
            logger.info(f"✅ 文件哈希计算成功: {file_hash}")
        else:
            logger.error("❌ 文件哈希计算失败")
        
        # 测试3: 测试断点信息管理
        logger.info("=== 测试3: 测试断点信息管理 ===")
        network_sync.save_breakpoint(test_file, "remote/test.txt", 100, 200)
        breakpoint = network_sync.get_breakpoint(test_file, "remote/test.txt")
        if breakpoint:
            logger.info(f"✅ 断点信息保存和读取成功: {breakpoint}")
            network_sync.delete_breakpoint(test_file, "remote/test.txt")
            logger.info("✅ 断点信息删除成功")
        else:
            logger.error("❌ 断点信息管理失败")
        
        # 测试4: 测试SyncManager配置
        logger.info("=== 测试4: 测试SyncManager配置 ===")
        sync_config = {
            "enable_network_sync": True,
            "sync_mode": "client",
            "sync_host": "127.0.0.1",
            "sync_port": 8080,
            "ssl_enabled": False,
            "conflict_resolution": "newest",
            "chunk_size": 4096,
            "resume_enabled": True
        }
        sync_manager.set_sync_config(sync_config)
        logger.info("✅ SyncManager配置成功")
        
        # 测试5: 测试冲突检测和解决
        logger.info("=== 测试5: 测试冲突检测和解决 ===")
        
        # 创建模拟冲突
        local_file = {
            "full_path": test_file,
            "base_dir": temp_dir,
            "type": "file",
            "create_time": time.time() - 100,
            "modify_time": time.time() - 50,
            "size": 100
        }
        
        remote_file = {
            "full_path": "remote/test.txt",
            "base_dir": "remote",
            "type": "file",
            "create_time": time.time() - 200,
            "modify_time": time.time() - 25,
            "size": 150
        }
        
        conflicts = [{
            "local_file": local_file,
            "remote_file": remote_file
        }]
        
        resolved = sync_manager.resolve_conflicts(conflicts)
        if resolved:
            logger.info(f"✅ 冲突解决成功: {resolved}")
        else:
            logger.error("❌ 冲突解决失败")
        
        logger.info("=== 测试完成 ===")
        logger.info("✅ 所有测试用例执行完毕")
        
        return True
        
    except Exception as e:
        logger.error(f"测试过程中发生错误: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # 清理临时目录
        shutil.rmtree(temp_dir)
        logger.info(f"测试结束，清理临时目录: {temp_dir}")


def test_config_loading():
    """测试配置加载功能"""
    logger = Logger(log_level="DEBUG")
    logger.info("=== 测试配置加载功能 ===")
    
    # 创建测试配置文件
    test_config = """
[monitor]
source_dir = .
target_dir = ./test_target
interval = 30
mode = sync
log_file = test.log
log_level = DEBUG
thread_count = 4
max_threads = 16
progress_update_interval = 5
filter_suffixes = .log,.ini

# 跨系统同步配置
enable_network_sync = true
sync_mode = client
sync_host = 127.0.0.1
sync_port = 8080
ssl_enabled = false
cert_file = 
key_file = 
ca_cert = 
conflict_resolution = newest
chunk_size = 4096
resume_enabled = true
"""
    
    with open("test_config.ini", "w", encoding="utf-8") as f:
        f.write(test_config)
    
    try:
        # 测试加载配置
        config_manager = ConfigManager()
        config = config_manager.load_config("test_config.ini")
        
        # 验证跨系统同步配置是否正确加载
        if config["enable_network_sync"]:
            logger.info("✅ 跨系统同步配置加载成功")
            logger.info(f"   sync_mode: {config['sync_mode']}")
            logger.info(f"   sync_host: {config['sync_host']}")
            logger.info(f"   sync_port: {config['sync_port']}")
            logger.info(f"   ssl_enabled: {config['ssl_enabled']}")
            logger.info(f"   conflict_resolution: {config['conflict_resolution']}")
            logger.info(f"   chunk_size: {config['chunk_size']}")
            logger.info(f"   resume_enabled: {config['resume_enabled']}")
            return True
        else:
            logger.error("❌ 跨系统同步配置加载失败")
            return False
            
    finally:
        # 清理测试配置文件
        if os.path.exists("test_config.ini"):
            os.remove("test_config.ini")


if __name__ == "__main__":
    """测试主入口"""
    print("跨系统文件同步功能测试")
    print("=" * 60)
    
    # 运行配置加载测试
    print("\n1. 测试配置加载功能...")
    if test_config_loading():
        print("✅ 配置加载测试通过")
    else:
        print("❌ 配置加载测试失败")
    
    # 运行网络同步功能测试
    print("\n2. 测试跨系统同步功能...")
    if test_network_sync():
        print("✅ 跨系统同步功能测试通过")
    else:
        print("❌ 跨系统同步功能测试失败")
    
    print("\n" + "=" * 60)
    print("测试完成！")

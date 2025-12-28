# 文件夹内容监视程序

一个用Python开发的文件夹内容监视程序，能够定时扫描指定的源文件夹，当检测到新创建的文件或文件夹时，自动执行同步或移动操作到预设的目标文件夹。

## 功能特性

- ✅ 定时扫描指定源文件夹
- ✅ 检测新创建和修改的文件和文件夹
- ✅ 支持同步（保留源文件）和移动（移除源文件）两种操作模式
- ✅ 支持递归扫描子文件夹
- ✅ 处理大文件传输，确保文件完整性
- ✅ 详细的日志记录，包含线程ID、文件名和行号
- ✅ 完善的异常处理
- ✅ 跨平台兼容（Windows、macOS、Linux）
- ✅ 支持配置文件和命令行参数
- ✅ 多线程支持，可配置线程数和动态调整
- ✅ 文件后缀过滤功能
- ✅ 实时进度条显示，安全更新机制
- ✅ 目标文件夹完整性校验
- ✅ 跨系统文件同步功能
  - 双向同步支持
  - SSL加密传输
  - 断点续传机制
  - 多种冲突解决策略（最新优先、最大优先、手动）
  - 服务器/客户端模式支持

## 技术栈

- Python 3.6+
- 依赖库：
  - tqdm (用于进度条显示)

## 文件目录结构

```
folder_monitor/
├── __pycache__/          # Python编译缓存文件
├── docs/                 # 项目文档目录
│   ├── ACCEPTANCE_*.md   # 验收标准文档
│   ├── ALIGNMENT_*.md    # 需求对齐文档
│   ├── CONSENSUS_*.md    # 共识文档
│   ├── DESIGN_*.md       # 设计文档
│   ├── FINAL_*.md        # 最终报告
│   └── TASK_*.md         # 任务分解文档
├── README.md             # 项目说明文档
├── config.ini            # Windows平台配置文件
├── config.py             # 配置管理模块
├── file_operator.py      # 文件操作模块，处理文件同步和移动
├── folder_monitor.log    # 日志文件
├── linux_config.ini      # Linux平台配置文件
├── logger.py             # 日志管理模块
├── main.py               # 主程序入口
├── network_sync.py       # 跨系统同步模块
├── requirements.txt      # 依赖库列表
├── scanner.py            # 文件夹扫描模块
└── test_network_sync.py  # 跨系统同步测试脚本
```

### 核心文件说明

| 文件 | 功能描述 |
|------|----------|
| **main.py** | 主程序入口，负责初始化配置、启动扫描和处理文件变化 |
| **config.py** | 配置管理模块，负责加载和验证配置文件 |
| **scanner.py** | 文件夹扫描模块，负责扫描源文件夹，检测文件变化 |
| **file_operator.py** | 文件操作模块，负责执行文件的同步和移动操作，支持多线程 |
| **network_sync.py** | 跨系统同步模块，负责不同系统间的文件同步，支持SSL加密和断点续传 |
| **logger.py** | 日志管理模块，负责记录程序运行日志 |
| **config.ini** | 配置文件，包含程序运行的各项参数 |
| **test_network_sync.py** | 跨系统同步功能的测试脚本 |

## 安装

1. 确保您的系统已安装Python 3.6或更高版本
2. 克隆或下载项目代码到本地
3. 进入项目目录
4. 安装依赖

```bash
git clone <repository-url>
cd folder_monitor
pip install -r requirements.txt
```

## 使用方法

### 1. 使用配置文件

1. 复制并修改配置文件 `config.ini`

```bash
cp config.ini my_config.ini
```

2. 编辑配置文件，设置源文件夹、目标文件夹等参数

3. 运行程序

```bash
python main.py -c my_config.ini
```

### 2. 使用命令行参数

```bash
python main.py -s <源文件夹路径> -t <目标文件夹路径> -i <扫描间隔> -m <操作模式>
```

### 命令行参数说明

| 参数 | 缩写 | 说明 | 可选值 |
|------|------|------|--------|
| --config | -c | 配置文件路径 | 任意有效的文件路径 |
| --source | -s | 源文件夹路径 | 任意有效的文件夹路径 |
| --target | -t | 目标文件夹路径 | 任意有效的文件夹路径 |
| --interval | -i | 扫描间隔（秒） | 整数，最小值为1 |
| --mode | -m | 操作模式 | sync（同步）或 move（移动） |
| --log-file | 无 | 日志文件路径 | 任意有效的文件路径 |
| --log-level | 无 | 日志级别 | DEBUG, INFO, WARNING, ERROR, CRITICAL |
| --thread-count | 无 | 线程数量，0表示自动计算 | 整数，0或正整数 |
| --max-threads | 无 | 最大线程数 | 正整数 |
| --progress-update-interval | 无 | 进度更新间隔（MB） | 正整数 |
| --filter-suffixes | 无 | 需要过滤的文件后缀，以逗号分隔 | 例如：.txt,.jpg,.png |
| --enable-network-sync | 无 | 启用跨系统同步 | 无需值 |
| --sync-mode | 无 | 同步模式 | client（客户端）或 server（服务器） |
| --sync-host | 无 | 同步服务器地址 | IP地址或域名 |
| --sync-port | 无 | 同步服务器端口 | 1-65535 |
| --ssl-enabled | 无 | 启用SSL加密 | 无需值 |
| --cert-file | 无 | 证书文件路径（服务器模式） | 任意有效的文件路径 |
| --key-file | 无 | 私钥文件路径（服务器模式） | 任意有效的文件路径 |
| --ca-cert | 无 | CA证书文件路径（客户端模式） | 任意有效的文件路径 |
| --conflict-resolution | 无 | 冲突解决策略 | newest（最新优先）、largest（最大优先）、manual（手动） |
| --chunk-size | 无 | 文件分块大小（字节） | 正整数，1024-1048576 |
| --resume-enabled | 无 | 启用断点续传 | 无需值 |

### 3. 混合使用

命令行参数优先级高于配置文件，您可以使用配置文件设置默认值，然后使用命令行参数覆盖特定配置项。

```bash
python main.py -c config.ini -i 10 -m move
```

## 配置文件说明

配置文件使用INI格式，包含两个主要部分：

### [monitor] 部分 - 基本监视配置

```ini
[monitor]
# 源文件夹路径
source_dir = D:\source\test

# 目标文件夹路径
target_dir = D:\target\test

# 扫描间隔（秒），最小值为1
interval = 5

# 操作模式：sync（同步，保留源文件）或 move（移动，移除源文件）
mode = sync

# 日志文件路径
log_file = folder_monitor.log

# 日志级别：DEBUG, INFO, WARNING, ERROR, CRITICAL
log_level = INFO

# 线程数量，0表示自动计算
thread_count = 0

# 最大线程数
max_threads = 32

# 进度更新间隔（MB）
progress_update_interval = 10

# 需要过滤的文件后缀，以逗号分隔，如：.txt,.jpg
filter_suffixes =
```

### [server] 部分 - 跨系统同步配置

```ini
[server]
# 是否启用跨系统同步
enable_network_sync = false

# 同步模式：client（客户端）或 server（服务器）
sync_mode = client

# 同步服务器地址
sync_host = 127.0.0.1

# 同步服务器端口
sync_port = 8080

# 是否启用SSL加密
ssl_enabled = false

# 证书文件路径（服务器模式）
cert_file =

# 私钥文件路径（服务器模式）
key_file =

# CA证书文件路径（客户端模式）
ca_cert =

# 冲突解决策略：newest（最新优先）、largest（最大优先）、manual（手动）
conflict_resolution = newest

# 文件分块大小（字节）
chunk_size = 4096

# 是否启用断点续传
resume_enabled = true
```

## 日志记录

程序会生成详细的日志文件，包含：

- 程序启动和退出信息
- 扫描结果
- 执行的操作
- 可能出现的错误信息
- 跨系统同步日志
- 线程ID、文件名和行号（便于定位问题）

日志格式：
```
2025-12-28 11:00:00,000 - INFO - [Thread:12345] - logger.py:40 - 文件夹监视程序已启动
2025-12-28 11:00:00,000 - INFO - [Thread:12345] - main.py:23 - 配置信息：源文件夹=D:\source\test, 目标文件夹=D:\target\test, 扫描间隔=5秒, 操作模式=sync
2025-12-28 11:00:00,000 - INFO - [Thread:12345] - scanner.py:32 - 开始扫描文件夹: D:\source\test
2025-12-28 11:00:00,000 - INFO - [Thread:12345] - scanner.py:76 - 扫描完成，共发现 0 个项目
2025-12-28 11:00:00,000 - INFO - [Thread:67890] - network_sync.py:627 - 开始跨系统文件同步
```

## 异常处理

程序能够处理以下异常情况：

- 文件访问权限问题
- 文件正在被使用
- 路径不存在
- 磁盘空间不足
- 配置错误

所有异常都会被记录到日志中，程序会继续运行，不会崩溃。

## 性能优化

- 仅处理新创建和修改的文件和文件夹，避免重复处理
- 大文件使用分块复制，提高传输效率
- 使用MD5哈希值验证文件完整性
- 扫描和操作分离，提高并发处理能力
- 多线程并行处理，大幅提高处理效率
- 动态线程数量调整，根据CPU核心数和可用内存自动优化
- 文件后缀过滤，减少不必要的文件处理
- 断点续传机制，避免网络中断后重新传输
- 实时进度条显示，安全更新机制，避免UI阻塞

## 退出程序

按下 `Ctrl+C` 组合键可以优雅退出程序。

## 示例

### 示例1：使用配置文件运行

1. 创建配置文件 `my_config.ini`：

```ini
[monitor]
source_dir = D:\Downloads
target_dir = D:\Backup
interval = 10
mode = sync
log_file = download_backup.log
log_level = INFO
thread_count = 0
max_threads = 16
progress_update_interval = 5
filter_suffixes = .tmp,.temp
```

2. 运行程序：

```bash
python main.py -c my_config.ini
```

### 示例2：使用命令行参数运行

```bash
python main.py -s /home/user/Documents -t /home/user/Backup -i 30 -m move --log-file docs_backup.log --log-level DEBUG --thread-count 4 --filter-suffixes .tmp,.log
```

### 示例3：跨系统同步 - 服务器模式

1. 创建服务器配置文件 `server_config.ini`：

```ini
[monitor]
source_dir = /home/server/sync_source
target_dir = /home/server/sync_target
interval = 10
mode = sync
log_file = sync_server.log
log_level = INFO

[server]
# 跨系统同步配置
enable_network_sync = true
sync_mode = server
sync_host = 0.0.0.0
sync_port = 8080
ssl_enabled = false
cert_file =
key_file =
ca_cert =
conflict_resolution = newest
resume_enabled = true
```

2. 启动服务器：

```bash
python main.py -c server_config.ini
```

### 示例4：跨系统同步 - 客户端模式

1. 创建客户端配置文件 `client_config.ini`：

```ini
[monitor]
source_dir = /home/client/local_folder
target_dir = /home/client/sync_folder
interval = 10
mode = sync
log_file = sync_client.log
log_level = INFO

[server]
# 跨系统同步配置
enable_network_sync = true
sync_mode = client
sync_host = 192.168.1.100
sync_port = 8080
ssl_enabled = false
cert_file =
key_file =
ca_cert =
conflict_resolution = newest
resume_enabled = true
```

2. 启动客户端：

```bash
python main.py -c client_config.ini
```

## 注意事项

1. 确保源文件夹和目标文件夹路径正确
2. 确保程序有足够的权限访问源文件夹和目标文件夹
3. 扫描间隔建议设置为合理值，避免过于频繁的扫描影响系统性能
4. 大文件传输可能需要较长时间，请根据实际情况调整扫描间隔
5. 日志文件会随着时间增长，建议定期清理或归档
6. 多线程设置建议：
   - 对于机械硬盘，建议线程数不超过CPU核心数
   - 对于固态硬盘，可以适当增加线程数
   - 设置为0时会自动计算最佳线程数
7. 文件后缀过滤：
   - 后缀名区分大小写
   - 每个后缀前必须加`.`，如：`.txt` 而不是 `txt`
8. 跨系统同步注意事项：
   - 确保防火墙允许同步端口的通信
   - SSL模式下需要正确配置证书
   - 服务器模式下建议使用固定IP或域名
   - 冲突解决策略需要根据实际业务需求选择
   - 断点续传功能会在同步目录下生成`.sync_breakpoints`文件夹，用于存储断点信息
9. 跨平台注意事项：
   - Windows路径使用`\`，Linux/macOS使用`/`
   - 文件名大小写敏感性：Windows不敏感，Linux/macOS敏感
   - 特殊字符处理：不同系统支持的文件名特殊字符不同

## 许可证

MIT License

## 贡献

欢迎提交Issue和Pull Request！

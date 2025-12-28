import os
import socket
import ssl
import json
import hashlib
import threading
import time
from typing import Dict, List, Tuple, Optional
from logger import Logger

class NetworkSync:
    """跨系统文件同步类"""
    
    def __init__(self, logger: Logger):
        """初始化网络同步类
        
        Args:
            logger: 日志管理器实例
        """
        self.logger = logger
        self.socket = None
        self.ssl_context = None
        self.is_server = False
        self.connected = False
        self.lock = threading.Lock()
        
        # 断点续传相关
        self.breakpoint_dir = ".sync_breakpoints"
        os.makedirs(self.breakpoint_dir, exist_ok=True)
        self.chunk_size = 4096
        
    def setup_ssl_context(self, cert_file: str = None, key_file: str = None, ca_cert: str = None):
        """设置SSL上下文
        
        Args:
            cert_file: 证书文件路径
            key_file: 私钥文件路径
            ca_cert: CA证书文件路径
        """
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if self.is_server else ssl.PROTOCOL_TLS_CLIENT)
        
        if self.is_server:
            # 服务器模式：加载证书和私钥
            if cert_file and key_file:
                self.ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        else:
            # 客户端模式：验证服务器证书
            self.ssl_context.check_hostname = True
            self.ssl_context.verify_mode = ssl.CERT_REQUIRED
            if ca_cert:
                self.ssl_context.load_verify_locations(ca_cert)
    
    def start_server(self, host: str, port: int):
        """启动服务器
        
        Args:
            host: 服务器地址
            port: 服务器端口
        
        Returns:
            bool: 服务器启动是否成功
        """
        self.is_server = True
        try:
            # 创建TCP socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((host, port))
            server_socket.listen(5)
            
            # 包装为SSL socket
            if self.ssl_context:
                server_socket = self.ssl_context.wrap_socket(server_socket, server_side=True)
            
            self.logger.info(f"跨系统同步服务器已启动，监听地址: {host}:{port}")
            
            # 启动线程处理客户端连接
            threading.Thread(target=self._handle_clients, args=(server_socket,), daemon=True).start()
            return True
        except Exception as e:
            self.logger.error(f"启动跨系统同步服务器失败: {e}")
            return False
    
    def connect_to_server(self, host: str, port: int):
        """连接到服务器
        
        Args:
            host: 服务器地址
            port: 服务器端口
        
        Returns:
            bool: 连接是否成功
        """
        self.is_server = False
        try:
            # 创建TCP socket
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # 包装为SSL socket
            if self.ssl_context:
                client_socket = self.ssl_context.wrap_socket(client_socket, server_hostname=host)
            
            # 连接服务器
            client_socket.connect((host, port))
            self.socket = client_socket
            self.connected = True
            self.logger.info(f"成功连接到跨系统同步服务器: {host}:{port}")
            return True
        except Exception as e:
            self.logger.error(f"连接到跨系统同步服务器失败: {e}")
            return False
    
    def _handle_clients(self, server_socket):
        """处理客户端连接
        
        Args:
            server_socket: 服务器socket
        """
        while True:
            try:
                # 接受客户端连接
                client_socket, client_addr = server_socket.accept()
                self.logger.info(f"接收到客户端连接: {client_addr}")
                
                # 启动线程处理客户端请求
                threading.Thread(target=self._handle_client_request, args=(client_socket, client_addr), daemon=True).start()
            except Exception as e:
                self.logger.error(f"处理客户端连接时发生错误: {e}")
                break
    
    def _handle_client_request(self, client_socket, client_addr):
        """处理客户端请求
        
        Args:
            client_socket: 客户端socket
            client_addr: 客户端地址
        """
        try:
            while True:
                # 接收请求
                data = self._recv_data(client_socket)
                if not data:
                    break
                
                # 解析请求
                request = json.loads(data.decode('utf-8'))
                self.logger.debug(f"接收到客户端请求: {request}")
                
                # 处理请求
                response = self._process_request(request)
                
                # 发送响应
                self._send_data(client_socket, json.dumps(response).encode('utf-8'))
        except Exception as e:
            self.logger.error(f"处理客户端请求时发生错误: {e}")
        finally:
            client_socket.close()
            self.logger.info(f"客户端连接已关闭: {client_addr}")
    
    def _process_request(self, request: Dict) -> Dict:
        """处理请求
        
        Args:
            request: 请求字典
        
        Returns:
            Dict: 响应字典
        """
        response = {
            "status": "error",
            "message": "未知请求类型"
        }
        
        request_type = request.get("type")
        
        if request_type == "sync_info":
            # 处理同步信息请求
            response = self._handle_sync_info_request(request)
        elif request_type == "file_metadata":
            # 处理文件元数据请求
            response = self._handle_file_metadata_request(request)
        elif request_type == "send_file":
            # 处理发送文件请求
            response = self._handle_send_file_request(request)
        elif request_type == "file_chunk":
            # 处理文件分块请求
            response = self._handle_file_chunk_request(request)
        elif request_type == "file_end":
            # 处理文件发送结束请求
            response = self._handle_file_end_request(request)
        elif request_type == "delete_file":
            # 处理文件删除请求
            response = self._handle_delete_file_request(request)
        
        return response
    
    def _handle_sync_info_request(self, request: Dict) -> Dict:
        """处理同步信息请求
        
        Args:
            request: 请求字典
        
        Returns:
            Dict: 响应字典
        """
        try:
            # 返回同步服务信息
            return {
                "status": "ok",
                "message": "同步信息请求处理成功",
                "service_info": {
                    "version": "1.0",
                    "supported_operations": ["send_file", "receive_file", "delete_file"],
                    "timestamp": time.time()
                }
            }
        except Exception as e:
            self.logger.error(f"处理同步信息请求失败: {e}")
            return {
                "status": "error",
                "message": f"处理同步信息请求失败: {e}"
            }
    
    def _handle_file_metadata_request(self, request: Dict) -> Dict:
        """处理文件元数据请求
        
        Args:
            request: 请求字典，包含文件路径等信息
        
        Returns:
            Dict: 响应字典，包含文件元数据
        """
        try:
            file_path = request.get("file_path")
            if not file_path:
                return {
                    "status": "error",
                    "message": "缺少文件路径参数"
                }
            
            # 检查文件是否存在
            if not os.path.exists(file_path):
                return {
                    "status": "error",
                    "message": f"文件不存在: {file_path}"
                }
            
            # 获取文件元数据
            stat_info = os.stat(file_path)
            file_hash = self.calculate_file_hash(file_path)
            
            return {
                "status": "ok",
                "message": "文件元数据获取成功",
                "metadata": {
                    "file_path": file_path,
                    "size": stat_info.st_size,
                    "modify_time": stat_info.st_mtime,
                    "create_time": stat_info.st_ctime,
                    "hash": file_hash
                }
            }
        except Exception as e:
            self.logger.error(f"处理文件元数据请求失败: {e}")
            return {
                "status": "error",
                "message": f"处理文件元数据请求失败: {e}"
            }
    
    def _handle_send_file_request(self, request: Dict) -> Dict:
        """处理发送文件请求
        
        Args:
            request: 请求字典，包含文件信息
        
        Returns:
            Dict: 响应字典
        """
        try:
            remote_path = request.get("remote_path")
            file_size = request.get("file_size")
            file_hash = request.get("file_hash")
            offset = request.get("offset", 0)
            
            if not remote_path or file_size is None or not file_hash:
                return {
                    "status": "error",
                    "message": "缺少必要的文件参数"
                }
            
            # 保存当前文件传输状态
            self.current_transfer = {
                "remote_path": remote_path,
                "file_size": file_size,
                "file_hash": file_hash,
                "offset": offset,
                "received_bytes": offset
            }
            
            # 确保目标文件夹存在
            target_dir = os.path.dirname(remote_path)
            os.makedirs(target_dir, exist_ok=True)
            
            self.logger.info(f"准备接收文件: {remote_path}, 大小: {file_size}字节, 偏移量: {offset}")
            
            return {
                "status": "ok",
                "message": "准备接收文件成功",
                "offset": offset
            }
        except Exception as e:
            self.logger.error(f"处理发送文件请求失败: {e}")
            return {
                "status": "error",
                "message": f"处理发送文件请求失败: {e}"
            }
    
    def _handle_file_chunk_request(self, request: Dict) -> Dict:
        """处理文件分块请求
        
        Args:
            request: 请求字典，包含文件分块信息
        
        Returns:
            Dict: 响应字典
        """
        try:
            if not hasattr(self, 'current_transfer'):
                return {
                    "status": "error",
                    "message": "未找到当前传输任务"
                }
            
            offset = request.get("offset")
            chunk_size = request.get("chunk_size")
            
            if offset is None or chunk_size is None:
                return {
                    "status": "error",
                    "message": "缺少分块参数"
                }
            
            # 接收文件分块数据
            chunk_data = self._recv_data(self.socket)
            if not chunk_data or len(chunk_data) != chunk_size:
                return {
                    "status": "error",
                    "message": "文件分块数据不完整"
                }
            
            # 写入文件
            with open(self.current_transfer["remote_path"], 'ab' if offset > 0 else 'wb') as f:
                f.seek(offset)
                f.write(chunk_data)
            
            # 更新接收状态
            self.current_transfer["received_bytes"] += chunk_size
            
            # 定期刷新到磁盘
            if self.current_transfer["received_bytes"] % (self.chunk_size * 10) == 0:
                with open(self.current_transfer["remote_path"], 'rb') as f:
                    f.flush()
            
            return {
                "status": "ok",
                "received": self.current_transfer["received_bytes"],
                "message": "文件分块接收成功"
            }
        except Exception as e:
            self.logger.error(f"处理文件分块请求失败: {e}")
            return {
                "status": "error",
                "message": f"处理文件分块请求失败: {e}"
            }
    
    def _handle_file_end_request(self, request: Dict) -> Dict:
        """处理文件发送结束请求
        
        Args:
            request: 请求字典
        
        Returns:
            Dict: 响应字典
        """
        try:
            if not hasattr(self, 'current_transfer'):
                return {
                    "status": "error",
                    "message": "未找到当前传输任务"
                }
            
            transfer_info = self.current_transfer
            file_path = transfer_info["remote_path"]
            file_size = transfer_info["file_size"]
            file_hash = transfer_info["file_hash"]
            
            # 验证文件完整性
            received_hash = self.calculate_file_hash(file_path)
            if received_hash != file_hash:
                self.logger.error(f"文件完整性验证失败: {file_path}, 预期哈希: {file_hash}, 实际哈希: {received_hash}")
                return {
                    "status": "error",
                    "message": "文件完整性验证失败"
                }
            
            # 验证文件大小
            received_size = os.path.getsize(file_path)
            if received_size != file_size:
                self.logger.error(f"文件大小验证失败: {file_path}, 预期大小: {file_size}, 实际大小: {received_size}")
                return {
                    "status": "error",
                    "message": "文件大小验证失败"
                }
            
            # 清理当前传输状态
            delattr(self, 'current_transfer')
            
            self.logger.info(f"文件接收成功: {file_path}, 大小: {file_size}字节")
            return {
                "status": "ok",
                "message": "文件接收成功"
            }
        except Exception as e:
            self.logger.error(f"处理文件结束请求失败: {e}")
            return {
                "status": "error",
                "message": f"处理文件结束请求失败: {e}"
            }
    
    def _handle_delete_file_request(self, request: Dict) -> Dict:
        """处理文件删除请求
        
        Args:
            request: 请求字典，包含要删除的文件路径
        
        Returns:
            Dict: 响应字典
        """
        try:
            file_path = request.get("file_path")
            if not file_path:
                return {
                    "status": "error",
                    "message": "缺少文件路径参数"
                }
            
            # 删除文件
            if os.path.exists(file_path):
                os.remove(file_path)
                self.logger.info(f"删除文件: {file_path}")
            else:
                self.logger.warning(f"尝试删除不存在的文件: {file_path}")
            
            return {
                "status": "ok",
                "message": "文件删除成功"
            }
        except Exception as e:
            self.logger.error(f"处理文件删除请求失败: {e}")
            return {
                "status": "error",
                "message": f"处理文件删除请求失败: {e}"
            }
    
    def _send_data(self, socket_obj, data: bytes):
        """发送数据
        
        Args:
            socket_obj: socket对象
            data: 要发送的数据
        """
        # 发送数据长度
        data_len = len(data)
        socket_obj.sendall(data_len.to_bytes(4, byteorder='big'))
        # 发送数据
        socket_obj.sendall(data)
    
    def _recv_data(self, socket_obj) -> bytes:
        """接收数据
        
        Args:
            socket_obj: socket对象
        
        Returns:
            bytes: 接收到的数据
        """
        # 接收数据长度
        len_data = socket_obj.recv(4)
        if not len_data:
            return b''
        data_len = int.from_bytes(len_data, byteorder='big')
        
        # 接收数据
        data = b''
        while len(data) < data_len:
            chunk = socket_obj.recv(min(data_len - len(data), 4096))
            if not chunk:
                return b''
            data += chunk
        
        return data
    
    def calculate_file_hash(self, file_path: str) -> Optional[str]:
        """计算文件哈希值
        
        Args:
            file_path: 文件路径
        
        Returns:
            Optional[str]: 文件哈希值，计算失败返回None
        """
        try:
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            self.logger.error(f"计算文件哈希值失败: {file_path}, 错误: {e}")
            return None
    
    def _get_breakpoint_file(self, file_path: str, remote_path: str) -> str:
        """获取断点文件路径
        
        Args:
            file_path: 本地文件路径
            remote_path: 远程文件路径
        
        Returns:
            str: 断点文件路径
        """
        # 生成唯一的断点文件名
        breakpoint_key = hashlib.sha256(f"{file_path}_{remote_path}".encode()).hexdigest()
        return os.path.join(self.breakpoint_dir, f"breakpoint_{breakpoint_key}.json")
    
    def save_breakpoint(self, file_path: str, remote_path: str, offset: int, total_size: int):
        """保存断点信息
        
        Args:
            file_path: 本地文件路径
            remote_path: 远程文件路径
            offset: 当前传输偏移量
            total_size: 文件总大小
        """
        try:
            breakpoint_file = self._get_breakpoint_file(file_path, remote_path)
            breakpoint_data = {
                "file_path": file_path,
                "remote_path": remote_path,
                "offset": offset,
                "total_size": total_size,
                "last_update": time.time()
            }
            
            with open(breakpoint_file, 'w') as f:
                json.dump(breakpoint_data, f, indent=2)
            
            self.logger.debug(f"保存断点信息: {file_path} -> {remote_path}, 偏移量: {offset}/{total_size}")
        except Exception as e:
            self.logger.error(f"保存断点信息失败: {e}")
    
    def get_breakpoint(self, file_path: str, remote_path: str) -> Optional[Dict]:
        """获取断点信息
        
        Args:
            file_path: 本地文件路径
            remote_path: 远程文件路径
        
        Returns:
            Optional[Dict]: 断点信息，格式为 {"offset": int, "total_size": int, "last_update": float}，如果没有断点则返回None
        """
        try:
            breakpoint_file = self._get_breakpoint_file(file_path, remote_path)
            if os.path.exists(breakpoint_file):
                with open(breakpoint_file, 'r') as f:
                    breakpoint_data = json.load(f)
                
                # 检查断点是否有效（文件存在且大小一致）
                if os.path.exists(breakpoint_data["file_path"]):
                    file_size = os.path.getsize(breakpoint_data["file_path"])
                    if file_size == breakpoint_data["total_size"]:
                        self.logger.debug(f"读取断点信息: {file_path} -> {remote_path}, 偏移量: {breakpoint_data['offset']}/{breakpoint_data['total_size']}")
                        return breakpoint_data
            
            # 断点无效，删除
            self.delete_breakpoint(file_path, remote_path)
            return None
        except Exception as e:
            self.logger.error(f"获取断点信息失败: {e}")
            return None
    
    def delete_breakpoint(self, file_path: str, remote_path: str):
        """删除断点信息
        
        Args:
            file_path: 本地文件路径
            remote_path: 远程文件路径
        """
        try:
            breakpoint_file = self._get_breakpoint_file(file_path, remote_path)
            if os.path.exists(breakpoint_file):
                os.remove(breakpoint_file)
                self.logger.debug(f"删除断点信息: {file_path} -> {remote_path}")
        except Exception as e:
            self.logger.error(f"删除断点信息失败: {e}")
    
    def send_file_with_resume(self, file_path: str, remote_path: str, resume_enabled: bool = True) -> bool:
        """发送文件，支持断点续传
        
        Args:
            file_path: 本地文件路径
            remote_path: 远程文件路径
            resume_enabled: 是否启用断点续传
        
        Returns:
            bool: 发送是否成功
        """
        try:
            # 检查文件是否存在
            if not os.path.exists(file_path):
                self.logger.error(f"文件不存在: {file_path}")
                return False
            
            # 获取文件信息
            file_size = os.path.getsize(file_path)
            file_hash = self.calculate_file_hash(file_path)
            
            # 获取断点信息
            offset = 0
            if resume_enabled:
                breakpoint = self.get_breakpoint(file_path, remote_path)
                if breakpoint:
                    offset = breakpoint["offset"]
            
            # 构建发送请求
            request = {
                "type": "send_file",
                "remote_path": remote_path,
                "file_size": file_size,
                "file_hash": file_hash,
                "offset": offset,
                "chunk_size": self.chunk_size
            }
            
            # 发送请求
            self._send_data(self.socket, json.dumps(request).encode('utf-8'))
            
            # 接收响应
            response_data = self._recv_data(self.socket)
            if not response_data:
                self.logger.error("未收到服务器响应")
                return False
            
            response = json.loads(response_data.decode('utf-8'))
            if response["status"] != "ok":
                self.logger.error(f"服务器拒绝请求: {response['message']}")
                return False
            
            # 开始发送文件数据
            sent_bytes = offset
            with open(file_path, 'rb') as f:
                f.seek(offset)
                
                while sent_bytes < file_size:
                    # 读取文件块
                    remaining = file_size - sent_bytes
                    chunk = f.read(min(remaining, self.chunk_size))
                    if not chunk:
                        break
                    
                    # 发送文件块
                    chunk_request = {
                        "type": "file_chunk",
                        "offset": sent_bytes,
                        "chunk_size": len(chunk)
                    }
                    
                    # 发送块头
                    self._send_data(self.socket, json.dumps(chunk_request).encode('utf-8'))
                    # 发送块数据
                    self._send_data(self.socket, chunk)
                    
                    # 接收确认
                    ack_data = self._recv_data(self.socket)
                    if not ack_data:
                        self.logger.error("未收到块确认")
                        return False
                    
                    ack = json.loads(ack_data.decode('utf-8'))
                    if ack["status"] != "ok":
                        self.logger.error(f"块发送失败: {ack['message']}")
                        return False
                    
                    # 更新已发送字节数
                    sent_bytes += len(chunk)
                    
                    # 定期保存断点
                    if resume_enabled and sent_bytes % (self.chunk_size * 10) == 0:
                        self.save_breakpoint(file_path, remote_path, sent_bytes, file_size)
            
            # 发送结束标记
            end_request = {
                "type": "file_end"
            }
            self._send_data(self.socket, json.dumps(end_request).encode('utf-8'))
            
            # 接收最终确认
            final_ack = self._recv_data(self.socket)
            if not final_ack:
                self.logger.error("未收到最终确认")
                return False
            
            final_ack_json = json.loads(final_ack.decode('utf-8'))
            if final_ack_json["status"] == "ok":
                # 文件发送成功，删除断点
                if resume_enabled:
                    self.delete_breakpoint(file_path, remote_path)
                self.logger.info(f"文件发送成功: {file_path} -> {remote_path}, 大小: {file_size}字节")
                return True
            else:
                self.logger.error(f"文件发送失败: {final_ack_json['message']}")
                return False
        
        except Exception as e:
            self.logger.error(f"发送文件失败: {e}")
            # 保存断点
            if resume_enabled:
                self.save_breakpoint(file_path, remote_path, sent_bytes, file_size)
            return False
    
    def receive_file_with_resume(self, file_path: str, total_size: int, file_hash: str, offset: int = 0, resume_enabled: bool = True) -> bool:
        """接收文件，支持断点续传
        
        Args:
            file_path: 本地文件路径
            total_size: 文件总大小
            file_hash: 文件哈希值
            offset: 起始偏移量
            resume_enabled: 是否启用断点续传
        
        Returns:
            bool: 接收是否成功
        """
        try:
            # 确保目标文件夹存在
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            # 打开文件，支持断点续传
            with open(file_path, 'ab' if offset > 0 else 'wb') as f:
                if offset > 0:
                    f.seek(offset)
                
                received_bytes = offset
                
                while received_bytes < total_size:
                    # 接收块头
                    chunk_header_data = self._recv_data(self.socket)
                    if not chunk_header_data:
                        self.logger.error("未收到块头")
                        return False
                    
                    chunk_header = json.loads(chunk_header_data.decode('utf-8'))
                    if chunk_header["type"] != "file_chunk":
                        self.logger.error(f"无效的块头类型: {chunk_header['type']}")
                        return False
                    
                    # 接收块数据
                    chunk_data = self._recv_data(self.socket)
                    if not chunk_data or len(chunk_data) != chunk_header["chunk_size"]:
                        self.logger.error(f"块数据不完整，预期: {chunk_header['chunk_size']}，实际: {len(chunk_data)}")
                        return False
                    
                    # 写入文件
                    f.write(chunk_data)
                    received_bytes += len(chunk_data)
                    
                    # 发送确认
                    ack = {
                        "status": "ok",
                        "received": received_bytes
                    }
                    self._send_data(self.socket, json.dumps(ack).encode('utf-8'))
                    
                    # 定期刷新到磁盘
                    if received_bytes % (self.chunk_size * 10) == 0:
                        f.flush()
            
            # 验证文件完整性
            received_hash = self.calculate_file_hash(file_path)
            if received_hash != file_hash:
                self.logger.error(f"文件完整性验证失败，预期哈希: {file_hash}，实际哈希: {received_hash}")
                return False
            
            self.logger.info(f"文件接收成功: {file_path}, 大小: {total_size}字节")
            return True
        
        except Exception as e:
            self.logger.error(f"接收文件失败: {e}")
            return False
    
    def close(self):
        """关闭连接"""
        if self.socket:
            self.socket.close()
            self.connected = False
            self.logger.info("跨系统同步连接已关闭")

class SyncManager:
    """同步管理器类"""
    
    def __init__(self, logger: Logger):
        """初始化同步管理器
        
        Args:
            logger: 日志管理器实例
        """
        self.logger = logger
        self.network_sync = NetworkSync(logger)
        self.sync_config = {}
        
    def set_sync_config(self, config: Dict):
        """设置同步配置
        
        Args:
            config: 同步配置字典
        """
        self.sync_config = config
        self.logger.info(f"设置跨系统同步配置: {config}")
    
    def start_sync(self):
        """开始同步
        
        Returns:
            bool: 同步启动是否成功
        """
        try:
            # 这里需要实现同步逻辑
            self.logger.info("开始跨系统文件同步")
            return True
        except Exception as e:
            self.logger.error(f"开始跨系统文件同步失败: {e}")
            return False
    
    def stop_sync(self):
        """停止同步"""
        try:
            # 这里需要实现停止同步逻辑
            self.logger.info("停止跨系统文件同步")
        except Exception as e:
            self.logger.error(f"停止跨系统文件同步失败: {e}")
    
    def detect_file_changes(self, local_scan: Dict, remote_scan: Dict) -> Tuple[List, List, List]:
        """检测文件变化
        
        Args:
            local_scan: 本地扫描结果
            remote_scan: 远程扫描结果
        
        Returns:
            Tuple[List, List, List]: 新增文件列表、修改文件列表、删除文件列表
        """
        # 转换为相对路径映射，方便比较
        local_rel_map = {}
        remote_rel_map = {}
        
        # 获取同步配置
        local_dir = self.sync_config.get("source_dir", ".")
        remote_dir = self.sync_config.get("target_dir", ".")
        
        # 构建本地相对路径映射
        for item_path, item_info in local_scan.items():
            if item_info["type"] == "file":
                rel_path = os.path.relpath(item_path, local_dir)
                local_rel_map[rel_path] = {
                    "full_path": item_path,
                    "base_dir": local_dir,
                    **item_info
                }
        
        # 构建远程相对路径映射
        for item_path, item_info in remote_scan.items():
            if item_info["type"] == "file":
                rel_path = os.path.relpath(item_path, remote_dir)
                remote_rel_map[rel_path] = {
                    "full_path": item_path,
                    "base_dir": remote_dir,
                    **item_info
                }
        
        # 检测新增文件：本地有，远程没有
        new_files = []
        for rel_path, local_item in local_rel_map.items():
            if rel_path not in remote_rel_map:
                new_files.append({
                    "rel_path": rel_path,
                    "local_item": local_item,
                    "remote_item": None
                })
        
        # 检测修改文件：本地和远程都有，但本地更新
        modified_files = []
        for rel_path, local_item in local_rel_map.items():
            if rel_path in remote_rel_map:
                remote_item = remote_rel_map[rel_path]
                if (local_item["modify_time"] > remote_item["modify_time"] or 
                    local_item["size"] != remote_item["size"]):
                    modified_files.append({
                        "rel_path": rel_path,
                        "local_item": local_item,
                        "remote_item": remote_item
                    })
        
        # 检测删除文件：本地没有，远程有
        deleted_files = []
        for rel_path, remote_item in remote_rel_map.items():
            if rel_path not in local_rel_map:
                deleted_files.append({
                    "rel_path": rel_path,
                    "local_item": None,
                    "remote_item": remote_item
                })
        
        self.logger.info(f"文件变化检测结果: 新增={len(new_files)}, 修改={len(modified_files)}, 删除={len(deleted_files)}")
        return new_files, modified_files, deleted_files
    
    def resolve_conflicts(self, conflicts: List[Dict]) -> List[Dict]:
        """解决文件冲突
        
        Args:
            conflicts: 冲突文件列表，每个冲突项包含本地和远程文件信息
        
        Returns:
            List[Dict]: 冲突解决结果，包含处理方式和保留的文件信息
        """
        resolved_conflicts = []
        
        for conflict in conflicts:
            local_file = conflict.get("local_file")
            remote_file = conflict.get("remote_file")
            
            if not local_file or not remote_file:
                self.logger.error(f"无效的冲突项: {conflict}")
                continue
            
            # 提取相对路径
            local_rel_path = os.path.relpath(local_file["full_path"], local_file["base_dir"])
            remote_rel_path = os.path.relpath(remote_file["full_path"], remote_file["base_dir"])
            
            # 获取冲突解决策略
            resolution = self.sync_config.get("conflict_resolution", "newest")
            result = {
                "local_rel_path": local_rel_path,
                "remote_rel_path": remote_rel_path,
                "local_file": local_file,
                "remote_file": remote_file
            }
            
            try:
                if resolution == "newest":
                    # 最新优先：比较修改时间
                    if local_file["modify_time"] > remote_file["modify_time"]:
                        result["action"] = "keep_local"
                        result["reason"] = f"本地文件更新（本地: {local_file['modify_time']}, 远程: {remote_file['modify_time']}）"
                    else:
                        result["action"] = "keep_remote"
                        result["reason"] = f"远程文件更新（本地: {local_file['modify_time']}, 远程: {remote_file['modify_time']}）"
                
                elif resolution == "largest":
                    # 最大优先：比较文件大小
                    if local_file["size"] > remote_file["size"]:
                        result["action"] = "keep_local"
                        result["reason"] = f"本地文件更大（本地: {local_file['size']}字节, 远程: {remote_file['size']}字节）"
                    else:
                        result["action"] = "keep_remote"
                        result["reason"] = f"远程文件更大（本地: {local_file['size']}字节, 远程: {remote_file['size']}字节）"
                
                elif resolution == "manual":
                    # 手动处理：记录日志，后续可以扩展
                    result["action"] = "manual"
                    result["reason"] = "需要手动处理冲突"
                    self.logger.warning(f"检测到文件冲突，需要手动处理: {local_rel_path}")
                
                else:
                    # 默认使用最新优先
                    if local_file["modify_time"] > remote_file["modify_time"]:
                        result["action"] = "keep_local"
                    else:
                        result["action"] = "keep_remote"
                    result["reason"] = f"使用默认策略（最新优先）"
                
                resolved_conflicts.append(result)
                self.logger.info(f"冲突解决: {result['action']} -> {local_rel_path}, 原因: {result['reason']}")
                
            except Exception as e:
                self.logger.error(f"处理冲突时发生错误: {e}, 冲突项: {conflict}")
                result["action"] = "error"
                result["reason"] = f"处理错误: {e}"
                resolved_conflicts.append(result)
        
        return resolved_conflicts
    
    def detect_conflicts(self, local_scan: Dict, remote_scan: Dict, local_dir: str, remote_dir: str) -> List[Dict]:
        """检测文件冲突
        
        Args:
            local_scan: 本地扫描结果
            remote_scan: 远程扫描结果
            local_dir: 本地文件夹路径
            remote_dir: 远程文件夹路径
        
        Returns:
            List[Dict]: 冲突文件列表
        """
        conflicts = []
        
        # 转换为相对路径映射，方便比较
        local_rel_map = {}
        remote_rel_map = {}
        
        # 构建本地相对路径映射
        for item_path, item_info in local_scan.items():
            if item_info["type"] == "file":
                rel_path = os.path.relpath(item_path, local_dir)
                local_rel_map[rel_path] = {
                    "full_path": item_path,
                    "base_dir": local_dir,
                    **item_info
                }
        
        # 构建远程相对路径映射
        for item_path, item_info in remote_scan.items():
            if item_info["type"] == "file":
                rel_path = os.path.relpath(item_path, remote_dir)
                remote_rel_map[rel_path] = {
                    "full_path": item_path,
                    "base_dir": remote_dir,
                    **item_info
                }
        
        # 检测冲突：本地和远程都有，且都被修改
        for rel_path, local_item in local_rel_map.items():
            if rel_path in remote_rel_map:
                remote_item = remote_rel_map[rel_path]
                
                # 检查是否发生冲突
                # 冲突条件：本地和远程文件都存在，且修改时间不同
                if local_item["modify_time"] != remote_item["modify_time"] and local_item["size"] != remote_item["size"]:
                    conflict = {
                        "local_file": local_item,
                        "remote_file": remote_item,
                        "rel_path": rel_path
                    }
                    conflicts.append(conflict)
                    self.logger.info(f"检测到冲突: {rel_path}, 本地修改时间: {local_item['modify_time']}, 远程修改时间: {remote_item['modify_time']}")
        
        return conflicts
    
    def sync_files(self, new_files: List, modified_files: List, deleted_files: List):
        """同步文件
        
        Args:
            new_files: 新增文件列表
            modified_files: 修改文件列表
            deleted_files: 删除文件列表
        """
        try:
            self.logger.info(f"开始同步文件：新增{len(new_files)}个，修改{len(modified_files)}个，删除{len(deleted_files)}个")
            
            # 获取同步配置
            resume_enabled = self.sync_config.get("resume_enabled", True)
            
            # 处理新增文件
            for item in new_files:
                rel_path = item["rel_path"]
                local_item = item["local_item"]
                
                if local_item:
                    # 发送文件到远程
                    local_path = local_item["full_path"]
                    remote_path = os.path.join(self.sync_config.get("target_dir", "."), rel_path)
                    
                    if self.network_sync.send_file_with_resume(local_path, remote_path, resume_enabled):
                        self.logger.info(f"新增文件同步成功: {rel_path}")
                    else:
                        self.logger.error(f"新增文件同步失败: {rel_path}")
            
            # 处理修改文件
            for item in modified_files:
                rel_path = item["rel_path"]
                local_item = item["local_item"]
                
                if local_item:
                    # 发送文件到远程
                    local_path = local_item["full_path"]
                    remote_path = os.path.join(self.sync_config.get("target_dir", "."), rel_path)
                    
                    if self.network_sync.send_file_with_resume(local_path, remote_path, resume_enabled):
                        self.logger.info(f"修改文件同步成功: {rel_path}")
                    else:
                        self.logger.error(f"修改文件同步失败: {rel_path}")
            
            # 处理删除文件
            for item in deleted_files:
                rel_path = item["rel_path"]
                remote_path = os.path.join(self.sync_config.get("target_dir", "."), rel_path)
                
                # 发送删除请求到远程
                try:
                    request = {
                        "type": "delete_file",
                        "file_path": remote_path
                    }
                    self.network_sync._send_data(self.network_sync.socket, json.dumps(request).encode('utf-8'))
                    
                    # 接收响应
                    response_data = self.network_sync._recv_data(self.network_sync.socket)
                    if response_data:
                        response = json.loads(response_data.decode('utf-8'))
                        if response["status"] == "ok":
                            self.logger.info(f"删除文件成功: {rel_path}")
                        else:
                            self.logger.error(f"删除文件失败: {rel_path}, 原因: {response['message']}")
                    else:
                        self.logger.error(f"删除文件无响应: {rel_path}")
                except Exception as e:
                    self.logger.error(f"发送删除请求失败: {rel_path}, 错误: {e}")
            
            self.logger.info("文件同步完成")
        except Exception as e:
            self.logger.error(f"同步文件时发生错误: {e}")
    
    def resume_sync(self):
        """恢复同步
        
        Returns:
            bool: 恢复同步是否成功
        """
        try:
            self.logger.info("恢复跨系统文件同步")
            # 检查是否有未完成的传输
            breakpoint_files = os.listdir(self.network_sync.breakpoint_dir)
            if breakpoint_files:
                self.logger.info(f"发现{len(breakpoint_files)}个断点文件，将尝试恢复传输")
                
                # 恢复每个断点传输
                for breakpoint_file in breakpoint_files:
                    try:
                        breakpoint_path = os.path.join(self.network_sync.breakpoint_dir, breakpoint_file)
                        with open(breakpoint_path, 'r') as f:
                            breakpoint_data = json.load(f)
                        
                        local_path = breakpoint_data["file_path"]
                        remote_path = breakpoint_data["remote_path"]
                        
                        # 尝试恢复传输
                        self.logger.info(f"尝试恢复传输: {local_path} -> {remote_path}, 偏移量: {breakpoint_data['offset']}/{breakpoint_data['total_size']}")
                        if self.network_sync.send_file_with_resume(local_path, remote_path, True):
                            self.logger.info(f"恢复传输成功: {local_path}")
                        else:
                            self.logger.error(f"恢复传输失败: {local_path}")
                    except Exception as e:
                        self.logger.error(f"处理断点文件{breakpoint_file}时发生错误: {e}")
            
            return True
        except Exception as e:
            self.logger.error(f"恢复跨系统文件同步失败: {e}")
            return False

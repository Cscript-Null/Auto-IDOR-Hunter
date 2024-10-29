# proxy_server/server.py

import socket
import ssl
import threading
import re
import json
import os
import datetime
import tempfile
from io import BytesIO
from urllib.parse import urlparse
from app import models
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from app.database import SessionLocal, engine


class ProxyServer:
    def __init__(self, config_path='patterns.json'):
        self.config_path = config_path
        self.load_config()
        self.server_thread = None
        self.stop_event = threading.Event()
        self.db_session = SessionLocal()

    # def load_config(self):
    #     """加载配置文件，包括监听端口和正则表达式模式"""
    #     try:
    #         with open(self.config_path, 'r', encoding='utf-8') as f:
    #             config = json.load(f)
    #         self.listen_port = config.get('listen_port', 8888)
    #         patterns_raw = config.get('patterns', [])
    #         self.patterns = []
    #         for p in patterns_raw:
    #             pattern_str = p.get('pattern')
    #             description = p.get('description', '')
    #             if pattern_str:
    #                 try:
    #                     compiled = re.compile(pattern_str)
    #                     self.patterns.append({'pattern': compiled, 'description': description, 'raw': pattern_str})
    #                 except re.error as e:
    #                     print(f"编译模式 '{pattern_str}' 时出错: {e}")
    #         self.ca_key_path = config.get('ca_key', 'ca.key')
    #         self.ca_cert_path = config.get('ca_cert', 'ca.crt')
    #         self.database_path = config.get('database', 'matches.db')

    #         # 加载 CA 证书和私钥
    #         with open(self.ca_cert_path, 'rb') as f:
    #             self.ca_cert = f.read()
    #         with open(self.ca_key_path, 'rb') as f:
    #             self.ca_key = serialization.load_pem_private_key(
    #                 f.read(),
    #                 password=None,
    #             )
    #     except Exception as e:
    #         print(f"加载配置文件 '{self.config_path}' 时出错: {e}")
    #         self.listen_port = 8888
    #         self.patterns = []
    #         self.ca_key = None
    #         self.ca_cert = None
    def load_config(self):
        """Load configuration including listening port and regex patterns."""
        # Load other configurations from the config file
        with open(self.config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        Session=SessionLocal()
        # Read listening port
        self.listen_port = config.get('listen_port', 8888)

        # Load regex patterns from both config file and database
        patterns_from_db = Session.query(models.Pattern).all()
        patterns_raw = config.get('patterns', [])
        self.patterns = []
        
        for pattern_entry in patterns_from_db:
            pattern_str = pattern_entry.pattern
            description = pattern_entry.description or ''
            if pattern_str:
                try:
                    compiled = re.compile(pattern_str)
                    self.patterns.append({
                        'pattern': compiled,
                        'description': description,
                        'raw': pattern_str
                    })
                    print(f"Loaded pattern '{pattern_str}' from database.")
                except re.error as e:
                    print(f"Error compiling pattern '{pattern_str}': {e}")
            

        # Read CA certificate and private key paths
        self.ca_key_path = config.get('ca_key', 'ca.key')
        self.ca_cert_path = config.get('ca_cert', 'ca.crt')
        self.database_path = config.get('database', 'matches.db')
        self.save_js = config.get('save_js', False)

        # Load CA certificate
        with open(self.ca_cert_path, 'rb') as f:
            self.ca_cert = f.read()

        # Load CA private key
        with open(self.ca_key_path, 'rb') as f:
            self.ca_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
            )
    def log(self, message):
        """记录日志信息。"""
        print(message)
        self.logs.append(message)

    def get_logs(self):
        """返回当前的日志。"""
        return self.logs

    def get_config(self):
        """返回当前的配置。"""
        with open(self.config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        return config
    def start(self):
        """启动代理服务器"""
        if self.server_thread and self.server_thread.is_alive():
            print("代理服务器已在运行。")
            return

        self.stop_event.clear()
        self.server_thread = threading.Thread(target=self.run_server, daemon=True)
        self.server_thread.start()
        print(f"代理服务器已启动，监听端口 {self.listen_port}.")
        address = socket.gethostbyname(socket.gethostname())
        return address, self.listen_port

    def stop(self):
        """停止代理服务器"""
        if not self.server_thread:
            print("代理服务器未启动。")
            return
        self.stop_event.set()
        self.server_thread.join()
        print("代理服务器已停止。")
    
    def get_status(self):
        """获取代理服务器的当前状态"""
        if self.server_thread and self.server_thread.is_alive():
            address = socket.gethostbyname(socket.gethostname())
            return {"running": True, "address": address, "port": self.listen_port}
        else:
            return {"running": False}


    def run_server(self):
        """运行代理服务器的主循环"""
        HOST, PORT = '0.0.0.0', self.listen_port

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((HOST, PORT))
        server.listen(100)
        print(f"代理服务器运行在 {HOST}:{PORT}")

        while not self.stop_event.is_set():
            try:
                server.settimeout(1.0)  # 设置超时以定期检查停止事件
                client_socket, client_address = server.accept()
                print(f"接受来自 {client_address} 的连接")
                handler = ProxyThread(
                    client_socket=client_socket,
                    client_address=client_address,
                    ca_cert=self.ca_cert,
                    ca_key=self.ca_key,
                    patterns=self.patterns
                )
                handler.daemon = True
                handler.start()
            except socket.timeout:
                continue
            except Exception as e:
                print(f"服务器错误: {e}")
                break

        server.close()

    def reload_config(self):
        """重新加载配置文件"""
        self.load_config()
        print("配置文件已重新加载。")


class ProxyThread(threading.Thread):
    """
    代理处理线程，负责处理单个客户端连接。
    """
    def __init__(self, client_socket, client_address, ca_cert, ca_key, patterns):
        super().__init__()
        self.client_socket = client_socket
        self.client_address = client_address
        self.ca_cert = ca_cert
        self.ca_key = ca_key
        self.patterns = patterns

    def run(self):
        try:
            request = self.client_socket.recv(65535)
            if not request:
                self.client_socket.close()
                return

            # 解析请求行
            request_line = request.split(b'\n')[0].decode(errors='ignore')
            parts = request_line.split()
            if len(parts) != 3:
                print(f"[{self.client_address}] 无法解析请求行: {request_line}")
                self.client_socket.close()
                return

            method, path, version = parts

            if method.upper() == 'CONNECT':
                # 处理 HTTPS 请求
                self.handle_connect(path)
            else:
                # 处理 HTTP 请求
                self.handle_http(request, method, path, version)
        except Exception as e:
            print(f"[{self.client_address}] Error: {e}")
        finally:
            self.client_socket.close()

    def handle_http(self, request, method, path, version):
        """
        处理 HTTP 请求。
        """
        try:
            # 解析目标主机和端口
            parsed = urlparse(path)
            host = parsed.hostname
            port = parsed.port or 80
            path = parsed.path or '/'
            if parsed.query:
                path += '?' + parsed.query

            # 建立与目标服务器的连接
            with socket.create_connection((host, port)) as remote:
                # 转发请求
                # 重新构造请求行
                request_line = f"{method} {path} {version}\r\n".encode()
                # 重新构造头部
                headers = b''
                for line in request.split(b'\n')[1:]:
                    if line.strip() == b'':
                        break
                    headers += line + b'\n'
                request_rebuilt = request_line + headers + b'\r\n'
                remote.sendall(request_rebuilt)

                # 转发剩余数据（请求体）
                body = request.split(b'\r\n\r\n', 1)
                if len(body) == 2:
                    remote.sendall(body[1])
                
                
                # 接收响应
                response = b""
                while True:
                    data = remote.recv(4096)
                    if not data:
                        break
                    response += data

            # 匹配正则表达式
            send_text = body[1].decode('utf-8', errors='ignore')
            
            for p in self.patterns:
                if p['pattern'].search(send_text):
                    print(f"[{self.client_address}] 响应匹配成功 (模式: {p['pattern'].pattern})")
                    self.save_match_to_db(p['description'].description, send_text)# 在这里可以添加自定义处理逻辑
                    break
            # 将响应返回给客户端
            self.client_socket.sendall(response)
        except Exception as e:
            print(f"[{self.client_address}] HTTP 处理错误: {e}")

    def save_match_to_db(self, pattern_description, matched_data, cookie_credential_id=None):
        session = SessionLocal()
        try:
            # 检查是否已经存在相同的 matched_data
            existing_match = session.query(models.ProcessedMatch).filter_by(matched_data=pattern_description).first()

            if existing_match:
                print(f"[{self.client_address}] 匹配记录已存在，保存新的响应到响应历史表")
                # 如果匹配记录已存在，保存新的响应到 ResponseHistory 表
                response_history = models.ResponseHistory(
                    processed_match_id=existing_match.id,
                    response="",
                    cookie_credential_id=cookie_credential_id,  # 关联 CookieCredential
                    timestamp=datetime.datetime.now()  # 设置当前时间戳
                )
                session.add(response_history)
            else:
                # 创建新的匹配记录
                match = models.ProcessedMatch(
                    matched_data=matched_data,
                    pattern_description=pattern_description,
                    user_cookie_id=cookie_credential_id  # 关联 CookieCredential
                )
                session.add(match)
                session.flush()  # 确保 match.id 可用

                # 保存新的响应到 ResponseHistory 表
                response_history = models.ResponseHistory(
                    processed_match_id=match.id,
                    response="",
                    cookie_credential_id=cookie_credential_id,  # 关联 CookieCredential
                    timestamp=datetime.datetime.now() # 设置当前时间戳
                )
                session.add(response_history)

            session.commit()
            print(f"[{self.client_address}] 匹配记录和响应已保存到数据库")
        except Exception as e:
            session.rollback()
            print(f"[{self.client_address}] 保存匹配记录时发生错误: {e}")
        finally:
            session.close()

    def handle_connect(self, path):
        """
        处理 HTTPS CONNECT 请求。
        """
        try:
            hostname, port = path.split(':')
            port = int(port)

            # 建立与目标服务器的连接
            remote_socket = socket.create_connection((hostname, port))

            # 通知客户端已建立连接
            self.client_socket.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')

            # 动态生成并加载证书
            cert_pem, key_pem = generate_cert(hostname, self.ca_cert, self.ca_key)

            # 将证书和私钥写入临时文件
            with tempfile.NamedTemporaryFile(delete=False) as cert_file:
                cert_file.write(cert_pem)
                cert_file_path = cert_file.name

            with tempfile.NamedTemporaryFile(delete=False) as key_file:
                key_file.write(key_pem)
                key_file_path = key_file.name

            try:
                # 创建 SSL 上下文
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(certfile=cert_file_path, keyfile=key_file_path)

                # 将客户端套接字升级为 SSL
                ssl_client_socket = context.wrap_socket(self.client_socket, server_side=True)

                # 与目标服务器建立 SSL 连接
                context_server = ssl.create_default_context()
                ssl_remote = context_server.wrap_socket(remote_socket, server_hostname=hostname)

                # 启动双向转发
                self.forward_data(ssl_client_socket, ssl_remote)
            finally:
                # 删除临时文件
                os.remove(cert_file_path)
                os.remove(key_file_path)
        except Exception as e:
            print(f"[{self.client_address}] CONNECT 处理错误: {e}")

    def forward_data(self, client, remote):
        """
        双向转发数据，并进行正则匹配。
        """
        try:
            # 启动两个线程分别处理客户端到远程和远程到客户端
            t1 = threading.Thread(target=self.forward_one_direction, args=(client, remote, "客户端 -> 服务器"))
            t2 = threading.Thread(target=self.forward_one_direction, args=(remote, client, "服务器 -> 客户端"))
            t1.start()
            t2.start()
            t1.join()
            t2.join()
        except Exception as e:
            print(f"[{self.client_address}] 转发数据错误: {e}")
        finally:
            client.close()
            remote.close()

    def forward_one_direction(self, source, destination, direction):
        """
        转发单个方向的数据，并进行正则匹配。
        """
        try:
            while True:
                data = source.recv(4096)
                if not data:
                    break

                # 可以在这里添加对数据的处理
                data_text = data.decode('utf-8', errors='ignore')
                for p in self.patterns:
                    # print('正在匹配')
                    if p['pattern'].search(data_text):
                        print(f"[{self.client_address}] {direction} 数据匹配成功 (模式: {p['pattern'].pattern})")
                        self.save_match_to_db(p['description'],data_text)# 在这里可以添加自定义处理逻辑
                        break

                destination.sendall(data)
        except Exception as e:
            print(f"[{self.client_address}] {direction} 方向转发错误: {e}")


def generate_cert(hostname, ca_cert, ca_key):
    """
    为指定主机名生成证书，并由 CA 签名。
    返回证书和私钥的 PEM 格式（字节）。
    """
    # 生成私钥
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # 加载 CA 证书
    ca_cert_obj = x509.load_pem_x509_certificate(ca_cert)

    # 构建证书主体信息
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"您的省份"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"您的城市"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"您的组织"),
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])

    # 构建证书
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert_obj.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]),
            critical=False,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    # 序列化证书和私钥
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )

    return cert_pem, key_pem

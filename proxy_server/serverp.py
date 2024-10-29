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

blacklist = [
    # ... [保持不变]
    # Add any additional extensions as needed
]


class ProxyServer:
    def __init__(self, config_path='patterns.json'):
        self.config_path = config_path
        self.server_thread = None
        self.stop_event = threading.Event()
        self.logs = []
        self.load_config()

    def load_config(self):
        """加载配置，包括监听端口和正则模式。"""
        with open(self.config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        Session = SessionLocal()
        # 读取监听端口
        self.listen_port = config.get('listen_port', 8888)

        # 从配置文件和数据库加载正则模式
        patterns_from_db = Session.query(models.Pattern).all()
        patterns_raw = config.get('patterns', [])
        self.patterns = []

        # 从配置文件加载模式
        for p in patterns_raw:
            pattern_str = p.get('pattern')
            description = p.get('description', '')
            if pattern_str:
                try:
                    compiled = re.compile(pattern_str, re.IGNORECASE)
                    self.patterns.append({'pattern': compiled, 'description': description, 'raw': pattern_str})
                except re.error as e:
                    self.log(f"Error compiling pattern '{pattern_str}': {e}")

        # 从数据库加载模式
        for pattern_entry in patterns_from_db:
            pattern_str = pattern_entry.pattern
            description = pattern_entry.description or ''
            if pattern_str:
                try:
                    compiled = re.compile(pattern_str, re.IGNORECASE)
                    self.patterns.append({
                        'pattern': compiled,
                        'description': description,
                        'raw': pattern_str
                    })
                    self.log(f"Loaded pattern '{pattern_str}' from database.")
                except re.error as e:
                    self.log(f"Error compiling pattern '{pattern_str}': {e}")

        # 读取 CA 证书和私钥路径
        self.ca_key_path = config.get('ca_key', 'ca.key')
        self.ca_cert_path = config.get('ca_cert', 'ca.crt')
        self.database_path = config.get('database', 'matches.db')
        self.save_js = config.get('save_js', False)

        # 加载 CA 证书
        with open(self.ca_cert_path, 'rb') as f:
            self.ca_cert = f.read()

        # 加载 CA 私钥
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
        """启动代理服务器。"""
        if self.server_thread and self.server_thread.is_alive():
            self.log("Proxy server is already running.")
            return

        self.stop_event.clear()
        self.server_thread = threading.Thread(target=self.run_server, daemon=True)
        self.server_thread.start()
        self.log(f"Proxy server started, listening on port {self.listen_port}.")
        address = socket.gethostbyname(socket.gethostname())
        return address, self.listen_port

    def stop(self):
        """停止代理服务器。"""
        if not self.server_thread:
            self.log("Proxy server is not running.")
            return
        self.stop_event.set()
        self.server_thread.join()
        self.log("Proxy server stopped.")

    def get_status(self):
        """获取代理服务器的当前状态。"""
        if self.server_thread and self.server_thread.is_alive():
            address = socket.gethostbyname(socket.gethostname())
            return {"running": True, "address": address, "port": self.listen_port}
        else:
            return {"running": False}

    def run_server(self):
        """运行代理服务器的主循环。"""
        HOST, PORT = '0.0.0.0', self.listen_port

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((HOST, PORT))
        server.listen(100)
        self.log(f"Proxy server running on {HOST}:{PORT}")

        while not self.stop_event.is_set():
            try:
                server.settimeout(1.0)  # 超时以定期检查停止事件
                client_socket, client_address = server.accept()
                self.log(f"Accepted connection from {client_address}")
                handler = ProxyThread(
                    client_socket=client_socket,
                    client_address=client_address,
                    ca_cert=self.ca_cert,
                    ca_key=self.ca_key,
                    patterns=self.patterns,
                    save_js=self.save_js
                )
                handler.daemon = True
                handler.start()
            except socket.timeout:
                continue
            except Exception as e:
                self.log(f"Server error: {e}")
                break
        server.close()

    def reload_config(self):
        """重新加载配置文件。"""
        self.load_config()
        self.log("Configuration file reloaded.")


class ProxyThread(threading.Thread):
    """
    代理处理线程，负责处理单个客户端连接。
    """
    def __init__(self, client_socket, client_address, ca_cert, ca_key, patterns, save_js):
        super().__init__()
        self.client_socket = client_socket
        self.client_address = client_address
        self.ca_cert = ca_cert
        self.ca_key = ca_key
        self.patterns = patterns
        self.save_js = save_js  # 修复：使用传入的 save_js 参数
        self.logs = []

    def log(self, message):
        """记录日志信息。"""
        print(message)
        self.logs.append(message)

    def get_logs(self):
        """返回当前的日志。"""
        return self.logs

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
                self.log(f"[{self.client_address}] Couldn't parse request line: {request_line}")
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
            self.log(f"[{self.client_address}] Error: {e}")
        finally:
            self.client_socket.close()

    def handle_http(self, request, method, path, version):
        """
        处理 HTTP 请求。
        """
        # 解析目标主机和端口
        parsed = urlparse(path)
        host = parsed.hostname
        port = parsed.port or 80
        path = parsed.path or '/'
        _, file_extension = os.path.splitext(path)
        if parsed.query:
            path += '?' + parsed.query

        try:
            # 建立与目标服务器的连接
            with socket.create_connection((host, port)) as remote:
                # 转发请求到远程服务器
                # 重构请求行
                request_line = f"{method} {path} {version}\r\n".encode()
                # 重构头部
                headers = b''
                for line in request.split(b'\n')[1:]:
                    if line.strip() == b'':
                        break
                    headers += line + b'\n'
                request_rebuilt = request_line + headers + b'\r\n'
                remote.sendall(request_rebuilt)

                # 转发剩余的数据（请求体）
                body = request.split(b'\r\n\r\n', 1)
                if len(body) == 2:
                    remote.sendall(body[1])

                # 接收远程服务器的响应
                response = b""
                while True:
                    data = remote.recv(4096)
                    if not data:
                        break
                    response += data

                # 将响应返回给客户端
                self.client_socket.sendall(response)

                # 解析响应的头部
                response_headers, _, response_body = response.partition(b'\r\n\r\n')
                headers_text = response_headers.decode(errors='ignore')
                lines = headers_text.split('\r\n')
                status_line = lines[0]
                status_parts = status_line.split()
                if len(status_parts) < 2:
                    status_code = None
                else:
                    status_code = status_parts[1]

                headers = self.parse_headers(headers_text)
                content_type = headers.get('Content-Type', '')

                # 检查是否是JavaScript文件
                is_js = False
                if file_extension.lower() == '.js' and self.save_js:
                    is_js = True

                if is_js:
                    self.log(f"[{self.client_address}] JavaScript file detected: {path} from {host}")
                    try:
                        js_content = response_body.decode('utf-8', errors='ignore')
                        self.save_js_file(host, path, js_content)
                    except UnicodeDecodeError:
                        self.log(f"[{self.client_address}] Failed to decode JS content from {path}")

                # 解析响应体以进行模式匹配
                try:
                    send_text = response_body.decode('utf-8', errors='ignore')
                except UnicodeDecodeError:
                    send_text = ''

                # 判断响应是否成功并检查文件扩展名
                if status_code and status_code.startswith('2') and (file_extension.lower() not in blacklist):
                    if 'session=' in send_text:
                        self.save_match_to_db('响应匹配成功: session=存在', send_text)
                    for p in self.patterns:
                        if p['pattern'].search(send_text):
                            self.log(f"[{self.client_address}] 响应匹配成功 (模式: {p['pattern'].pattern})")
                            self.save_match_to_db(p['description'], send_text)  # 自定义处理逻辑
                            break

        except Exception as e:
            self.log(f"[{self.client_address}] Error: {e}")
        finally:
            self.client_socket.close()

    def parse_headers(self, headers_text):
        """
        解析 HTTP 头部到字典。
        """
        headers = {}
        for line in headers_text.split('\r\n')[1:]:  # 跳过状态行
            if ': ' in line:
                key, value = line.split(': ', 1)
                headers[key] = value
        return headers

    def save_js_file(self, host, path, content):
        """
        将拦截的 JavaScript 文件保存到数据库。
        """
        session = SessionLocal()
        try:
            js_file = models.JSFile(
                host=host,
                path=path,
                content=content,
                timestamp=datetime.datetime.now()
            )
            session.add(js_file)
            session.commit()
            self.log(f"[{self.client_address}] Saved JS file: {host}{path}")
        except Exception as e:
            session.rollback()
            self.log(f"[{self.client_address}] Error saving JS file: {e}")
        finally:
            session.close()

    def save_match_to_db(self, pattern_description, matched_data, cookie_credential_id=None):
        session = SessionLocal()
        try:
            # 修复：检查是否已经存在相同的 matched_data
            existing_match = session.query(models.ProcessedMatch).filter_by(matched_data=matched_data).first()

            if existing_match:
                self.log(f"[{self.client_address}] 匹配记录已存在，保存新的响应到响应历史表")
                # 如果匹配记录已存在，保存新的响应到 ResponseHistory 表
                response_history = models.ResponseHistory(
                    processed_match_id=existing_match.id,
                    response=pattern_description,  # 假设保存描述信息
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
                    response=pattern_description,
                    cookie_credential_id=cookie_credential_id,  # 关联 CookieCredential
                    timestamp=datetime.datetime.now()  # 设置当前时间戳
                )
                session.add(response_history)

            session.commit()
            self.log(f"[{self.client_address}] 匹配记录和响应已保存到数据库")
        except Exception as e:
            session.rollback()
            self.log(f"[{self.client_address}] 保存匹配记录时发生错误: {e}")
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

            # 通知客户端连接已建立
            self.client_socket.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')

            # 动态生成并加载证书
            cert_pem, key_pem = generate_cert(hostname, self.ca_cert, self.ca_key)

            # 写入临时文件
            with tempfile.NamedTemporaryFile(delete=False) as cert_file:
                cert_file.write(cert_pem)
                cert_file_path = cert_file.name

            with tempfile.NamedTemporaryFile(delete=False) as key_file:
                key_file.write(key_pem)
                key_file_path = key_file.name

            try:
                # 创建客户端 SSL 上下文
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(certfile=cert_file_path, keyfile=key_file_path)

                # 将客户端套接字升级为 SSL
                ssl_client_socket = context.wrap_socket(self.client_socket, server_side=True)

                # 创建服务器端 SSL 上下文
                context_server = ssl.create_default_context()
                ssl_remote = context_server.wrap_socket(remote_socket, server_hostname=hostname)

                # 开始双向转发
                self.forward_data(ssl_client_socket, ssl_remote, hostname)
            finally:
                # 删除临时证书文件
                os.remove(cert_file_path)
                os.remove(key_file_path)
        except Exception as e:
            self.log(f"[{self.client_address}] CONNECT handling error: {e}")

    def forward_data(self, client, remote, hostname):
        """
        双向转发客户端和远程服务器的数据。
        """
        try:
            # 启动两个线程处理双向数据转发
            t1 = threading.Thread(target=self.forward_one_direction_https, args=(client, remote, "Client -> Server", hostname))
            t2 = threading.Thread(target=self.forward_one_direction_https, args=(remote, client, "Server -> Client", hostname))
            t1.start()
            t2.start()
            t1.join()
            t2.join()
        except Exception as e:
            self.log(f"[{self.client_address}] Data forwarding error: {e}")
        finally:
            client.close()
            remote.close()

    def forward_one_direction_https(self, source, destination, direction, hostname):
        """
        双向转发 HTTPS 数据，同时检测 JavaScript。
        """
        try:
            buffer = b''
            while True:
                data = source.recv(4096)
                if not data:
                    break

                buffer += data
                # 尝试解析 HTTP 响应头部
                if direction == "Server -> Client":
                    if b'\r\n\r\n' in buffer:
                        header_part, _, body_part = buffer.partition(b'\r\n\r\n')
                        headers_text = header_part.decode(errors='ignore')
                        headers = self.parse_headers(headers_text)
                        content_type = headers.get('Content-Type', '')

                        # 判断是否为 JavaScript 文件
                        is_js = False
                        if 'javascript' in content_type.lower() and self.save_js:
                            is_js = True

                        if is_js:
                            self.log(f"[{self.client_address}] JavaScript file detected via HTTPS from {hostname}")
                            try:
                                js_content = body_part.decode('utf-8', errors='ignore')
                                self.save_js_file(hostname, 'Unknown (HTTPS)', js_content)
                            except UnicodeDecodeError:
                                self.log(f"[{self.client_address}] Failed to decode JS content via HTTPS from {hostname}")
                else:
                    # 对于 "Client -> Server" 方向，可以添加更多处理逻辑
                    pass

                # 检查并进行模式匹配
                try:
                    send_text = buffer.decode('utf-8', errors='ignore')
                except UnicodeDecodeError:
                    send_text = ''

                if "200 OK" not in send_text and '/' not in send_text:
                    if 'session=' in send_text:
                        self.save_match_to_db("响应匹配成功: session=存在", send_text)
                    for p in self.patterns:
                        if p['pattern'].search(send_text):
                            self.log(f"[{self.client_address}] 响应匹配成功 (模式: {p['pattern'].pattern})")
                            self.save_match_to_db(p['description'], send_text)  # 自定义处理逻辑
                            break

                # 转发数据
                destination.sendall(data)
        except Exception as e:
            self.log(f"[{self.client_address}] {direction} forwarding error: {e}")

    def save_js_file_https(self, host, path, content):
        """
        将拦截的 HTTPS JavaScript 文件保存到数据库。
        """
        session = SessionLocal()
        try:
            js_file = models.JSFile(
                host=host,
                path=path,
                content=content,
                timestamp=datetime.datetime.now()
            )
            session.add(js_file)
            session.commit()
            self.log(f"[{self.client_address}] Saved JS file via HTTPS from {host}")
        except Exception as e:
            session.rollback()
            self.log(f"[{self.client_address}] Error saving JS file via HTTPS: {e}")
        finally:
            session.close()


def generate_cert(hostname, ca_cert, ca_key):
    """
    为指定的主机名生成由 CA 签名的证书。
    返回 PEM 格式的证书和私钥（字节）。
    """
    # 生成私钥
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # 加载 CA 证书
    ca_cert_obj = x509.load_pem_x509_certificate(ca_cert)

    # 构建证书主题
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"YourState"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"YourCity"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"YourOrganization"),
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

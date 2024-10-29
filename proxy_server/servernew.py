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
    # HTML & Markup
    '.html', '.htm',

    # Images
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff', '.tif', '.webp', '.svg', 
    '.svgz', '.ico', '.avif', '.heic',

    # Stylesheets
    '.css', '.less', '.sass', '.scss',

    # Fonts
    '.woff', '.woff2', '.ttf', '.otf', '.eot', '.ttc',

    # Audio
    '.mp3', '.wav', '.ogg', '.aac', '.flac', '.m4a', '.mid', '.midi',

    # Video
    '.mp4', '.webm', '.ogv', '.avi', '.mkv', '.mov', '.flv', '.swf', '.mpeg', 
    '.mpg', '.3gp',

    # Documents
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', 
    '.csv', '.md', '.rtf',

    # Archives
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.iso', '.dmg', '.img',

    # Executables & Scripts
    '.exe', '.dll', '.bin', '.deb', '.rpm', '.msi', '.sh', '.bat', '.py', 
    '.rb',

    # Data Formats
    '.json', '.xml', '.yaml', '.yml', '.csv',

    # Source Maps & Configurations
    '.map', '.env', '.config', '.ini', '.log',

    # 3D Models & Graphics
    '.obj', '.fbx', '.glsl', '.blend', '.dae',

    # Templates
    '.ejs', '.hbs', '.handlebars', '.twig', '.jade',

    # Miscellaneous
    '.psd', '.ai', '.eps', '.dxf', '.dwg', '.manifest', '.webmanifest',
    '.LICENSE', '.LICENSE.txt', '/'

    # Add any additional extensions as needed
]


class ProxyServer:
    def __init__(self, config_path='patterns.json'):
        self.config_path = config_path
        self.server_thread = None
        self.stop_event = threading.Event()
        self.logs=[]
        self.load_config()

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
        
        # Load patterns from config file
        for p in patterns_raw:
            pattern_str = p.get('pattern')
            description = p.get('description', '')
            if pattern_str:
                try:
                    compiled = re.compile(pattern_str)
                    self.patterns.append({'pattern': compiled, 'description': description, 'raw': pattern_str})
                except re.error as e:
                    self.log(f"Error compiling pattern '{pattern_str}': {e}")
        
        # Load patterns from database
            for pattern_entry in patterns_from_db:
                pattern_str = pattern_entry.pattern
                description = pattern_entry.description or ''
                if pattern_str:
                    try:
                        # 检查模式是否以 "/i" 结尾，表示忽略大小写
                        if pattern_str.endswith('"i') or pattern_str.endswith("'i"):
                            pattern_str = pattern_str[:-2]  # 移除末尾的 "i
                            compiled = re.compile(pattern_str, re.IGNORECASE)
                        else:
                            compiled = re.compile(pattern_str)
                        
                        self.patterns.append({
                            'pattern': compiled,
                            'description': description,
                            'raw': pattern_str
                        })
                        self.log(f"Loaded pattern '{pattern_str}' from database.")
                    except re.error as e:
                        self.log(f"Error compiling pattern '{pattern_str}': {e}")
                

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
        """Start the proxy server."""
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
        """Stop the proxy server."""
        if not self.server_thread:
            self.log("Proxy server is not running.")
            return
        self.stop_event.set()
        self.server_thread.join()
        self.log("Proxy server stopped.")
    
    def get_status(self):
        """Get the current status of the proxy server."""
        if self.server_thread and self.server_thread.is_alive():
            address = socket.gethostbyname(socket.gethostname())
            return {"running": True, "address": address, "port": self.listen_port}
        else:
            return {"running": False}


    def run_server(self):
        """Main loop to run the proxy server."""
        HOST, PORT = '0.0.0.0', self.listen_port

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((HOST, PORT))
        server.listen(100)
        self.log(f"Proxy server running on {HOST}:{PORT}")

        while not self.stop_event.is_set():
            try:
                server.settimeout(1.0)  # Timeout to periodically check stop event
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
        self.log(handler.get_logs())
        server.close()

    def reload_config(self):
        """Reload the configuration file."""
        self.load_config()
        self.log("Configuration file reloaded.")


class ProxyThread(threading.Thread):
    """
    Proxy handling thread, responsible for handling a single client connection.
    """
    def __init__(self, client_socket, client_address, ca_cert, ca_key, patterns, save_js):
        super().__init__()
        self.client_socket = client_socket
        self.client_address = client_address
        self.ca_cert = ca_cert
        self.ca_key = ca_key
        self.patterns = patterns
        self.save_js = True
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
            send_text = request.decode('UTF-8',errors='ignore')
            if True:
                    # print(send_text)
                    for p in self.patterns:
                        if p['pattern'].search(send_text,re.I):
                            self.log(f"[{self.client_address}] 响应匹配成功 (模式: {p['pattern'].pattern})")
                            try:
                                self.save_match_to_db(p['description'], send_text)  # 自定义处理逻辑
                            except Exception as e:
                                self.log(f"[{self.client_address}] 数据库已存在: {e}")

            # Parse request line
            request_line = request.split(b'\n')[0].decode(errors='ignore')
            parts = request_line.split()
            if len(parts) != 3:
                self.log(f"[{self.client_address}] Couldn't parse request line: {request_line}")
                self.client_socket.close()
                return

            method, path, version = parts

            if method.upper() == 'CONNECT':
                # Handle HTTPS request
                self.handle_connect(path)
            else:
                # Handle HTTP request
                self.handle_http(request, method, path, version)
        except Exception as e:
            self.log(f"[{self.client_address}] Error: {e}")
        finally:
            self.client_socket.close()

    def handle_http(self, request, method, path, version):
        """
        Handle HTTP requests.
        """
        
        # Parse target host and port
        parsed = urlparse(path)
        host = parsed.hostname
        port = parsed.port or 80
        path = parsed.path or '/'
        _, file_extension = os.path.splitext(path)
        if parsed.query:
            path += '?' + parsed.query

        try:
            # Establish connection to the target server
            with socket.create_connection((host, port)) as remote:
                # Forward the request to the remote server
                # Reconstruct request line
                request_line = f"{method} {path} {version}\r\n".encode()
                # Reconstruct headers
                headers = b''
                for line in request.split(b'\n')[1:]:
                    if line.strip() == b'':
                        break
                    headers += line + b'\n'
                request_rebuilt = request_line + headers + b'\r\n'
                remote.sendall(request_rebuilt)

                # Forward remaining data (request body)
                body = request.split(b'\r\n\r\n', 1)
                if len(body) == 2:
                    remote.sendall(body[1])

                # **接收远程服务器的响应**
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
                headers = self.parse_headers(headers_text)
                content_type = headers.get('Content-Type', '')

                # 检查是否是JavaScript文件
                is_js = False
                if path.lower().endswith('.js') and self.save_js:
                    is_js = True

                if is_js:
                    self.log(f"[{self.client_address}] JavaScript file detected: {path} from {host}")
                    js_content = response_body.decode('utf-8', errors='ignore')
                    self.save_js_file(host, path, js_content)
                # send_text = b.decode('utf-8',errors='ignore')
                # 正则匹配内容（如果需要）
                send_text = response_body.decode('utf-8', errors='ignore')
                # if ("200 OK" not in send_text) and (file_extension not in blacklist):
                # if True:
                #     print(send_text)
                #     if 'session=' in send_text:
                #         self.save_match_to_db('响应匹配成功', send_text)
                #     for p in self.patterns:
                #         if p['pattern'].search(send_text,re.I):
                #             self.log(f"[{self.client_address}] 响应匹配成功 (模式: {p['pattern'].pattern})")
                #             self.save_match_to_db(p['description'], send_text)  # 自定义处理逻辑
                #             break

        except Exception as e:
            self.log(f"[{self.client_address}] Error: {e}")
        finally:
            self.client_socket.close()

        

    def parse_headers(self, headers_text):
        """
        Parse HTTP headers into a dictionary.
        """
        headers = {}
        for line in headers_text.split('\r\n')[1:]:  # Skip the status line
            if ': ' in line:
                key, value = line.split(': ', 1)
                headers[key] = value
        return headers

    def save_js_file(self, host, path, content):
        """
        Save the intercepted JavaScript file to the database.
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
            # 检查是否已经存在相同的 matched_data
            existing_match = session.query(models.ProcessedMatch).filter_by(matched_data=pattern_description).first()

            if existing_match:
                self.log(f"[{self.client_address}] 匹配记录已存在，保存新的响应到响应历史表")
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
            self.log(f"[{self.client_address}] 匹配记录和响应已保存到数据库")
        except Exception as e:
            session.rollback()
            self.log(f"[{self.client_address}] 保存匹配记录时发生错误: {e}")
        finally:
            session.close()

    def handle_connect(self, path):
        """
        Handle HTTPS CONNECT requests.
        """
        try:
            hostname, port = path.split(':')
            port = int(port)

            # Establish connection to the target server
            remote_socket = socket.create_connection((hostname, port))

            # Notify the client that the connection has been established
            self.client_socket.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')

            # Dynamically generate and load certificate
            cert_pem, key_pem = generate_cert(hostname, self.ca_cert, self.ca_key)

            # Write certificate and key to temporary files
            with tempfile.NamedTemporaryFile(delete=False) as cert_file:
                cert_file.write(cert_pem)
                cert_file_path = cert_file.name

            with tempfile.NamedTemporaryFile(delete=False) as key_file:
                key_file.write(key_pem)
                key_file_path = key_file.name

            try:
                # Create SSL context for the client side
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(certfile=cert_file_path, keyfile=key_file_path)

                # Upgrade the client socket to SSL
                ssl_client_socket = context.wrap_socket(self.client_socket, server_side=True)

                # Create SSL context for the server side
                context_server = ssl.create_default_context()
                ssl_remote = context_server.wrap_socket(remote_socket, server_hostname=hostname)

                # Start bidirectional forwarding
                self.forward_data(ssl_client_socket, ssl_remote, hostname)
            finally:
                # Remove temporary certificate files
                os.remove(cert_file_path)
                os.remove(key_file_path)
        except Exception as e:
            self.log(f"[{self.client_address}] CONNECT handling error: {e}")

    def forward_data(self, client, remote, hostname):
        """
        Bidirectional forwarding of data between client and remote server.
        """
        try:
            # Start two threads to handle both directions
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
        Forward data in one direction for HTTPS, with JavaScript detection.
        """
        try:
            buffer = b''
            while True:
                data = source.recv(4096)
                if not data:
                    break

                buffer += data
                # Attempt to parse HTTP response if direction is Server -> Client
                if direction == "Server -> Client":
                    
                    if b'\r\n\r\n' in buffer:
                        header_part, _, body_part = buffer.partition(b'\r\n\r\n')
                        headers_text = header_part.decode(errors='ignore')
                        headers = self.parse_headers(headers_text)
                        content_type = headers.get('Content-Type', '')
                        
                        # Determine if the response is a JavaScript file
                        is_js = False
                        if ('javascript' in content_type.lower() or hostname.lower().endswith('.js')) and self.save_js:
                            is_js = True

                        if is_js:
                            self.log(f"[{self.client_address}] JavaScript file detected via HTTPS from {hostname}")
                            self.save_js_file_https(hostname, destination, body_part)
                else:
                    header_part, _, body_part = buffer.partition(b'\r\n\r\n')
                    headers_text = header_part.decode(errors='ignore')
                    request_line = headers_text.splitlines()[0]
                    method, path, _ = request_line.split()
                    parsed = urlparse(path)
                    host = parsed.hostname
                    port = parsed.port or 80
                    path = parsed.path or '/'
                    _, file_extension = os.path.splitext(path)
                    
                    # if ("200 OK" not in send_text) and (file_extension not in blacklist):
                    # if True:
                    #     print(b)
                    #     if 'session' in send_text:
                    #         self.save_match_to_db("响应匹配成功", send_text)
                    #     for p in self.patterns:
                    #         # self.log("check!")
                    #         if p['pattern'].search(send_text):
                    #             self.log(f"[{self.client_address}] 响应匹配成功 (模式: {p['pattern'].pattern})")
                    #             self.save_match_to_db(p['description'], send_text)# 在这里可以添加自定义处理逻辑
                    #             break

                # Forward the data
                destination.sendall(data)
        except Exception as e:
            self.log(f"[{self.client_address}] {direction} forwarding error: {e}")

    def save_js_file_https(self, host, destination, content):
        """
        Save the intercepted JavaScript file from HTTPS to the database.
        """
        session = SessionLocal()
        try:
            js_file = models.JSFile(
                host=host,
                path='Unknown (HTTPS)',  # Parsing exact path requires more sophisticated handling
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
    Generate a certificate for the specified hostname, signed by the CA.
    Returns the certificate and private key in PEM format (bytes).
    """
    # Generate private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Load CA certificate
    ca_cert_obj = x509.load_pem_x509_certificate(ca_cert)

    # Build certificate subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"YourState"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"YourCity"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"YourOrganization"),
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])

    # Build certificate
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

    # Serialize certificate and private key
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )

    return cert_pem, key_pem
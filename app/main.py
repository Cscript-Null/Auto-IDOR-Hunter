# app/main.py

import logging
import socket
from sqlite3 import IntegrityError
import ssl
from urllib.parse import urlparse
from fastapi import BackgroundTasks, Depends, FastAPI, Request, Form,HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func
from . import models
from .database import SessionLocal, engine
import json
import os
import subprocess
from typing import List
from pydantic import BaseModel
import datetime
from . import jsparse
from . import checker


from proxy_server import ProxyServer

app = FastAPI()

# 连接数据库
models.Base.metadata.create_all(bind=engine)

# 设置模板和静态文件目录
templates = Jinja2Templates(directory="app/templates")
app.mount("/static", StaticFiles(directory="app/static"), name="static")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# 创建代理服务器实例
proxy = ProxyServer()

# 路由 1: 首页+基础配置

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


# 路由 1: 查看和修改 patterns.json
# @app.get("/patterns", response_class=HTMLResponse)
# def view_patterns(request: Request, db: Session = Depends(get_db)):#asd
#     try:
#         with open("patterns.json", "r", encoding="utf-8") as f:
#             config = json.load(f)
#         patterns = config.get("patterns", [])
#     except Exception as e:
#         patterns = []
#     return templates.TemplateResponse("patterns.html", {"request": request, "patterns": patterns})

# @app.post("/patterns/add", response_class=HTMLResponse)
# def add_pattern(request: Request, pattern: str = Form(...), description: str = Form(...), db: Session = Depends(get_db)):
#     try:
#         with open("patterns.json", "r", encoding="utf-8") as f:
#             config = json.load(f)
#         config["patterns"].append({"pattern": pattern, "description": description})
#         with open("patterns.json", "w", encoding="utf-8") as f:
#             json.dump(config, f, indent=4, ensure_ascii=False)
#         # 重新加载代理服务器配置
#         proxy.reload_config()
#         return RedirectResponse(url="/patterns", status_code=303)
#     except Exception as e:
#         return templates.TemplateResponse("patterns.html", {"request": request, "patterns": [], "error": str(e)})

@app.get("/patterns", response_class=HTMLResponse)
def view_patterns(request: Request, db: Session = Depends(get_db)):
    try:
        # 从数据库中查询所有 patterns
        patterns = db.query(models.Pattern).all()
    except Exception as e:
        patterns = []
    return templates.TemplateResponse("patterns.html", {"request": request, "patterns": patterns})

# 添加新的 pattern
@app.post("/patterns/add", response_class=HTMLResponse)
def add_pattern(request: Request, pattern: str = Form(...), description: str = Form(...), db: Session = Depends(get_db)):
    try:
        # 检查模式是否已经存在
        existing_pattern = db.query(models.Pattern).filter_by(pattern=pattern).first()
        if existing_pattern:
            error_message = "Pattern already exists."
            return templates.TemplateResponse("patterns.html", {"request": request, "patterns": [], "error": error_message})
        
        # 创建新的 Pattern 实例
        new_pattern = models.Pattern(pattern=pattern, description=description)
        # 添加到数据库
        db.add(new_pattern)
        db.commit()
        db.refresh(new_pattern)
        
        # 重新加载代理服务器配置
        proxy.reload_config()
        return RedirectResponse(url="/patterns", status_code=303)
    except IntegrityError:
        db.rollback()
        error_message = "An integrity error occurred."
        return templates.TemplateResponse("patterns.html", {"request": request, "patterns": [], "error": error_message})
    except Exception as e:
        db.rollback()
        return templates.TemplateResponse("patterns.html", {"request": request, "patterns": [], "error": str(e)})

@app.post("/patterns/delete/{pattern_id}", response_class=HTMLResponse)
def delete_pattern(request: Request, pattern_id: int, db: Session = Depends(get_db)):
    try:
        # 根据 pattern_id 删除对应的 Pattern
        pattern = db.query(models.Pattern).filter(models.Pattern.id == pattern_id).first()
        if not pattern:
            raise Exception("Pattern not found")
        db.delete(pattern)
        db.commit()
        return RedirectResponse(url="/patterns", status_code=303)
    except Exception as e:
        return templates.TemplateResponse("patterns.html", {"request": request, "patterns": [], "error": str(e)})
        # 重新加载代理服务器配置

# 展示编辑表单
@app.get("/patterns/edit/{pattern_id}", response_class=HTMLResponse)
def edit_pattern(request: Request, pattern_id: int, db: Session = Depends(get_db)):
    try:
        # 根据 pattern_id 查询对应的 Pattern
        pattern = db.query(models.Pattern).filter(models.Pattern.id == pattern_id).first()
        if not pattern:
            raise Exception("Pattern not found")
        return templates.TemplateResponse("edit_pattern.html", {"request": request, "pattern": pattern})
    except Exception as e:
        return templates.TemplateResponse("patterns.html", {"request": request, "patterns": [], "error": str(e)})

# 提交编辑后的 pattern
@app.post("/patterns/edit/{pattern_id}", response_class=HTMLResponse)
def update_pattern(request: Request, pattern_id: int, pattern: str = Form(...), description: str = Form(...), db: Session = Depends(get_db)):
    try:
        # 查询对应的 Pattern
        existing_pattern = db.query(models.Pattern).filter(models.Pattern.id == pattern_id).first()
        if not existing_pattern:
            raise Exception("Pattern not found")
        
        # 检查是否有其他记录使用相同的模式
        duplicate_pattern = db.query(models.Pattern).filter(models.Pattern.pattern == pattern, models.Pattern.id != pattern_id).first()
        if duplicate_pattern:
            error_message = "Another pattern with the same value already exists."
            return templates.TemplateResponse("edit_pattern.html", {"request": request, "pattern": existing_pattern, "error": error_message})
        
        # 更新 pattern 和 description
        existing_pattern.pattern = pattern
        existing_pattern.description = description
        # 提交到数据库
        db.commit()
        db.refresh(existing_pattern)
        
        # 重新加载代理服务器配置
        proxy.reload_config()
        return RedirectResponse(url="/patterns", status_code=303)
    except IntegrityError:
        db.rollback()
        error_message = "An integrity error occurred."
        return templates.TemplateResponse("edit_pattern.html", {"request": request, "pattern": existing_pattern, "error": error_message})
    except Exception as e:
        db.rollback()
        return templates.TemplateResponse("edit_pattern.html", {"request": request, "pattern": existing_pattern, "error": str(e)})



# 路由 2: 管理 Cookie 凭据
@app.get("/cookies", response_class=HTMLResponse)
def view_cookies(request: Request, db: Session = Depends(get_db)):
    cookies = db.query(models.CookieCredential).all()
    return templates.TemplateResponse("cookies.html", {"request": request, "cookies": cookies})

@app.post("/cookies/add", response_class=HTMLResponse)
def add_cookie(request: Request, credential: str = Form(...), permission: str = Form(...), user: str = Form(...), db: Session = Depends(get_db)):
    try:
        new_cookie = models.CookieCredential(
            credential=credential,
            permission=permission,
            user=user
        )
        db.add(new_cookie)
        db.commit()
        db.refresh(new_cookie)
        return RedirectResponse(url="/cookies", status_code=303)
    except Exception as e:
        cookies = db.query(models.CookieCredential).all()
        return templates.TemplateResponse("cookies.html", {"request": request, "cookies": cookies, "error": str(e)})

@app.post("/cookies/delete/{cookie_id}", response_class=HTMLResponse)
def delete_cookie(request: Request, cookie_id: int, db: Session = Depends(get_db)):
    try:
        cookie = db.query(models.CookieCredential).filter(models.CookieCredential.id == cookie_id).first()
        if not cookie:
            raise HTTPException(status_code=404, detail="Cookie 不存在")
        
        db.delete(cookie)
        db.commit()
        return RedirectResponse(url="/cookies", status_code=303)
    except Exception as e:
        cookies = db.query(models.CookieCredential).all()
        return templates.TemplateResponse("cookies.html", {"request": request, "cookies": cookies, "error": str(e)})




# 路由 3: 匹配记录有关操作
@app.get("/matches", response_class=HTMLResponse)
def view_matches(request: Request, db: Session = Depends(get_db)):
    # 去重 matched_data
    matches = db.query(models.ProcessedMatch).distinct(models.ProcessedMatch.matched_data).all()
    cookies = db.query(models.CookieCredential).all()
    return templates.TemplateResponse("matches.html", {"request": request, "matches": matches, "cookies": cookies})

@app.get("/matches/edit/{match_id}", response_class=HTMLResponse)
def edit_match_view(match_id: int, request: Request, db: Session = Depends(get_db)):
    # 查找要编辑的匹配记录
    match = db.query(models.ProcessedMatch).filter(models.ProcessedMatch.id == match_id).first()
    # 如果未找到记录，抛出404错误
    if not match:
        raise HTTPException(status_code=404, detail="Match not found")
    
    # 返回编辑页面
    return templates.TemplateResponse("edit_match.html", {"request": request, "match": match})

# 处理编辑提交
@app.post("/matches/edit/{match_id}", response_class=HTMLResponse)
def edit_match(match_id: int, matched_data: str = Form(...), db: Session = Depends(get_db)):
    # 查找要编辑的匹配记录
    match = db.query(models.ProcessedMatch).filter(models.ProcessedMatch.id == match_id).first()
    # 如果未找到记录，抛出404错误
    if not match:
        raise HTTPException(status_code=404, detail="Match not found")
    
    # 更新 matched_data 字段
    match.matched_data = matched_data
    db.commit()
    
    # 重定向回匹配页面
    return RedirectResponse(url="/matches", status_code=303)

@app.post("/matches/delete/{match_id}", response_class=HTMLResponse)
def delete_match(match_id: int, db: Session = Depends(get_db)):
    # 查找要删除的记录
    match = db.query(models.ProcessedMatch).filter(models.ProcessedMatch.id == match_id).first()
    # 如果未找到记录，抛出404错误
    if not match:
        raise HTTPException(status_code=404, detail="Match not found")
    # 删除关联的 response_history 记录
    db.query(models.ResponseHistory).filter(models.ResponseHistory.processed_match_id == match_id).delete()
    # 删除 ProcessedMatch 记录
    db.delete(match)
    db.commit()
    # 重定向回匹配页面
    return RedirectResponse(url="/matches", status_code=303)

@app.get("/matches/delete_all", response_class=HTMLResponse)
def delete_all_matches(db: Session = Depends(get_db)):
    # 删除所有匹配记录和相关的响应历史记录
    db.query(models.ProcessedMatch).delete()
    db.query(models.ResponseHistory).delete()
    db.commit()
    return RedirectResponse(url="/matches", status_code=303)


# 路由 3.2: 处理匹配记录（替换Cookie并发送请求）
# @app.post("/matches/process/{match_id}", response_class=HTMLResponse)
# def process_match(request: Request, match_id: int, user_cookie_ids: List[int] = Form(...), db: Session = Depends(get_db)):
#     try:
#         match_record = db.query(models.ProcessedMatch).filter(models.ProcessedMatch.id == match_id).first()
#         if not match_record:
#             raise ValueError("匹配记录不存在。")

#         # 遍历每个用户 Cookie ID，逐一替换 Cookie 并发送请求
#         for user_cookie_id in user_cookie_ids:
#             user_cookie = db.query(models.CookieCredential).filter(models.CookieCredential.id == user_cookie_id).first()
#             if not user_cookie:
#                 raise ValueError(f"用户Cookie {user_cookie_id} 不存在。")

#             # 假设 matched_data 包含完整的HTTP请求报文，需要解析并替换Cookie
#             import email
#             from io import StringIO
#             from urllib.parse import urlparse

#             request_lines = match_record.matched_data.split('\r\n')
#             request_line = request_lines[0]
#             headers = email.message_from_file(StringIO('\n'.join(request_lines[1:])))

#             # 替换Cookie
#             if 'Cookie' in headers:
#                 headers.replace_header('Cookie', user_cookie.credential)
#             else:
#                 headers.add_header('Cookie', user_cookie.credential)

#             # 构建新的HTTP请求
#             new_request = f"{request_line}\r\n"
#             for header, value in headers.items():
#                 new_request += f"{header}: {value}\r\n"
#             new_request += "\r\n"  # 请求体，如果有的话需要处理
            
#             print(new_request)
            
#             # 解析原始请求以获取目标地址
#             parsed = urlparse(request_line.split(' ')[1])
#             host = parsed.hostname or headers.get('Host')
#             port = parsed.port or (443 if headers.get('Proxy-Connection') == 'keep-alive' else 80)

#             # 发送新的请求
#             if headers.get('Proxy-Connection', '').lower() == 'keep-alive':
#                 # HTTPS 请求
#                 context = ssl.create_default_context()
#                 with socket.create_connection((host, port)) as sock:
#                     with context.wrap_socket(sock, server_hostname=host) as ssock:
#                         ssock.sendall(new_request.encode())
#                         response = ssock.recv(65535).decode(errors='ignore')
#             else:
#                 # HTTP 请求
#                 with socket.create_connection((host, port)) as sock:
#                     sock.sendall(new_request.encode())
#                     response = sock.recv(65535).decode(errors='ignore')

#             # 保存每次响应到 ResponseHistory 表
#             response_history = models.ResponseHistory(
#                 processed_match_id=match_record.id,
#                 response=response,
#                 cookie_credential_id=user_cookie.id
#             )
#             db.add(response_history)

#         db.commit()

#         return RedirectResponse(url="/matches", status_code=303)
#     except Exception as e:
#         db.rollback()
#         matches = db.query(models.ProcessedMatch).distinct(models.ProcessedMatch.matched_data).all()
#         cookies = db.query(models.CookieCredential).all()
#         return templates.TemplateResponse("matches.html", {"request": request, "matches": matches, "cookies": cookies, "error": str(e)})

@app.post("/matches/process/{match_id}", response_class=HTMLResponse)
def process_match(
    request: Request, 
    match_id: int, 
    user_cookie_ids: List[int] = Form(...), 
    db: Session = Depends(get_db)
):
    try:
        match_record = db.query(models.ProcessedMatch).filter(models.ProcessedMatch.id == match_id).first()
        if not match_record:
            raise ValueError("匹配记录不存在。")

        # 检查 matched_data 是否为空
        if not match_record.matched_data:
            raise ValueError("匹配数据为空。")

        # 分割 HTTP 报文行
        request_lines = match_record.matched_data.split('\r\n')
        if len(request_lines) < 1:
            raise ValueError("匹配数据的格式不正确。")

        request_line = request_lines[0]
        request_line_parts = request_line.split(' ')

        # 确保请求行有足够的部分，例如 "GET /path HTTP/1.1"
        if len(request_line_parts) < 3:
            raise ValueError("请求行格式不正确。")

        method, path, http_version = request_line_parts

        # headers = {}
        # for line in request_lines[1:]:
        #     if line:
        #         key, value = line.split(':', 1)
        #         headers[key.strip()] = value.strip()
        headers = {}
        for line in request_lines[1:]:
            if line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    key, value = parts
                    headers[key.strip()] = value.strip()
                else:
                    # 处理异常情况，记录错误日志或抛出异常
                    raise ValueError(f"无效的头部行格式: {line}")

        # 遍历每个用户 Cookie ID，逐一替换 Cookie 并发送请求
        for user_cookie_id in user_cookie_ids:
            user_cookie = db.query(models.CookieCredential).filter(models.CookieCredential.id == user_cookie_id).first()
            if not user_cookie:
                raise ValueError(f"用户Cookie {user_cookie_id} 不存在。")

            # 替换Cookie
            if 'Cookie' in headers:
                headers['Cookie'] = user_cookie.credential
            else:
                headers['Cookie'] = user_cookie.credential

            # 构建新的HTTP请求
            new_request = f"{method} {path} {http_version}\r\n"
            for header, value in headers.items():
                new_request += f"{header}: {value}\r\n"
            new_request += "\r\n"  # 请求体，如果有的话需要处理

            print(new_request)

            # 解析 Host 头部以获取主机名和端口号
            host_header = headers.get('Host', '')
            if not host_header:
                raise ValueError("Host 头部缺失。")

            if ':' in host_header:
                host, host_port = host_header.split(':', 1)
                try:
                    port = int(host_port)
                except ValueError:
                    raise ValueError(f"无效的端口号: {host_port}")
            else:
                host = host_header
                port = 443 if headers.get('Proxy-Connection', '').lower() == 'keep-alive' else 80

            # 发送新的请求
            if headers.get('Proxy-Connection', '').lower() == 'keep-alive':
                # HTTPS 请求
                context = ssl.create_default_context()
                with socket.create_connection((host, port)) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        ssock.sendall(new_request.encode())
                        response = b""
                        while True:
                            part = ssock.recv(4096)
                            if not part:
                                break
                            response += part
                        response = response.decode(errors='ignore')
            else:
                # HTTP 请求
                with socket.create_connection((host, port)) as sock:
                    sock.sendall(new_request.encode())
                    response = b""
                    while True:
                        part = sock.recv(4096)
                        if not part:
                            break
                        response += part
                    response = response.decode(errors='ignore')

            # 保存每次响应到 ResponseHistory 表
            response_history = models.ResponseHistory(
                processed_match_id=match_record.id,
                response=response,
                cookie_credential_id=user_cookie.id
            )
            db.add(response_history)

        db.commit()

        return RedirectResponse(url="/matches", status_code=303)
    except Exception as e:
        db.rollback()
        matches = db.query(models.ProcessedMatch).distinct(models.ProcessedMatch.matched_data).all()
        cookies = db.query(models.CookieCredential).all()
        return templates.TemplateResponse(
            "matches.html", 
            {"request": request, "matches": matches, "cookies": cookies, "error": str(e)}
        )

# 路由 3.4: 显示已处理的匹配记录详情
@app.get("/matches/processed/{match_id}", response_class=HTMLResponse)
def show_processed_match_detail(request: Request, match_id: int, db: Session = Depends(get_db)):
    # 查询单个 ProcessedMatch 记录
    match = db.query(models.ProcessedMatch).filter(models.ProcessedMatch.id == match_id).first()
    if not match:
        raise HTTPException(status_code=404, detail="匹配记录未找到")
    # 将查询结果传递给模板
    return templates.TemplateResponse("processed_match_detail.html", {"request": request, "match": match})

# 路由 3.5: 删除已处理的匹配记录
@app.post("/matches/processed/delete")
def delete_processed_match(match_id: int = Form(...), db: Session = Depends(get_db)):
    # 查询要删除的匹配记录
    match = db.query(models.ProcessedMatch).filter(models.ProcessedMatch.id == match_id).first()
    if not match:
        raise HTTPException(status_code=404, detail="匹配记录未找到")
    # 删除相关的 ResponseHistory 记录，使用 processed_match_id 进行过滤
    db.query(models.ResponseHistory).filter(models.ResponseHistory.processed_match_id == match_id).delete()
    # 删除 ProcessedMatch 记录
    db.delete(match)
    db.commit()
    return RedirectResponse(url="/matches/processed", status_code=303)

# 路由 4: js文件处理已经相关api的提取


# 路由 5: 控制代理服务器（启动和重启）
@app.get("/proxy_control", response_class=HTMLResponse)
def proxy_control_page(request: Request):
    server_status = proxy.get_status()  
    config = proxy.get_config()
    return templates.TemplateResponse("proxy_control.html", {
        "request": request, 
        "server_status": server_status, 
        "config": config,
    })

@app.post("/proxy_control/start", response_class=HTMLResponse)
def start_proxy_server(request: Request):
    try:
        address, port = proxy.start()
        server_status = {"address": address, "port": port, "running": True}
        config = proxy.get_config()
        logs = proxy.get_logs()
        return templates.TemplateResponse("proxy_control.html", {
            "request": request, 
            "server_status": server_status, 
            "config": config, 
            "logs": logs
        })
    except Exception as e:
        config = proxy.get_config()
        logs = proxy.get_logs()
        return templates.TemplateResponse("proxy_control.html", {
            "request": request, 
            "error": str(e), 
            "config": config, 
            "logs": logs
        })

@app.post("/proxy_control/restart", response_class=HTMLResponse)
def restart_proxy_server(request: Request):
    try:
        proxy.stop()
        address, port = proxy.start()
        server_status = {"address": address, "port": port, "running": True}
        config = proxy.get_config()
        logs = proxy.get_logs()
        return templates.TemplateResponse("proxy_control.html", {
            "request": request, 
            "server_status": server_status, 
            "config": config, 
            "logs": logs
        })
    except Exception as e:
        config = proxy.get_config()
        logs = proxy.get_logs()
        return templates.TemplateResponse("proxy_control.html", {
            "request": request, 
            "error": str(e), 
            "config": config, 
            "logs": logs
        })

@app.post("/proxy_control/stop", response_class=HTMLResponse)
def stop_proxy_server(request: Request):
    try:
        proxy.stop()
        server_status = proxy.get_status()  # 获取停止后的状态
        config = proxy.get_config()
        logs = proxy.get_logs()
        return templates.TemplateResponse("proxy_control.html", {
            "request": request, 
            "server_status": server_status, 
            "config": config, 
            "logs": logs
        })
    except Exception as e:
        config = proxy.get_config()
        logs = proxy.get_logs()
        return templates.TemplateResponse("proxy_control.html", {
            "request": request, 
            "error": str(e), 
            "config": config, 
            "logs": logs
        })
@app.get("/check", response_class=HTMLResponse)
def get_checks(request: Request, db: Session = Depends(get_db)):
    # 查询所有 ProcessedMatch，其关联的 ResponseHistory 个数大于2
    processed_matches = db.query(models.ProcessedMatch).join(models.ResponseHistory).group_by(models.ProcessedMatch.id).having(func.count(models.ResponseHistory.id) > 2).all()
    
    return templates.TemplateResponse("check_list.html", {"request": request, "processed_matches": processed_matches})


# # 新增路由 3: POST /check/{id} 检查指定 ProcessedMatch 的 ResponseHistory 是否存在越权漏洞
# @app.post("/check/{id}", response_class=HTMLResponse)
# def check_vulnerability(id: int, method: str = Form(...), db: Session = Depends(get_db), request: Request = None):
#     # 获取指定的 ProcessedMatch
#     processed_match = db.query(models.ProcessedMatch).filter(models.ProcessedMatch.id == id).first()
#     if not processed_match:
#         raise HTTPException(status_code=404, detail="ProcessedMatch not found")
    
#     # 获取所有关联的 ResponseHistory
#     response_histories = db.query(models.ResponseHistory).filter(models.ResponseHistory.processed_match_id == id).all()
#     if not response_histories:
#         raise HTTPException(status_code=404, detail="No associated ResponseHistory found")
    
#     if method == "ai":
#         # 使用 AI 方法检查越权
#         is_vulnerable, reason = checker.ai_check_privilege_escalation(
#             api_key=checker.api_key,
#             base_url=checker.base_url,
#             responses=response_histories
#         )
#     elif method == "json":
#         # 使用 JSON 比较方法检查越权
#         # 假设第一个和第二个响应进行比较，您可以根据需求调整
#         if len(response_histories) < 2:
#             raise HTTPException(status_code=400, detail="Not enough ResponseHistory to compare")
#         json_obj1 = checker.extract_json_from_http(response_histories[0].response)
#         json_obj2 = checker.extract_json_from_http(response_histories[1].response)
#         if not json_obj1 or not json_obj2:
#             raise HTTPException(status_code=400, detail="Failed to extract JSON from responses")
#         similarity = checker.compare_json_similarity(json_obj1, json_obj2)
#         # 假设相似度低于某个阈值认为存在漏洞，这个阈值可以根据实际情况调整
#         threshold = 0.8
#         is_vulnerable = 1 if similarity < threshold else 0
#         reason = f"JSON相似度为{similarity}，阈值为{threshold}。" + ("存在越权漏洞。" if is_vulnerable else "未检测到越权漏洞。")
#     else:
#         raise HTTPException(status_code=400, detail="Invalid method. Choose 'ai' or 'json'")
    
#     # 更新 ProcessedMatch 的 is_vulnerable 字段
#     processed_match.is_vulnerable = is_vulnerable
#     processed_match.vulnerability_reason = reason  # 如果有这个字段
#     db.add(processed_match)
#     db.commit()
#     db.refresh(processed_match)
    
#     # 根据需求返回不同内容，这里假设返回更新后的 ProcessedMatch 信息
#     return templates.TemplateResponse("check_result.html", {"request": request, "processed_match": processed_match})


@app.post("/check_all", response_class=HTMLResponse)
def check_all_vulnerabilities(
    method: str = Form(...),
    db: Session = Depends(get_db),
    request: Request = None,
    background_tasks: BackgroundTasks = None
):
    """
    批量检查所有未检查的 ProcessedMatch 是否存在越权漏洞。
    - **method**: 检查方法，选择 "ai" 或 "json"
    - **db**: 数据库会话
    - **request**: 请求对象
    - **background_tasks**: FastAPI 的后台任务管理器
    """
    # 获取所有未检查的 ProcessedMatch (is_vulnerable = None)
    unprocessed_matches = db.query(models.ProcessedMatch).filter(
        (models.ProcessedMatch.is_vulnerable == None) | (models.ProcessedMatch.is_vulnerable == -1)
    ).all()
    
    if not unprocessed_matches:
        return templates.TemplateResponse("check_all_result.html", {"request": request, "message": "没有未检查的记录。"})

    # 定义后台任务处理函数，确保每个任务有独立的数据库会话
    def process_match(match_id: int, method: str):
        # 为每个后台任务创建新的数据库会话
        db = SessionLocal()
        try:
            # 获取指定的 ProcessedMatch
            match = db.query(models.ProcessedMatch).filter(models.ProcessedMatch.id == match_id).first()
            if not match:
                return
            
            # 获取所有关联的 ResponseHistory
            response_histories = db.query(models.ResponseHistory).filter(models.ResponseHistory.processed_match_id == match.id).all()
            if not response_histories:
                return
            
            if method == "ai":
                # 使用 AI 方法检查越权
                is_vulnerable, reason = checker.ai_check_privilege_escalation(
                    session=db,
                    processed_match_id=match.id
                )
            elif method == "json":
                # 使用 JSON 比较方法检查越权
                if len(response_histories) < 2:
                    return
                json_obj1 = checker.extract_json_from_http(response_histories[0].response)
                json_obj2 = checker.extract_json_from_http(response_histories[1].response)
                if not json_obj1 or not json_obj2:
                    return
                similarity = checker.compare_json_similarity(json_obj1, json_obj2)
                threshold = 0.6
                is_vulnerable = similarity
                reason = f"JSON相似度为{similarity:.2f}，阈值为{threshold}。" + ("很可能存在越权漏洞。" if threshold<is_vulnerable else "未检测到越权漏洞。")
            else:
                return

            # 更新 ProcessedMatch 的 is_vulnerable 和 vulnerability_reason 字段
            match.is_vulnerable = is_vulnerable
            match.vulnerability_reason = reason
            db.add(match)
            db.commit()
            db.refresh(match)
        except Exception as e:
            # 记录错误日志
            logging.error(f"处理 ProcessedMatch ID {match_id} 时出错: {e}")
        finally:
            db.close()  # 确保数据库会话关闭

    # 批量处理所有未检查的 ProcessedMatch
    for match in unprocessed_matches:
        background_tasks.add_task(process_match, match.id, method)

    return templates.TemplateResponse("check_all_result.html", {"request": request, "message": "检查任务已启动，稍后请查看结果。"})


@app.post("/check/{id}", response_class=HTMLResponse)
def check_vulnerability(
    id: int,
    method: str = Form(..., description="选择检查方法: 'ai' 或 'json'"),
    db: Session = Depends(get_db),
    request: Request = None
):
    """
    检查指定 ProcessedMatch 的 ResponseHistory 是否存在逻辑越权漏洞。

    - **id**: ProcessedMatch 的ID
    - **method**: 检查方法，选择 "ai" 或 "json"
    - **db**: 数据库会话
    - **request**: 请求对象，用于渲染模板
    """
    # 获取指定的 ProcessedMatch
    processed_match = db.query(models.ProcessedMatch).filter(models.ProcessedMatch.id == id).first()
    if not processed_match:
        raise HTTPException(status_code=404, detail="ProcessedMatch not found")
    
    # 获取所有关联的 ResponseHistory
    response_histories = db.query(models.ResponseHistory).filter(models.ResponseHistory.processed_match_id == id).all()
    if not response_histories:
        raise HTTPException(status_code=404, detail="No associated ResponseHistory found")
    
    if method == "ai":
        # 使用 AI 方法检查越权
        is_vulnerable, reason = checker.ai_check_privilege_escalation(
            session=db,
            processed_match_id=id
        )
    elif method == "json":
        # 使用 JSON 比较方法检查越权
        # 假设第一个和第二个响应进行比较，您可以根据需求调整
        if len(response_histories) < 2:
            raise HTTPException(status_code=400, detail="Not enough ResponseHistory to compare")
        json_obj1 = checker.extract_json_from_http(response_histories[0].response)
        json_obj2 = checker.extract_json_from_http(response_histories[1].response)
        if not json_obj1 or not json_obj2:
            raise HTTPException(status_code=400, detail="Failed to extract JSON from responses")
        similarity = checker.compare_json_similarity(json_obj1, json_obj2)
        # 假设相似度低于某个阈值认为存在漏洞，这个阈值可以根据实际情况调整
        threshold = 0.6
        is_vulnerable = similarity
        reason = f"JSON相似度为{similarity:.2f}，阈值为{threshold}。" + ("很可能存在越权漏洞。" if threshold<is_vulnerable else "未检测到越权漏洞。")
    else:
        raise HTTPException(status_code=400, detail="Invalid method. Choose 'ai' or 'json'")
    
    # 更新 ProcessedMatch 的 is_vulnerable 字段和 vulnerability_reason 字段
    processed_match.is_vulnerable = is_vulnerable
    processed_match.vulnerability_reason = reason  # 确保 ProcessedMatch 模型中存在此字段
    db.add(processed_match)
    db.commit()
    db.refresh(processed_match)
    
    # 根据需求返回不同内容，这里假设返回更新后的 ProcessedMatch 信息
    return templates.TemplateResponse("check_result.html", {"request": request, "processed_match": processed_match})


@app.get("/jsparse", response_class=HTMLResponse)
def show_js_files(request: Request, db: Session = Depends(get_db)):
    js_files = db.query(models.JSFile).all()
    return templates.TemplateResponse("js_files.html", {"request": request, "js_files": js_files})

@app.get("/jsparse/deleteall", response_class=HTMLResponse)
def delete_all_js_files(db: Session = Depends(get_db)):
    # 删除所有 JSFile 记录
    num_deleted = db.query(models.JSFile).delete()
    db.commit()

    return HTMLResponse(f"成功删除了 {num_deleted} 条 JavaScript 文件记录。")


@app.get("/jsparse/extract/{id}", response_class=HTMLResponse)
def extract_api_from_js_file(id: int, db: Session = Depends(get_db)):
    # 获取指定 ID 的 JSFile 记录
    js_file = db.query(models.JSFile).filter(models.JSFile.id == id).first()
    
    if not js_file:
        raise HTTPException(status_code=404, detail="JavaScript 文件未找到")

    # 提取 API 请求并保存到数据库
    api_requests = jsparse.extract_api_requests(js_file.content)
    
    for api in api_requests:
        api_request = models.APIRequest(
            type=api.type,
            url=api.url,
            method=api.method,
            headers=api.headers if api.headers else {},
            body=api.body,
            location_start_line=api.location_start_line,
            location_start_column=api.location_start_column,
            location_end_line=api.location_end_line,
            location_end_column=api.location_end_column,
            js_file_id=js_file.id
        )
        db.add(api_request)
    
    db.commit()

    return RedirectResponse(url=f"/jsparse/{id}", status_code=302)


@app.get("/jsparse/extractall", response_class=HTMLResponse)
def extract_all_js_files(background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    # 获取所有 JSFile 记录
    js_files = db.query(models.JSFile).all()

    # 将提取任务添加到后台任务中
    background_tasks.add_task(extract_all_api_requests, js_files, db)

    return HTMLResponse("正在后台提取所有 JavaScript 文件中的 API 请求。")

def extract_all_api_requests(js_files: List[models.JSFile], db: Session):
    for js_file in js_files:
        api_requests = jsparse.extract_api_requests(js_file.content)
        
        for api in api_requests:
            api_request = models.APIRequest(
                type=api.type,
                url=api.url,
                method=api.method,
                headers=api.headers if api.headers else {},
                body=api.body,
                location_start_line=api.location_start_line,
                location_start_column=api.location_start_column,
                location_end_line=api.location_end_line,
                location_end_column=api.location_end_column,
                js_file_id=js_file.id
            )
            db.add(api_request)
    
    db.commit()


@app.get("/jsparse/{id}", response_class=HTMLResponse)
def show_js_file_details(id: int, request: Request, db: Session = Depends(get_db)):
    # 获取指定 ID 的 JSFile 记录
    js_file = db.query(models.JSFile).filter(models.JSFile.id == id).first()

    if not js_file:
        raise HTTPException(status_code=404, detail="JavaScript 文件未找到")

    # 获取该 JSFile 关联的 APIRequest 记录
    api_requests = db.query(models.APIRequest).filter(models.APIRequest.js_file_id == id).all()

    return templates.TemplateResponse("js_file_details.html", {"request": request, "js_file": js_file, "api_requests": api_requests})

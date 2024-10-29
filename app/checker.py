# app/checker.py
import json,openai
from openai import OpenAI
from sqlalchemy.orm import session

if __name__ == "__main__":
    import models
else:
    from . import models 

config_path = "patterns.json"
with open(config_path, 'r', encoding='utf-8') as f:
    config = json.load(f)
    api_key = config["api_key"]
    base_url = config["base_url"]


if api_key is None or base_url is None:
    raise ValueError("请先配置好api_key和base_url")

client = openai.OpenAI(
    api_key=api_key,
    base_url=base_url,
)


# json格式
#{status:200,message:"success",data:['123213213'],code:0}
# {status:200,message:"success",data:[...],code:0} 
def ai_check_privilege_escalation(
    session, 
    processed_match_id: int
) -> tuple[bool, str]:
    """
    使用 OpenAI 大模型 API，分析指定 ProcessedMatch 相关的 ResponseHistory，
    判断是否存在逻辑越权漏洞。

    参数：
    - session: SQLAlchemy 会话对象
    - processed_match_id: 需要分析的 ProcessedMatch 的ID

    返回：
    - Tuple[bool, str]: (是否存在漏洞, 具体原因)
    """
    # 获取指定的 ProcessedMatch 及其相关的 ResponseHistory
    processed_match = session.query(models.ProcessedMatch).filter(
        models.ProcessedMatch.id == processed_match_id
    ).first()

    if not processed_match:
        return False, f"ProcessedMatch ID {processed_match_id} 未找到。"

    responses = processed_match.responses

    if not responses:
        return False, "没有相关的 ResponseHistory 数据。"

    # 构建用户提示内容
    user_prompt_body = ""
    for i, r in enumerate(responses, start=1):
        if not r.cookie_credential:
            user = "未知用户"
            permission = "未知权限"
        else:
            user = r.cookie_credential.user
            permission = r.cookie_credential.permission

        user_prompt_body += (
            f"\n\n第{i}段报文的cookie对应的用户为 {user}，权限为 {permission}，"
            f"具体内容如下:\n{r.response}\n"
        )

    # 系统提示词
    system_prompt = """
1. 水平越权 示例
假设有一个在线银行系统，用户可以查看自己的账户信息。用户A的账户ID是 12345，用户B的账户ID是 67890。用户A尝试通过修改URL来访问用户B的账户信息。

请求：
用户A登录后，尝试访问自己的账户信息，系统生成的请求如下：

GET /account/12345 HTTP/1.1
Host: bank.com
Authorization: Bearer <valid_token_for_user_A>
此时，用户A修改了请求中的账户ID，试图访问用户B的账户信息：

GET /account/67890 HTTP/1.1
Host: bank.com
Authorization: Bearer <valid_token_for_user_A>
正确的响应：
服务器应检测到用户A尝试访问用户B的账户信息，拒绝该请求并返回以下响应：

HTTP/1.1 403 Forbidden
Content-Type: application/json

{
  "error": "You do not have permission to access this account."
}
2. 垂直越权 示例
假设在同一个在线银行系统中，普通用户只能查看自己的账户信息，而管理员可以删除用户账户。普通用户A尝试通过发送删除请求来删除其他用户的账户。

请求：
普通用户A尝试删除用户B的账户，发送以下请求：

DELETE /admin/deleteUser/67890 HTTP/1.1
Host: bank.com
Authorization: Bearer <valid_token_for_user_A>
正确的响应：
服务器应检测到用户A是普通用户，且没有管理员权限，因此应拒绝该请求并返回以下响应：

HTTP/1.1 403 Forbidden
Content-Type: application/json

{
  "error": "You do not have permission to perform this action."
}
总结：
水平越权：用户A尝试通过修改URL中的参数访问用户B的数据，服务器返回 403 Forbidden。
垂直越权：用户A尝试执行只有管理员才能进行的操作，服务器也返回 403 Forbidden。
在这两种情况下，服务器的正确行为都是拒绝未授权的请求，并返回适当的错误信息，通常是 403 Forbidden。
接下来我会给你几段不同的http请求的返回报文，请你分别判断它们是否存在逻辑越权漏洞。
    """

    # 用户提示结束
    user_prompt_end = """请使用如下 JSON 格式输出你的回复：

{
    "is_vulnerable": true,
    "reason": "存在逻辑越权漏洞，因为用户A可以通过修改URL中的参数访问用户B的数据。"
}

注意：
- 请确保你的回复符合 JSON 格式。
- is_vulnerable 为布尔类型，表示是否存在逻辑越权漏洞。
- reason 为字符串类型，表示判别漏洞的具体原因。
- 普通用户只能获取自己的信息，不能获取其他用户的信息。
- 管理员用户可以获取所有用户的信息。
""" 
    prompt=[
        {"role":"system","content":system_prompt},
        {"role":"user","content":user_prompt_body+'\n\n'+user_prompt_end} 
    ]
    
    # 调用 OpenAI 大模型 API
    completion = client.chat.completions.create(
        model="moonshot-v1-auto",  # 根据实际情况选择合适的模型
        messages=prompt,
        temperature=0.3,
        max_tokens=1000,
    )
    

    # 解析返回的 JSON 数据
    try:
        response_content = completion.choices[0].message.content.strip()
        content = json.loads(response_content)
    except json.JSONDecodeError as e:
        return False, f"解析 OpenAI API 响应失败: {str(e)}"
    except (AttributeError, IndexError) as e:
        return False, f"响应内容格式错误: {str(e)}"

    # 验证 JSON 结构
    if not isinstance(content, dict):
        return False, "响应内容不是有效的 JSON 对象。"
    if "is_vulnerable" not in content or "reason" not in content:
        return False, "JSON 响应缺少必要的字段。"
    
    is_vulnerable = content['is_vulnerable']
    reason = content['reason']
    return is_vulnerable, reason










def compare_json_similarity(json_obj1, json_obj2, depth=0) -> float:
    """
    比较两个JSON对象的相似度。

    参数：
    - json_obj1: 第一个JSON对象
    - json_obj2: 第二个JSON对象
    - depth: 当前递归深度

    返回：
    - 相似度得分（0到1之间）
    """
    # 设置深度权重衰减系数，depth 越大，权重越小
    decay_factor = 0.5
    weight = decay_factor ** depth

    # 如果两个对象类型不同，相似度为 0
    if type(json_obj1) != type(json_obj2):
        return 0

    # 如果是字典类型，比较键和对应的值
    if isinstance(json_obj1, dict):
        keys1 = set(json_obj1.keys())
        keys2 = set(json_obj2.keys())
        all_keys = keys1.union(keys2)
        if not all_keys:
            return weight  # 空字典，视为完全相似

        # 键名相似度
        common_keys = keys1.intersection(keys2)
        key_similarity = len(common_keys) / len(all_keys)

        # 对于每个共同的键，递归计算值的相似度
        value_similarity = 0
        for key in common_keys:
            value_similarity += compare_json_similarity(json_obj1[key], json_obj2[key], depth + 1)
        if common_keys:
            value_similarity /= len(common_keys)

        # 结构和内容相似度综合
        similarity = weight * (0.8 * key_similarity + 0.2 * value_similarity)
        return similarity

    # 如果是列表类型，比较元素
    elif isinstance(json_obj1, list):
        if not json_obj1 and not json_obj2:
            return weight  # 空列表，视为完全相似
        min_len = min(len(json_obj1), len(json_obj2))
        max_len = max(len(json_obj1), len(json_obj2))
        if max_len == 0:
            return weight
        # 长度相似度
        length_similarity = min_len / max_len

        # 元素相似度，只比较前 min_len 个元素
        element_similarity = 0
        for i in range(min_len):
            element_similarity += compare_json_similarity(json_obj1[i], json_obj2[i], depth + 1)
        if min_len > 0:
            element_similarity /= min_len

        similarity = weight * (0.8 * length_similarity + 0.2 * element_similarity)
        return similarity

    # 如果是基本数据类型，直接比较是否相等
    else:
        return weight if json_obj1 == json_obj2 else 0

def extract_json_from_http(http_message: str):
    """
    从HTTP报文中提取JSON数据。

    参数：
    - http_message: 完整的HTTP报文字符串

    返回：
    - 如果成功提取并解析JSON数据，返回对应的dict对象
    - 如果失败，返回None
    """
    if "\r\n\r\n" in http_message:
        headers, body = http_message.split("\r\n\r\n", 1)
    elif "\n\n" in http_message:
        headers, body = http_message.split("\n\n", 1)
    else:
        return None

    if "Content-Type: application/json" in headers or "Content-Type: application/json" in headers.lower():
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return None
    else:
        return None

# 示例比较函数
if __name__ == '__main__':
    json_str1 = '''
{
    "name": "Alice",
    "age": 30,
    "skills": ["Python", "C++"],
    "details": {
        "city": "New York",
        "married": false
    }
}
'''
    json_str2 = '''
{
    "name": "Alice",
    "age": 31,
    "skills": ["Python", "Java"],
    "details": {
        "city": "New York",
        "married": false
    }
}
'''
    json_obj1 = json.loads(json_str1)
    json_obj2 = json.loads(json_str2)
    similarity = compare_json_similarity(json_obj1, json_obj2)
    print("JSON相似度：", similarity)



def extract_json_from_http(http_message):
    """
    从HTTP报文中提取JSON数据
    """
    if "\r\n\r\n" in http_message:
        headers, body = http_message.split("\r\n\r\n", 1) 
    elif "\n\n" in http_message:
        headers, body = http_message.split("\n\n", 1)
    else:
        return None
    if "Content-Type: application/json" in headers:
        return json.loads(body)  # 尝试解析为JSON
    else:
        return None


if __name__ == '__main__':
    json_str1 = '''
{
    "name": "Alice",
    "age": 30,
    "skills": ["Python", "C++"],
    "details": {
        "city": "New York",
        "married": false
    }
}
'''
    json_str2 = '''
{
    "name": "Alice",
    "age": 31,
    "skills": ["Python", "Java"],
    "details": {
        "city": "New York",
        "married": false
    }
}
'''
    json_obj1 = json.loads(json_str1)
    json_obj2 = json.loads(json_str2)
    similarity = compare_json_similarity(json_obj1, json_obj2)
    print("JSON相似度：", similarity)
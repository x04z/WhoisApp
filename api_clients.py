# api_clients.py
import requests
import asyncio
import aiohttp
import time
import socket
import ipaddress
import random
import logging
import dns.resolver
import dns.reversename
import dns.exception
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from utils import query_local_proxy_db

# Step 1と2で作成した外部ファイルからのインポート
from constants import RDAP_BOOTSTRAP_URL, VPNAPI_URL, PUBLIC_DNS_SERVERS
from utils import is_ipv4
from functools import wraps

# ==========================================
# 動的タイムアウト設定（API/プロトコルごとの足切りライン）
# ==========================================
TIMEOUT_DNS = 3.0       # DNSは本来高速。これ以上待つ場合はネットワーク障害とみなす
TIMEOUT_API_FAST = 5.0  # InternetDB, VPNAPIなど軽量なAPI用
TIMEOUT_ST = 12.0       # SecurityTrails用
TIMEOUT_RDAP = 15.0     # 各国のレジストリ(RDAP)用。相手サーバーの応答にバラつきがあるため長め
TIMEOUT_OTX = 15.0      # OTX用
TIMEOUT_REV_IP = 20.0   # Reverse IPはデータベース検索が重いため最長を設定
TIMEOUT_BULK = 15.0     # IPinfoのバルク一括取得用

def async_retry_with_backoff(max_retries=3, base_delay=1.0, max_delay=10.0):
    """
    指数バックオフとジッターを利用した非同期リトライ用デコレータ
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return await func(*args, **kwargs)
                
                # タイムアウトとサーバー側HTTPエラーを捕捉してリトライ対象とします
                except (asyncio.TimeoutError, aiohttp.ServerTimeoutError, aiohttp.ClientConnectionError, aiohttp.ClientResponseError) as e:
                    # 404(Not Found)や403(Forbidden)など、リトライしても解決しないエラーは即座に終了
                    if isinstance(e, aiohttp.ClientResponseError) and e.status in [400, 401, 403, 404]:
                        logging.error(f"[{func.__name__}] リトライ不要なHTTPエラー ({e.status})")
                        raise
                        
                    if attempt == max_retries - 1:
                        logging.error(f"[{func.__name__}] タイムアウトまたは通信エラー (試行 {attempt + 1}/{max_retries}) - 最終試行失敗")
                        raise
                    
                    # 指数バックオフの計算: base_delay * (2 ^ attempt)
                    delay = min(base_delay * (2 ** attempt), max_delay)
                    # ジッターの加算: 0.0秒から0.5秒の乱数
                    jitter = random.uniform(0.0, 0.5)
                    sleep_time = delay + jitter
                    
                    logging.warning(f"[{func.__name__}] タイムアウト発生。{sleep_time:.2f}秒後に再試行します (試行 {attempt + 1}/{max_retries})")
                    await asyncio.sleep(sleep_time)
                
                # タイムアウト以外の予期せぬエラー（認証エラーなど）はリトライせず即座に例外を投げる
                except Exception as e:
                    logging.error(f"[{func.__name__}] 予期せぬエラーによりリトライを中断: {e}")
                    raise
        return wrapper
    return decorator

import sqlite3
import json

# ==========================================
# ローカルキャッシュ機構 (SQLite)
# ==========================================
CACHE_DB_FILE = "osint_api_cache.db"

def _get_cache_conn():
    # check_same_thread=False により非同期タスクからのアクセスを許可
    conn = sqlite3.connect(CACHE_DB_FILE, check_same_thread=False)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS api_cache (
            cache_key TEXT PRIMARY KEY,
            response_data TEXT,
            timestamp REAL
        )
    ''')
    return conn

_cache_conn = _get_cache_conn()

def async_sqlite_cache(prefix_name, ttl=86400 * 7): # デフォルト7日間保持
    """APIレスポンスをSQLiteに保存・再利用する非同期デコレータ"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            if not args: return await func(*args, **kwargs)
            
            target = args[0] # IPアドレスまたはドメイン
            cache_key = f"{prefix_name}_{target}"
            
            # 1. キャッシュの読み込み (有効期限内かチェック)
            try:
                cursor = _cache_conn.cursor()
                cursor.execute("SELECT response_data, timestamp FROM api_cache WHERE cache_key = ?", (cache_key,))
                row = cursor.fetchone()
                if row:
                    data, timestamp = row
                    if time.time() - timestamp < ttl:
                        logging.info(f"[{prefix_name}] Cache Hit: {target}")
                        return json.loads(data)
            except Exception as e:
                logging.warning(f"Cache read error: {e}")
            
            # 2. キャッシュミス時は実際のAPI通信を実行
            result = await func(*args, **kwargs)
            
            # 3. 成功時のみSQLiteへ書き込み (レートリミット等のエラーは保存しない)
            if result is not None and not (isinstance(result, dict) and result.get("error")):
                try:
                    cursor = _cache_conn.cursor()
                    cursor.execute("REPLACE INTO api_cache (cache_key, response_data, timestamp) VALUES (?, ?, ?)",
                                   (cache_key, json.dumps(result), time.time()))
                    _cache_conn.commit()
                except Exception as e:
                    logging.warning(f"Cache write error: {e}")
            
            return result
        return wrapper
    return decorator

def get_session():
    session = requests.Session()
    session.headers.update({"User-Agent": "WhoisBatchTool/2.4 (+RDAP)"})
    
    # ネットワーク瞬断に対応するための自動リトライ機能
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    
    # pool_connections と pool_maxsize を設定し、同期通信時のローカルポート枯渇を防ぐ（セマフォの代わり）
    adapter = HTTPAdapter(max_retries=retries, pool_connections=20, pool_maxsize=20)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    return session

session = get_session()

# ==========================================
# 共通パースロジック (Parser Functions)
# ==========================================

def _parse_rdap_response(data, url):
    network_name = data.get('name', '')
    if not network_name and 'handle' in data:
        network_name = data['handle']
    return {'name': network_name, 'json': data, 'url': url}

def _parse_domain_rdap_response(data, url):
    return {'json': data, 'url': str(url)}

def _process_securitytrails_records(combined_records, start_date=None, end_date=None):
    if not combined_records:
        return None
        
    combined_records.sort(key=lambda x: str(x.get('first_seen', '1970-01-01')), reverse=True)
    
    filtered_records = []
    is_date_filtered = False
    
    if start_date and end_date:
        is_date_filtered = True
        start_str = start_date.strftime("%Y-%m-%d")
        end_str = end_date.strftime("%Y-%m-%d")
        for rec in combined_records:
            rec_first = str(rec.get('first_seen', '9999-12-31'))
            rec_last = str(rec.get('last_seen', '1970-01-01'))
            if rec_first <= end_str and rec_last >= start_str:
                filtered_records.append(rec)
    else:
        filtered_records = combined_records[:20]

    if filtered_records:
        result_data = {
            "records": filtered_records,
            "is_date_filtered": is_date_filtered
        }
        if is_date_filtered:
            result_data["start_date"] = start_date.strftime("%Y-%m-%d")
            result_data["end_date"] = end_date.strftime("%Y-%m-%d")
        return result_data
    return None

def _parse_otx_response(data):
    records = []
    for item in data.get("passive_dns", []):
        host = item.get("hostname")
        if host:
            records.append({"hostname": host})
            
    return {
        "records": records,
        "meta": {
            "total_records": len(records),
            "total_pages": 1
        },
        "source": "AlienVault OTX"
    }

def _parse_internetdb_response(data):
    RISK_PORTS = {
        21: "Vuln:FTP",
        23: "Vuln:Telnet (High Risk)",
        1080: "Proxy:SOCKS",
        3128: "Proxy:Squid",
        5554: "IoT:Android/Emu",
        5555: "IoT:Android/ADB (High Risk)",
        7547: "Vuln:TR-069",
        1900: "Vuln:UPnP",
        8080: "Proxy:HTTP",
    }
    
    found_risks = []
    open_ports = data.get('ports', [])
    vulns = data.get('vulns', [])
    
    for p in open_ports:
        if p in RISK_PORTS:
            found_risks.append(RISK_PORTS[p])
    
    if vulns:
        found_risks.append(f"CVEs({len(vulns)})")
        
    if found_risks:
        unique_risks = sorted(list(set(found_risks)))
        return " / ".join(unique_risks)
    else:
        if open_ports:
            return "[No Match (Other Ports)]"
        return "[No Match]"

def _parse_vpnapi_response(data):
    if "security" in data:
        return data
    return None


# ==========================================
# 同期 API クライアント関数群 (Sync)
# ==========================================

def fetch_rdap_data(ip):
    url = RDAP_BOOTSTRAP_URL.format(ip=ip)
    try:
        response = session.get(url, timeout=TIMEOUT_RDAP, allow_redirects=True)
        response.raise_for_status()
        if response.status_code == 200:
            return _parse_rdap_response(response.json(), url)
    except requests.exceptions.Timeout:
        logging.warning(f"[RDAP Sync] タイムアウト: {ip}")
    except requests.exceptions.RequestException as e:
        logging.warning(f"[RDAP Sync] 通信エラー ({type(e).__name__}): {ip}")
    except ValueError as e:
        logging.error(f"[RDAP Sync] JSON解析エラー: {ip} - {str(e)}")
    except Exception as e:
        logging.error(f"[RDAP Sync] 予期せぬエラー: {ip} - {str(e)}")
    return None

def fetch_domain_rdap_data(domain):
    try:
        url = f"https://rdap.org/domain/{domain}"
        response = session.get(url, timeout=TIMEOUT_RDAP, allow_redirects=True)
        response.raise_for_status()
        if response.status_code == 200:
            return _parse_domain_rdap_response(response.json(), response.url)
    except requests.exceptions.Timeout:
        logging.warning(f"[Domain RDAP Sync] タイムアウト: {domain}")
    except requests.exceptions.RequestException as e:
        logging.warning(f"[Domain RDAP Sync] 通信エラー ({type(e).__name__}): {domain}")
    except ValueError as e:
        logging.error(f"[Domain RDAP Sync] JSON解析エラー: {domain} - {str(e)}")
    except Exception as e:
        logging.error(f"[Domain RDAP Sync] 予期せぬエラー: {domain} - {str(e)}")
    return None

def get_securitytrails_data(domain, api_key, start_date=None, end_date=None):
    if not api_key or not domain:
        return None
    
    headers = {"APIKEY": api_key, "accept": "application/json"}
    combined_records = []
    
    for record_type in ['a', 'aaaa']:
        try:
            url = f"https://api.securitytrails.com/v1/history/{domain}/dns/{record_type}"
            res = session.get(url, headers=headers, timeout=TIMEOUT_ST)
            res.raise_for_status() 
            data = res.json()
            if "records" in data:
                combined_records.extend(data["records"])
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 429:
                logging.warning(f"[SecurityTrails Sync] レートリミット到達: {domain} ({record_type})")
                return {"error": "rate_limit"}
            logging.warning(f"[SecurityTrails Sync] HTTPエラー: {domain} ({record_type})")
        except requests.exceptions.RequestException as e:
            logging.error(f"[SecurityTrails Sync] 通信エラー: {domain} ({record_type}) - {str(e)}")
        except ValueError as e:
            logging.error(f"[SecurityTrails Sync] JSON解析エラー: {domain} ({record_type}) - {str(e)}")

    return _process_securitytrails_records(combined_records, start_date, end_date)

def get_securitytrails_reverse_ip(ip, api_key, fetch_all=False):
    if not api_key or not ip:
        return None
    
    headers = {"APIKEY": api_key, "accept": "application/json", "content-type": "application/json"}
    ip_key = "ipv4" if is_ipv4(ip) else "ipv6"
    payload = {"filter": {ip_key: ip}}
    
    try:
        url = "https://api.securitytrails.com/v1/domains/list"
        res = session.post(url, headers=headers, json=payload, timeout=TIMEOUT_REV_IP)
        res.raise_for_status()
        data = res.json()
        
        if fetch_all:
            total_pages = data.get('meta', {}).get('total_pages', 1)
            current_page = 1
            while current_page < total_pages and current_page <= 100:
                current_page += 1
                payload['page'] = current_page
                try:
                    time.sleep(1) 
                    res_next = session.post(url, headers=headers, json=payload, timeout=TIMEOUT_REV_IP)
                    res_next.raise_for_status()
                    data_next = res_next.json()
                    if 'records' in data_next:
                        data['records'].extend(data_next['records'])
                except requests.exceptions.HTTPError as e:
                    if e.response is not None and e.response.status_code == 429:
                        logging.warning(f"[SecurityTrails RevIP Sync] ページネーション中にレートリミット到達: {ip}")
                        data['error'] = "rate_limit_during_pagination"
                        break
                    else:
                        logging.warning(f"[SecurityTrails RevIP Sync] ページネーション中HTTPエラー: {ip} - {str(e)}")
                        break
                except Exception as e:
                    logging.error(f"[SecurityTrails RevIP Sync] ページネーション中予期せぬエラー: {ip} - {str(e)}")
                    break
        return data
        
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 429:
            logging.warning(f"[SecurityTrails RevIP Sync] レートリミット到達: {ip}")
            return {"error": "rate_limit"}
        logging.warning(f"[SecurityTrails RevIP Sync] HTTPエラー: {ip} - {str(e)}")
        return None
    except Exception as e:
        logging.error(f"[SecurityTrails RevIP Sync] 予期せぬエラー: {ip} - {str(e)}")
        return None

def get_alienvault_otx_pdns(ip, otx_api_key):
    if not otx_api_key or not ip:
        return None
    
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/passive_dns"
    headers = {"X-OTX-API-KEY": otx_api_key}
    
    try:
        res = session.get(url, headers=headers, timeout=TIMEOUT_OTX)
        res.raise_for_status()
        return _parse_otx_response(res.json())
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 429:
            logging.warning(f"[OTX Sync] レートリミット到達: {ip}")
            return {"error": "rate_limit"}
        logging.warning(f"[OTX Sync] HTTPエラー ({e.response.status_code if e.response else '不明'}): {ip}")
        return None
    except requests.exceptions.RequestException as e:
        logging.error(f"[OTX Sync] 通信エラー: {ip} - {str(e)}")
        return None
    except Exception as e:
        logging.error(f"[OTX Sync] 予期せぬエラー: {ip} - {str(e)}")
        return None

def check_internetdb_risk(ip, max_retries=3):
    for attempt in range(max_retries):
        try:
            url = f"https://internetdb.shodan.io/{ip}"
            response = session.get(url, timeout=TIMEOUT_API_FAST)
            
            if response.status_code == 404:
                return "[データなし]"
            elif response.status_code == 429:
                return "エラー: Shodanのアクセス制限超過"
            elif 500 <= response.status_code < 600:
                return f"エラー: Shodanサーバー側の障害 ({response.status_code})"
            elif response.status_code != 200:
                return f"エラー: Shodan通信障害 ({response.status_code})"
                
            return _parse_internetdb_response(response.json())
            
        except requests.exceptions.ConnectionError as e:
            logging.error(f"[InternetDB Sync] 接続エラー: {ip} - {str(e)}")
            raise
        except requests.exceptions.Timeout:
            logging.warning(f"[InternetDB Sync] タイムアウト (試行 {attempt+1}/{max_retries}): {ip}")
            if attempt == max_retries - 1:
                return "エラー: Shodan応答タイムアウト (サーバー混雑)"
            time.sleep(1.5)
        except requests.exceptions.RequestException as e:
            logging.error(f"[InternetDB Sync] 通信エラー: {ip} - {str(e)}")
            return "エラー: ネットワーク接続に失敗しました"
        except ValueError as e:
            logging.error(f"[InternetDB Sync] JSON解析エラー: {ip} - {str(e)}")
            return "エラー: データ解析失敗 (相手から不正なデータが返されました)"
        except Exception as e:
            logging.error(f"[InternetDB Sync] 予期せぬエラー: {ip} - {str(e)}")
            return "エラー: 予期せぬシステム例外"

def get_vpnapi_data(ip, api_key):
    if not api_key:
        return None
    try:
        url = VPNAPI_URL.format(ip=ip, key=api_key)
        response = session.get(url, timeout=TIMEOUT_API_FAST)
        
        if response.status_code == 429:
            logging.warning(f"[VPNAPI Sync] レートリミット到達: {ip}")
            return {"error": "rate_limit"}
            
        response.raise_for_status()
        if response.status_code == 200:
            return _parse_vpnapi_response(response.json())
    except requests.exceptions.Timeout:
        logging.warning(f"[VPNAPI Sync] タイムアウト: {ip}")
    except requests.exceptions.RequestException as e:
        logging.warning(f"[VPNAPI Sync] 通信エラー ({type(e).__name__}): {ip}")
    except ValueError as e:
        logging.error(f"[VPNAPI Sync] JSON解析エラー: {ip} - {str(e)}")
    except Exception as e:
        logging.error(f"[VPNAPI Sync] 予期せぬエラー: {ip} - {str(e)}")
    return None

def fetch_classic_whois(target):
    try:
        is_ip = False
        try:
            ipaddress.ip_address(target)
            is_ip = True
        except ValueError:
            pass
            
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT_API_FAST)
            s.connect(('whois.iana.org', 43))
            if is_ip:
                s.send((target + "\r\n").encode('utf-8'))
            else:
                tld = target.split('.')[-1].lower()
                s.send((tld + "\r\n").encode('utf-8'))
            
            response = b""
            while True:
                data = s.recv(4096)
                if not data: break
                response += data
            
        iana_response = response.decode('utf-8', errors='replace')
        whois_server = None
        for line in iana_response.splitlines():
            line_lower = line.lower()
            if line_lower.startswith('whois:'):
                whois_server = line.split(':', 1)[1].strip()
                break
            elif line_lower.startswith('refer:'):
                whois_server = line.split(':', 1)[1].strip()
                break
        
        if not whois_server:
            if is_ip:
                whois_server = "whois.arin.net" 
            else:
                tld = target.split('.')[-1].lower()
                whois_server = f"{tld}.whois-servers.net" 
            
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT_API_FAST)
            s.connect((whois_server, 43))
            
            if not is_ip and target.endswith('.jp'):
                query_str = f"{target}/e\r\n"
            else:
                query_str = f"{target}\r\n"
                
            s.send(query_str.encode('utf-8'))
            whois_text = b""
            while True:
                data = s.recv(4096)
                if not data: break
                whois_text += data
        
        try:
            decoded_text = whois_text.decode('iso-2022-jp').strip()
        except UnicodeDecodeError:
            decoded_text = whois_text.decode('utf-8', errors='replace').strip()
            
        if not decoded_text:
            return "Error: WHOISサーバーに接続できましたが、データが空でした（応答なし）。\n短時間での連続アクセスによる一時的なブロック（Rate Limit）の可能性が高いです。", whois_server
            
        return decoded_text, whois_server
        
    except socket.timeout:
        server_name = whois_server if 'whois_server' in locals() and whois_server else "不明"
        error_msg = "Error: WHOISサーバーからの応答がタイムアウトしました。..."
        logging.warning(f"[Classic WHOIS] タイムアウト: {target}")
        return error_msg, server_name
    except ConnectionRefusedError:
        error_msg = "Error: WHOISサーバーへの接続が拒否されました。\n接続制限、または相手方サーバーがダウンしている可能性があります。"
        logging.warning(f"[Classic WHOIS] 接続拒否: {target}")
        return error_msg, whois_server if 'whois_server' in locals() and whois_server else "不明"
    except Exception as e:
        error_msg = f"Error: WHOIS情報の取得中にシステムエラーが発生しました ({str(e)})"
        logging.error(f"[Classic WHOIS] エラー: {target} - {str(e)}")
        return error_msg, "不明"

def resolve_ip_nslookup(ip):
    hostnames = []
    raw_output = ""
    try:
        rev_name = dns.reversename.from_address(ip)
        
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = random.sample(PUBLIC_DNS_SERVERS, 2)
        # DNSは高速足切りを適用
        resolver.timeout = TIMEOUT_DNS
        resolver.lifetime = TIMEOUT_DNS
        
        answers = resolver.resolve(rev_name, 'PTR')       
       
        raw_lines = []
        for rdata in answers:
            host = rdata.target.to_text(omit_final_dot=True)
            if host and host not in hostnames:
                hostnames.append(host)
            raw_lines.append(f"{rev_name} domain name pointer {host}")
            
        raw_output = "\n".join(raw_lines)
        
    except ImportError:
        raw_output = "Error: 'dnspython' ライブラリがインストールされていません。\nターミナルで 'pip install dnspython' を実行してください。"
    except dns.resolver.NXDOMAIN:
        raw_output = f"NXDOMAIN: {ip} に対するPTRレコードが見つかりませんでした。"
    except dns.resolver.NoAnswer:
        raw_output = f"NoAnswer: {ip} に対するPTRレコードの応答がありません。"
    except (dns.resolver.Timeout, dns.exception.Timeout):
        raw_output = "Error: DNSクエリがタイムアウトしました。"
        logging.warning(f"[DNS PTR] タイムアウト: {ip}")
    except Exception as e:
        raw_output = f"Error executing dnspython: {str(e)}"
        logging.error(f"[DNS PTR] エラー: {ip} - {str(e)}")
    
    return hostnames, raw_output

def fetch_ipinfo_bulk(ip_list, api_key):
    if not ip_list or not api_key:
        return {}
    
    results = {}
    chunk_size = 1000
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    for i in range(0, len(ip_list), chunk_size):
        chunk = ip_list[i:i + chunk_size]
        try:
            url = f"https://ipinfo.io/batch?token={api_key}"
            response = session.post(url, headers=headers, json=chunk, timeout=TIMEOUT_BULK)
            if response.status_code == 200:
                batch_res = response.json()
                if isinstance(batch_res, dict):
                    valid_res = {k: v for k, v in batch_res.items() if isinstance(v, dict) and not v.get('error')}
                    results.update(valid_res)
        except Exception as e:
            logging.error(f"[IPinfo Bulk] エラー: {str(e)}")
            pass
            
    return results


# ==========================================
# 非同期 API クライアント関数群 (Async)
# ==========================================

@async_sqlite_cache("rdap_ip", ttl=86400 * 7)  # 7日間キャッシュ
@async_retry_with_backoff(max_retries=3, base_delay=1.0)
async def fetch_rdap_data_async(ip, session_async):
    url = RDAP_BOOTSTRAP_URL.format(ip=ip)    
    async with session_async.get(url, timeout=TIMEOUT_RDAP, allow_redirects=True) as response:
        response.raise_for_status()
        if response.status == 200:
            data = await response.json()
            return _parse_rdap_response(data, url)
    return None

@async_sqlite_cache("rdap_domain", ttl=86400 * 7)  # 7日間キャッシュ
@async_retry_with_backoff(max_retries=3, base_delay=1.0)
async def fetch_domain_rdap_data_async(domain, session_async):
    url = f"https://rdap.org/domain/{domain}"
    async with session_async.get(url, timeout=TIMEOUT_RDAP, allow_redirects=True) as response:
        response.raise_for_status()
        if response.status == 200:
            data = await response.json()
            return _parse_domain_rdap_response(data, response.url)
    return None

@async_sqlite_cache("st_dns", ttl=86400 * 7)  # 7日間キャッシュ
@async_retry_with_backoff(max_retries=3, base_delay=1.0)
async def get_securitytrails_data_async(domain, api_key, session_async, start_date=None, end_date=None):
    if not api_key or not domain:
        return None
    
    headers = {"APIKEY": api_key, "accept": "application/json"}
    combined_records = []
    
    for record_type in ['a', 'aaaa']:
        url = f"https://api.securitytrails.com/v1/history/{domain}/dns/{record_type}"
        async with session_async.get(url, headers=headers, timeout=TIMEOUT_ST) as res:
            if res.status == 429:
                logging.warning(f"[SecurityTrails Async] レートリミット到達: {domain} ({record_type})")
                return {"error": "rate_limit"}
            res.raise_for_status()
            data = await res.json()
            if "records" in data:
                combined_records.extend(data["records"])

    return _process_securitytrails_records(combined_records, start_date, end_date)

@async_sqlite_cache("st_rev_ip", ttl=86400 * 7)  # 7日間キャッシュ
@async_retry_with_backoff(max_retries=3, base_delay=1.0)
async def get_securitytrails_reverse_ip_async(ip, api_key, session_async, fetch_all=False):
    if not api_key or not ip:
        return None
    
    headers = {"APIKEY": api_key, "accept": "application/json", "content-type": "application/json"}
    ip_key = "ipv4" if is_ipv4(ip) else "ipv6"
    payload = {"filter": {ip_key: ip}}
    
    url = "https://api.securitytrails.com/v1/domains/list"
    async with session_async.post(url, headers=headers, json=payload, timeout=TIMEOUT_REV_IP) as res:
        if res.status == 429:
            logging.warning(f"[SecurityTrails RevIP Async] レートリミット到達: {ip}")
            return {"error": "rate_limit"}
            
        res.raise_for_status()
        data = await res.json()
        
        if fetch_all:
            total_pages = data.get('meta', {}).get('total_pages', 1)
            current_page = 1
            while current_page < total_pages and current_page <= 100:
                current_page += 1
                payload['page'] = current_page
                try:
                    await asyncio.sleep(1) # API制限回避用のウェイト
                    async with session_async.post(url, headers=headers, json=payload, timeout=TIMEOUT_REV_IP) as res_next:
                        if res_next.status == 429:
                            logging.warning(f"[SecurityTrails RevIP Async] ページネーション中レートリミット: {ip}")
                            data['error'] = "rate_limit_during_pagination"
                            break
                        res_next.raise_for_status()
                        data_next = await res_next.json()
                        if 'records' in data_next:
                            data['records'].extend(data_next['records'])
                except Exception as e:
                    logging.error(f"[SecurityTrails RevIP Async] ページネーション中エラーにより中断: {ip} - {str(e)}")
                    break
        return data

@async_sqlite_cache("otx_pdns", ttl=86400 * 7)  # 7日間キャッシュ
@async_retry_with_backoff(max_retries=3, base_delay=1.0)
async def get_alienvault_otx_pdns_async(ip, otx_api_key, session_async):
    if not otx_api_key or not ip:
        return None
    
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/passive_dns"
    headers = {"X-OTX-API-KEY": otx_api_key}
    
    async with session_async.get(url, headers=headers, timeout=TIMEOUT_OTX) as res:
        if res.status == 429:
            logging.warning(f"[OTX Async] レートリミット到達: {ip}")
            return {"error": "rate_limit"}
            
        res.raise_for_status()
        return _parse_otx_response(await res.json())

@async_sqlite_cache("internetdb", ttl=86400 * 3)  # リスク情報は変動しやすいため3日に短縮
@async_retry_with_backoff(max_retries=3, base_delay=1.0)
async def check_internetdb_risk_async(ip, session_async):
    url = f"https://internetdb.shodan.io/{ip}"
    async with session_async.get(url, timeout=TIMEOUT_API_FAST) as response:
        if response.status == 404:
            return "[データなし]"
        response.raise_for_status()
        return _parse_internetdb_response(await response.json())
                
@async_sqlite_cache("vpnapi", ttl=86400 * 3)  # 変動しやすいため3日間キャッシュ
@async_retry_with_backoff(max_retries=3, base_delay=1.0)
async def get_vpnapi_data_async(ip, api_key, session_async):
    if not api_key:
        return None
    
    url = VPNAPI_URL.format(ip=ip, key=api_key)
    async with session_async.get(url, timeout=TIMEOUT_API_FAST) as response:
        if response.status == 429:
            logging.warning(f"[VPNAPI Async] レートリミット到達: {ip}")
            return {"error": "rate_limit"}
            
        response.raise_for_status()
        if response.status == 200:
            return _parse_vpnapi_response(await response.json())
    return None
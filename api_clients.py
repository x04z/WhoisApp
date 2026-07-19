# api_clients.py
import requests
import asyncio
import aiohttp
import time
import socket
import ipaddress
import random
import dns.resolver
import dns.reversename
import dns.exception
import streamlit as st
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from utils import query_local_proxy_db

# Step 1と2で作成した外部ファイルからのインポート
from constants import RDAP_BOOTSTRAP_URL, VPNAPI_URL, PUBLIC_DNS_SERVERS
from utils import is_ipv4

@st.cache_resource
def get_session():
    session = requests.Session()
    session.headers.update({"User-Agent": "WhoisBatchTool/2.4 (+RDAP)"})
    
    # ネットワーク瞬断に対応するための自動リトライ機能 (3回, バックオフ)
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    return session

session = get_session()

# ==========================================
# 同期 API クライアント関数群
# ==========================================

# RDAPデータ取得関数 (公式台帳への照会)
def fetch_rdap_data(ip):
    try:
        url = RDAP_BOOTSTRAP_URL.format(ip=ip)
        # 海外レジストリ(AFRINIC等)の遅延を考慮し、タイムアウトを8秒に設定
        response = session.get(url, timeout=8, allow_redirects=True)
        response.raise_for_status()
        if response.status_code == 200:
            data = response.json()
            # 汎用的なRDAPレスポンスから名前を探す (name, handle, remarks)
            network_name = data.get('name', '')
            if not network_name and 'handle' in data:
                network_name = data['handle']
            return {'name': network_name, 'json': data, 'url': url}
    except requests.exceptions.Timeout:
        pass
    except requests.exceptions.RequestException:
        pass
    except ValueError:
        pass
    return None

# ドメイン専用RDAP取得関数
@st.cache_data(ttl=3600, show_spinner=False, max_entries=1000)
def fetch_domain_rdap_data(domain):
    """ ドメイン専用のRDAP情報を取得する関数 (rdap.org リゾルバを利用) """
    try:
        url = f"https://rdap.org/domain/{domain}"
        response = session.get(url, timeout=8, allow_redirects=True)
        response.raise_for_status()
        if response.status_code == 200:
            data = response.json()
            return {'json': data, 'url': response.url}
    except requests.exceptions.Timeout:
        pass
    except requests.exceptions.RequestException:
        pass
    except ValueError:
        pass
    return None

@st.cache_data(ttl=3600, show_spinner=False, max_entries=2000)
def fetch_classic_whois(target):
    """ OS非依存：Port 43を利用した旧式WHOIS取得 (ドメイン・IP両対応) """
    try:
        is_ip = False
        try:
            ipaddress.ip_address(target)
            is_ip = True
        except ValueError:
            pass
            
        # 1. IANAから権威WHOISサーバーを特定
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
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
        
        # IANAに記載がない場合の汎用推測
        if not whois_server:
            if is_ip:
                whois_server = "whois.arin.net" # IPのフォールバック
            else:
                tld = target.split('.')[-1].lower()
                whois_server = f"{tld}.whois-servers.net" # ドメインのフォールバック
            
        # 2. 権威サーバーに直接クエリを投げる
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((whois_server, 43))
            
            # JPRS (.jp) の場合、英語出力を強制するために /e を付与する
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
        
        # エンコーディング対応 (JPRS等のISO-2022-JP対応)
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
        return error_msg, server_name
    except ConnectionRefusedError:
        error_msg = "Error: WHOISサーバーへの接続が拒否されました。\n接続制限、または相手方サーバーがダウンしている可能性があります。"
        return error_msg, whois_server if 'whois_server' in locals() and whois_server else "不明"
    except Exception as e:
        error_msg = f"Error: WHOIS情報の取得中にシステムエラーが発生しました ({str(e)})"
        return error_msg, "不明"

# SecurityTrails API取得関数 (過去のAレコード・AAAAレコード履歴)
def get_securitytrails_data(domain, api_key, start_date=None, end_date=None):
    """ SecurityTrails APIを使用してドメインの過去のIP履歴(IPv4/IPv6)を取得し、期間でフィルタリングする """
    if not api_key or not domain:
        return None
    
    headers = {
        "APIKEY": api_key,
        "accept": "application/json"
    }
    
    combined_records = []
    
    # Aレコード (IPv4) 取得
    try:
        url_a = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
        res_a = session.get(url_a, headers=headers, timeout=10)
        res_a.raise_for_status() 
        data_a = res_a.json()
        if "records" in data_a:
            combined_records.extend(data_a["records"])
            
    except requests.exceptions.Timeout:
        pass
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 429:
            return {"error": "rate_limit"}
        pass
    except requests.exceptions.RequestException as e:
        pass
    except ValueError:
        pass

    # AAAAレコード (IPv6) 取得
    try:
        url_aaaa = f"https://api.securitytrails.com/v1/history/{domain}/dns/aaaa"
        res_aaaa = session.get(url_aaaa, headers=headers, timeout=10)
        res_aaaa.raise_for_status()
        data_aaaa = res_aaaa.json()
        if "records" in data_aaaa:
            combined_records.extend(data_aaaa["records"])
            
    except requests.exceptions.Timeout:
        pass
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 429:
            return {"error": "rate_limit"}
        pass
    except requests.exceptions.RequestException as e:
        pass
    except ValueError:
        pass

    if combined_records:
        # まず first_seen (初回観測日) の降順で全体をソート (新しい順)
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
                
                # レコードの生存期間が指定された期間と重なっているかを判定
                if rec_first <= end_str and rec_last >= start_str:
                    filtered_records.append(rec)
        else:
            # 期間指定がない場合は最新20件のみを抽出
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

# SecurityTrails API取得関数 (Reverse IP / ドメイン逆検索)
def get_securitytrails_reverse_ip(ip, api_key, fetch_all=False):
    """ SecurityTrails APIを使用してIPアドレスに紐づくドメイン群を取得する """
    if not api_key or not ip:
        return None
    
    headers = {
        "APIKEY": api_key,
        "accept": "application/json",
        "content-type": "application/json"
    }
    
    ip_key = "ipv4" if is_ipv4(ip) else "ipv6"
    payload = {"filter": {ip_key: ip}}
    
    try:
        url = "https://api.securitytrails.com/v1/domains/list"
        res = session.post(url, headers=headers, json=payload, timeout=10)
        res.raise_for_status()
        data = res.json()
        
        if fetch_all:
            total_pages = data.get('meta', {}).get('total_pages', 1)
            current_page = 1
            while current_page < total_pages and current_page <= 100:
                current_page += 1
                payload['page'] = current_page
                try:
                    time.sleep(1) # API制限回避のウェイト
                    res_next = session.post(url, headers=headers, json=payload, timeout=10)
                    res_next.raise_for_status()
                    data_next = res_next.json()
                    if 'records' in data_next:
                        data['records'].extend(data_next['records'])
                except requests.exceptions.HTTPError as e:
                    if e.response is not None and e.response.status_code == 429:
                        data['error'] = "rate_limit_during_pagination"
                        break
                    else:
                        break
                except Exception:
                    break
        return data
        
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 429:
            return {"error": "rate_limit"}
        return None
    except Exception:
        return None
    
# AlienVault OTX API取得関数 (Passive DNS / Reverse IP 代替)
def get_alienvault_otx_pdns(ip, otx_api_key):
    """ AlienVault OTX APIを使用してIPアドレスに紐づくドメイン群(Passive DNS)を取得する """
    if not otx_api_key or not ip:
        return None
    
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/passive_dns"
    headers = {"X-OTX-API-KEY": otx_api_key}
    
    try:
        res = session.get(url, headers=headers, timeout=10)
        res.raise_for_status()
        data = res.json()
        
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
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 429:
            return {"error": "rate_limit"}
        return None
    except Exception:
        return None

# Shodan InternetDB API Logic (No API Key Required)
def check_internetdb_risk(ip, max_retries=3):
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
    
    for attempt in range(max_retries):
        try:
            url = f"https://internetdb.shodan.io/{ip}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 404:
                return "[データなし]"
            elif response.status_code == 429:
                return "エラー: Shodanのアクセス制限超過"
            elif 500 <= response.status_code < 600:
                return f"エラー: Shodanサーバー側の障害 ({response.status_code})"
            elif response.status_code != 200:
                return f"エラー: Shodan通信障害 ({response.status_code})"
                
            data = response.json()
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
            
        except requests.exceptions.ConnectionError:
            raise
        except requests.exceptions.Timeout:
            if attempt == max_retries - 1:
                return "エラー: Shodan応答タイムアウト (サーバー混雑)"
            time.sleep(1.5)
        except requests.exceptions.HTTPError:
            return "エラー: Shodan通信失敗 (HTTPエラー)"
        except requests.exceptions.RequestException:
            return "エラー: ネットワーク接続に失敗しました"
        except ValueError:
            return "エラー: データ解析失敗 (相手から不正なデータが返されました)"
        
# VPNAPI.io 取得関数
def get_vpnapi_data(ip, api_key):
    if not api_key:
        return None
    try:
        url = VPNAPI_URL.format(ip=ip, key=api_key)
        response = session.get(url, timeout=5)
        
        if response.status_code == 429:
            return {"error": "rate_limit"}
            
        response.raise_for_status()
        if response.status_code == 200:
            data = response.json()
            if "security" in data:
                return data
    except requests.exceptions.Timeout:
        pass
    except requests.exceptions.RequestException:
        pass
    except ValueError:
        pass
    return None

# IP逆引き関数 (PTRレコード取得 - dnspython使用/高信頼設定)
def resolve_ip_nslookup(ip):
    """ dnspythonを使用して、外部DNSサーバーを直接指定し、逆引き(PTR)ホスト名を取得する """
    hostnames = []
    raw_output = ""
    try:
        rev_name = dns.reversename.from_address(ip)
        
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = random.sample(PUBLIC_DNS_SERVERS, 2)
        resolver.timeout = 3
        resolver.lifetime = 3
        
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
    except Exception as e:
        raw_output = f"Error executing dnspython: {str(e)}"
    
    return hostnames, raw_output

def fetch_ipinfo_bulk(ip_list, api_key):
    """ IPinfoの/batchエンドポイントを使用して最大1000件を一括取得する """
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
            response = session.post(url, headers=headers, json=chunk, timeout=15)
            if response.status_code == 200:
                batch_res = response.json()
                if isinstance(batch_res, dict):
                    valid_res = {k: v for k, v in batch_res.items() if isinstance(v, dict) and not v.get('error')}
                    results.update(valid_res)
        except Exception as e:
            import logging
            logging.warning(f"IPinfo Bulk API Error: {e}")
            pass
            
    return results


# ==========================================
# 非同期 API クライアント関数群
# ==========================================

async def fetch_rdap_data_async(ip, session):
    try:
        url = RDAP_BOOTSTRAP_URL.format(ip=ip)
        async with session.get(url, timeout=8, allow_redirects=True) as response:
            response.raise_for_status()
            if response.status == 200:
                data = await response.json()
                network_name = data.get('name', '')
                if not network_name and 'handle' in data:
                    network_name = data['handle']
                return {'name': network_name, 'json': data, 'url': url}
    except asyncio.TimeoutError:
        pass
    except aiohttp.ClientError:
        pass
    except ValueError:
        pass
    return None

async def fetch_domain_rdap_data_async(domain, session):
    try:
        url = f"https://rdap.org/domain/{domain}"
        async with session.get(url, timeout=8, allow_redirects=True) as response:
            response.raise_for_status()
            if response.status == 200:
                data = await response.json()
                return {'json': data, 'url': str(response.url)}
    except asyncio.TimeoutError:
        pass
    except aiohttp.ClientError:
        pass
    except ValueError:
        pass
    return None

async def get_securitytrails_data_async(domain, api_key, session, start_date=None, end_date=None):
    if not api_key or not domain:
        return None
    
    headers = {
        "APIKEY": api_key,
        "accept": "application/json"
    }
    
    combined_records = []
    
    try:
        url_a = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
        async with session.get(url_a, headers=headers, timeout=10) as res_a:
            if res_a.status == 429:
                return {"error": "rate_limit"}
            res_a.raise_for_status()
            data_a = await res_a.json()
            if "records" in data_a:
                combined_records.extend(data_a["records"])
    except Exception:
        pass

    try:
        url_aaaa = f"https://api.securitytrails.com/v1/history/{domain}/dns/aaaa"
        async with session.get(url_aaaa, headers=headers, timeout=10) as res_aaaa:
            if res_aaaa.status == 429:
                return {"error": "rate_limit"}
            res_aaaa.raise_for_status()
            data_aaaa = await res_aaaa.json()
            if "records" in data_aaaa:
                combined_records.extend(data_aaaa["records"])
    except Exception:
        pass

    if combined_records:
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

async def get_securitytrails_reverse_ip_async(ip, api_key, session, fetch_all=False, max_retries=3):
    if not api_key or not ip:
        return None
    
    headers = {
        "APIKEY": api_key,
        "accept": "application/json",
        "content-type": "application/json"
    }
    
    ip_key = "ipv4" if is_ipv4(ip) else "ipv6"
    payload = {"filter": {ip_key: ip}}
    
    for attempt in range(max_retries):
        try:
            url = "https://api.securitytrails.com/v1/domains/list"
            async with session.post(url, headers=headers, json=payload, timeout=20) as res:
                if res.status == 429:
                    return {"error": "rate_limit"}
                if res.status >= 500:
                    await asyncio.sleep(1.5 * (attempt + 1))
                    continue
                    
                res.raise_for_status()
                data = await res.json()
                
                if fetch_all:
                    total_pages = data.get('meta', {}).get('total_pages', 1)
                    current_page = 1
                    while current_page < total_pages and current_page <= 100:
                        current_page += 1
                        payload['page'] = current_page
                        try:
                            await asyncio.sleep(1)
                            async with session.post(url, headers=headers, json=payload, timeout=20) as res_next:
                                if res_next.status == 429:
                                    data['error'] = "rate_limit_during_pagination"
                                    break
                                res_next.raise_for_status()
                                data_next = await res_next.json()
                                if 'records' in data_next:
                                    data['records'].extend(data_next['records'])
                        except Exception:
                            break
                return data
        except asyncio.TimeoutError:
            if attempt < max_retries - 1:
                await asyncio.sleep(2)
            else:
                pass
        except Exception:
            if attempt < max_retries - 1:
                await asyncio.sleep(2)
            else:
                pass
    return None

async def get_alienvault_otx_pdns_async(ip, otx_api_key, session, max_retries=3):
    if not otx_api_key or not ip:
        return None
    
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/passive_dns"
    headers = {"X-OTX-API-KEY": otx_api_key}
    
    for attempt in range(max_retries):
        try:
            async with session.get(url, headers=headers, timeout=20) as res:
                if res.status == 429:
                    return {"error": "rate_limit"}
                if res.status >= 500:
                    await asyncio.sleep(1.5 * (attempt + 1))
                    continue
                    
                res.raise_for_status()
                data = await res.json()
                
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
        except asyncio.TimeoutError:
            if attempt < max_retries - 1:
                await asyncio.sleep(2)
            else:
                pass
        except Exception:
            if attempt < max_retries - 1:
                await asyncio.sleep(2)
            else:
                pass
    return None

async def check_internetdb_risk_async(ip, session, max_retries=3):
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
    
    for attempt in range(max_retries):
        try:
            url = f"https://internetdb.shodan.io/{ip}"
            async with session.get(url, timeout=5) as response:
                if response.status == 404:
                    return "[データなし]"
                elif response.status == 429:
                    return "エラー: Shodanのアクセス制限超過"
                elif 500 <= response.status < 600:
                    return f"エラー: Shodanサーバー側の障害 ({response.status})"
                elif response.status != 200:
                    return f"エラー: Shodan通信障害 ({response.status})"
                    
                data = await response.json()
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
                
        except aiohttp.ClientConnectionError:
            raise
        except asyncio.TimeoutError:
            if attempt == max_retries - 1:
                return "エラー: Shodan応答タイムアウト (サーバー混雑)"
            await asyncio.sleep(1.5)
        except Exception:
            return "エラー: ネットワーク接続に失敗しました"

async def get_vpnapi_data_async(ip, api_key, session):
    if not api_key:
        return None
    try:
        url = VPNAPI_URL.format(ip=ip, key=api_key)
        async with session.get(url, timeout=5) as response:
            if response.status == 429:
                return {"error": "rate_limit"}
            response.raise_for_status()
            if response.status == 200:
                data = await response.json()
                if "security" in data:
                    return data
    except Exception:
        pass
    return None
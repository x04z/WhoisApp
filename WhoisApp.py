import streamlit as st
from streamlit_option_menu import option_menu
import pandas as pd
import requests
import time
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import socket
import struct
import ipaddress
from urllib.parse import quote
import math
import random
import altair as alt 
alt.data_transformers.disable_max_rows() # 5000行以上の大容量データセットの描画を許可する
import json 
import io 
import re 
import subprocess
import dns.resolver
import dns.reversename
import dns
import zipfile
import datetime
import tempfile
import os
import bisect
import uuid
import duckdb
import aiohttp
import asyncio
import html

# ==========================================
#  [Local User Config] API Key Loading
# ==========================================
# .streamlit/secrets.toml から優先して読み込み、設定がない場合は空文字を返す
try:
    HARDCODED_IPINFO_KEY = st.secrets.get("IPINFO_KEY", "")
    HARDCODED_VPNAPI_KEY = st.secrets.get("VPNAPI_KEY", "")
    HARDCODED_SECURITYTRAILS_KEY = st.secrets.get("SECURITYTRAILS_KEY", "")
    HARDCODED_OTX_KEY = st.secrets.get("OTX_KEY", "")
except FileNotFoundError:
    HARDCODED_IPINFO_KEY = ""
    HARDCODED_VPNAPI_KEY = ""
    HARDCODED_SECURITYTRAILS_KEY = ""
    HARDCODED_OTX_KEY = ""
# ==========================================

BACKUP_FILE = "whois_recovery_session.json"
BACKUP_DETAILS_FILE = "whois_recovery_details.json"

def save_recovery_data():
    """ 検索進捗と詳細データをローカルに退避させる """
    if IS_PUBLIC_MODE: return # パブリック環境ではストレージ保護のため無効化
    try:
        session_data = {
            'raw_results': st.session_state.raw_results,
            'targets_cache': st.session_state.targets_cache,
            'deferred_ips': st.session_state.deferred_ips,
            'finished_ips': list(st.session_state.finished_ips),
            'target_freq_map': st.session_state.target_freq_map,
            'cidr_cache': st.session_state.cidr_cache,
            'learned_proxy_isps': st.session_state.learned_proxy_isps,
            'resolved_dns_map': st.session_state.resolved_dns_map,
        }
        
        # 一時ファイルに完全に書き込んでからリネーム(アトミック書き込み)し、クラッシュ時のデータ破損を防ぐ
        tmp_session = BACKUP_FILE + ".tmp"
        tmp_details = BACKUP_DETAILS_FILE + ".tmp"
        
        with open(tmp_session, "w", encoding="utf-8") as f:
            json.dump(session_data, f, ensure_ascii=False)
        with open(tmp_details, "w", encoding="utf-8") as f:
            json.dump(st.session_state.detailed_data, f, ensure_ascii=False)
            
        os.replace(tmp_session, BACKUP_FILE)
        os.replace(tmp_details, BACKUP_DETAILS_FILE)
    except TypeError as e:
        import logging
        logging.error(f"[Recovery Save Error] JSONシリアライズ失敗: {e}")
    except OSError as e:
        import logging
        logging.error(f"[Recovery Save Error] ファイル保存/置換失敗: {e}")

def load_recovery_data():
    """ 中断されたデータを復元し、再開フラグを立てる """
    if IS_PUBLIC_MODE: return False
    try:
        if os.path.exists(BACKUP_FILE) and os.path.exists(BACKUP_DETAILS_FILE):
            with open(BACKUP_FILE, "r", encoding="utf-8") as f:
                session_data = json.load(f)
            with open(BACKUP_DETAILS_FILE, "r", encoding="utf-8") as f:
                detailed_data = json.load(f)
                
            st.session_state.raw_results = session_data['raw_results']
            st.session_state.targets_cache = session_data['targets_cache']
            st.session_state.deferred_ips = session_data['deferred_ips']
            st.session_state.finished_ips = set(session_data['finished_ips'])
            st.session_state.target_freq_map = session_data['target_freq_map']
            st.session_state.cidr_cache = session_data['cidr_cache']
            st.session_state.learned_proxy_isps = session_data['learned_proxy_isps']
            st.session_state.resolved_dns_map = session_data['resolved_dns_map']
            st.session_state.detailed_data = detailed_data
            
            st.session_state.is_searching = True
            st.session_state.cancel_search = False
            return True
    except Exception:
        pass
    return False

def clear_recovery_data():
    """ 正常終了時や新規検索時にバックアップを破棄する """
    if IS_PUBLIC_MODE: return
    try:
        if os.path.exists(BACKUP_FILE): os.remove(BACKUP_FILE)
        if os.path.exists(BACKUP_DETAILS_FILE): os.remove(BACKUP_DETAILS_FILE)
    except OSError as e:
        import logging
        logging.warning(f"バックアップファイルの削除に失敗しました: {e}")

import platform

def open_local_path(path):
    """ ローカルPCでファイルやフォルダをOSの標準機能で開く """
    if IS_PUBLIC_MODE: return
    try:
        if platform.system() == 'Windows':
            os.startfile(path)
        elif platform.system() == 'Darwin': # macOS
            subprocess.Popen(['open', path])
        else: # Linux etc.
            subprocess.Popen(['xdg-open', path])
    except Exception as e:
        st.error(f"ファイルを開けませんでした: {e}")

def save_file_to_local(filename, data, export_dir=None):
    """ ローカル環境専用: ファイルを直接ディスクに保存して絶対パスを返す """
    if not export_dir:
        export_dir = os.path.join(os.getcwd(), "exports")
    
    os.makedirs(export_dir, exist_ok=True)
    filepath = os.path.abspath(os.path.join(export_dir, filename))
    
    mode = "wb" if isinstance(data, bytes) else "w"
    encoding = None if isinstance(data, bytes) else "utf-8"
    
    with open(filepath, mode, encoding=encoding) as f:
        f.write(data)
    return filepath

def render_local_save_ui(button_label, filename, data, key_prefix, button_type="primary"):
    """ ローカル保存ボタンと「開く」アクションを統合したUIコンポーネント """
    save_btn = st.button(button_label, type=button_type, width="stretch", key=f"btn_save_{key_prefix}")
    local_export_dir = st.session_state.get('local_export_dir', None)
    
    if save_btn:
        saved_path = save_file_to_local(filename, data, local_export_dir)
        st.session_state[f'saved_path_{key_prefix}'] = saved_path
        
    # 保存成功後のUI表示
    if st.session_state.get(f'saved_path_{key_prefix}'):
        saved_path = st.session_state[f'saved_path_{key_prefix}']
        st.success(f"📂 **保存完了:** `{saved_path}`")
        
        col_open1, col_open2 = st.columns(2)
        with col_open1:
            if st.button("📄 ファイルを開く (Excel/ブラウザ等)", key=f"btn_open_file_{key_prefix}", width="stretch"):
                open_local_path(saved_path)
        with col_open2:
            if st.button("📁 フォルダを開く (保存先)", key=f"btn_open_dir_{key_prefix}", width="stretch"):
                open_local_path(os.path.dirname(saved_path))

# ページ設定
st.set_page_config(layout="wide", page_title="検索大臣", page_icon="🔎")

st.markdown("""
<style>
/* グラフ描画時のフェードインアニメーション */
@keyframes fadeIn {
    from { opacity: 0.5; transform: translateY(2px); }
    to { opacity: 1; transform: translateY(0); }
}
.stAltairChart {
    animation: fadeIn 0.6s ease-out;
}
/* プログレスバーの滑らかな遷移 */
.stProgress > div > div {
    transition: width 0.5s ease-in-out !important;
}
</style>
""", unsafe_allow_html=True)

# ==========================================
# 自動モード判定ロジック (st.secrets利用)
# ==========================================
IS_PUBLIC_MODE = False
try:
    if "ENV_MODE" in st.secrets and st.secrets["ENV_MODE"] == "public":
        IS_PUBLIC_MODE = True
except FileNotFoundError:
    IS_PUBLIC_MODE = False
# ==========================================

from constants import *

# --- 匿名化・プロキシ判定用データ ---

@st.cache_data(ttl=86400, show_spinner=False, max_entries=10)
def fetch_tor_exit_nodes():
    try:
        url = "https://check.torproject.org/exit-addresses"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return set([line.split()[1] for line in response.text.splitlines() if line.startswith("ExitAddress")])
    except requests.exceptions.RequestException as e:
        import logging
        logging.warning(f"Tor出口ノードリストの取得に失敗しました: {e}")
        return set()

@st.cache_data(ttl=86400, show_spinner=False)
def fetch_threat_intel_list():
    """ 脅威IPリスト（ボットネットC2等）をFeodo Trackerから取得 """
    try:
        url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
        response = requests.get(url, timeout=10)
        return set([line.strip() for line in response.text.splitlines() if line.strip() and not line.startswith('#')])
    except:
        return set()

@st.cache_data(ttl=86400, show_spinner=False)
def fetch_proxy_intel_list():
    """ 既知のプロキシIPリストをFireHOLから取得 """
    try:
        url = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_proxies.netset"
        response = requests.get(url, timeout=10)
        # IP範囲が含まれる可能性があるため、ipaddressで正規化してセットに追加するロジックを推奨
        # ここではシンプルにIPアドレス行のみを抽出してセット化
        return set([line.strip() for line in response.text.splitlines() if line.strip() and not line.startswith('#')])
    except:
        return set()

@st.cache_data(ttl=86400*3, show_spinner=False)
def fetch_cloud_ip_ranges():
    """ 主要クラウドプロバイダの公式IPレンジ(JSON)を動的に取得し、二分探索用に最適化する """
    cloud_ranges_v4 = []
    cloud_ranges_v6 = []

    def add_range(cidr_str, provider):
        try:
            net = ipaddress.ip_network(cidr_str, strict=False)
            if net.version == 4:
                cloud_ranges_v4.append((int(net.network_address), int(net.broadcast_address), provider))
            else:
                cloud_ranges_v6.append((int(net.network_address), int(net.broadcast_address), provider))
        except Exception:
            pass

    # 1. AWS (Amazon Web Services)
    try:
        r = requests.get("https://ip-ranges.amazonaws.com/ip-ranges.json", timeout=10)
        if r.status_code == 200:
            data = r.json()
            for prefix in data.get("prefixes", []): add_range(prefix.get("ip_prefix"), "AWS")
            for prefix in data.get("ipv6_prefixes", []): add_range(prefix.get("ipv6_prefix"), "AWS")
    except: pass

    # 2. GCP (Google Cloud Platform)
    try:
        r = requests.get("https://www.gstatic.com/ipranges/cloud.json", timeout=10)
        if r.status_code == 200:
            data = r.json()
            for prefix in data.get("prefixes", []):
                if "ipv4Prefix" in prefix: add_range(prefix["ipv4Prefix"], "GCP")
                if "ipv6Prefix" in prefix: add_range(prefix["ipv6Prefix"], "GCP")
    except: pass

    # 3. Azure (Microsoft Download Centerをスクレイピングして動的URLを取得)
    try:
        dl_page = requests.get("https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519", timeout=10)
        match = re.search(r'href="(https://download\.microsoft\.com/download/.*?/ServiceTags_Public_.*?\.json)"', dl_page.text)
        if match:
            azure_url = match.group(1)
            r = requests.get(azure_url, timeout=15)
            if r.status_code == 200:
                data = r.json()
                for val in data.get("values", []):
                    for prefix in val.get("properties", {}).get("addressPrefixes", []):
                        add_range(prefix, "Azure")
    except: pass

    # 4. Cloudflare (Reverse Proxy / WAF)
    try:
        r_v4 = requests.get("https://www.cloudflare.com/ips-v4", timeout=5)
        if r_v4.status_code == 200:
            for line in r_v4.text.splitlines(): add_range(line.strip(), "Cloudflare")
        r_v6 = requests.get("https://www.cloudflare.com/ips-v6", timeout=5)
        if r_v6.status_code == 200:
            for line in r_v6.text.splitlines(): add_range(line.strip(), "Cloudflare")
    except: pass

    # 二分探索(O(log N))できるように開始IPの整数値でソート
    cloud_ranges_v4.sort(key=lambda x: x[0])
    cloud_ranges_v6.sort(key=lambda x: x[0])

    return {"v4": cloud_ranges_v4, "v6": cloud_ranges_v6}

def check_cloud_provider(ip_str, cloud_data):
    """ IPアドレスがクラウド事業者の公式リストに含まれているかを超高速で判定する """
    if not cloud_data: return None
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        ip_int = int(ip_obj)
        target_list = cloud_data["v4"] if ip_obj.version == 4 else cloud_data["v6"]

        # 二分探索で「開始IPが探しているIP以下の最大のインデックス」を見つける
        keys = [r[0] for r in target_list]
        idx = bisect.bisect_right(keys, ip_int) - 1

        if idx >= 0:
            start_ip, end_ip, provider = target_list[idx]
            if start_ip <= ip_int <= end_ip:
                return provider
    except:
        pass
    return None

@st.cache_data(ttl=86400, show_spinner=False, max_entries=10)
def fetch_disposable_domains():
    """ GitHubの有名リポジトリから最新の捨てアドドメイン一覧を取得 (1日1回更新) """
    try:
        url = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        if response.status_code == 200:
            # 空行とコメントを除外し、小文字でセット（集合）に格納して高速化
            return set([line.strip().lower() for line in response.text.splitlines() if line.strip() and not line.startswith('//')])
    except requests.exceptions.RequestException as e:
        import logging
        logging.warning(f"使い捨てドメインリストの取得に失敗しました: {e}")
    return set()

def check_disposable_domain(domain, nslookup_raw):
    """ MXレコードやドメイン名から捨てアドサービスを検知し、特定されたサービス名のリストを返す """
    dynamic_disposable_list = fetch_disposable_domains()
    detected_services = []
    raw_lower = nslookup_raw.lower() if nslookup_raw else ""
    query_domain_lower = domain.lower()
    
    import re
    mx_targets = re.findall(r'\bin\s+mx\s+\d+\s+(\S+)', raw_lower)
    targets_to_check = mx_targets + [query_domain_lower]
    
    # 1. 既知の辞書を使った特定
    for target in targets_to_check:
        target = target.strip('.')
        for pattern, service_name in DISPOSABLE_MX_SERVICES.items():
            if pattern in target and service_name not in detected_services:
                detected_services.append(service_name)
        for pattern, service_name in DISPOSABLE_DOMAIN_SERVICES.items():
            if pattern in target and service_name not in detected_services:
                detected_services.append(service_name)
                
    # 2. 外部DB（GitHubリスト）による特定不可ドメインの捕捉
    if not detected_services and dynamic_disposable_list:
        for target in targets_to_check:
            target = target.strip('.')
            parts = target.split('.')
            for i in range(len(parts) - 1): 
                domain_to_check = '.'.join(parts[i:])
                if domain_to_check in dynamic_disposable_list:
                    label = f"外部DB検知 ({domain_to_check} / サービス名特定不可)"
                    if label not in detected_services:
                        detected_services.append(label)
                    break 
    return detected_services   

def get_jp_names(english_isp, country_code):
    jp_country = COUNTRY_JP_NAME.get(country_code, country_code)
    
    if not english_isp:
        return "N/A", jp_country

    normalized_input = normalize_isp_key(english_isp)
    jp_isp = english_isp 

    if english_isp in ISP_JP_NAME:
        jp_isp = ISP_JP_NAME[english_isp]
    elif normalized_input in ISP_JP_NAME_NORMALIZED:
        jp_isp = ISP_JP_NAME_NORMALIZED[normalized_input]
    else:
        for keyword, mapped_name in ISP_REMAP_RULES:
            # 単語の境界(\b)を判定し、edionの中のdion等、意図しない部分文字列へのマッチを排除する
            if re.search(rf'\b{re.escape(keyword)}\b', normalized_input):
                jp_isp = mapped_name
                break
        
    jp_country = COUNTRY_JP_NAME.get(country_code, country_code)
    return jp_isp, jp_country

from api_clients import (
    session,
    fetch_rdap_data, fetch_domain_rdap_data, fetch_classic_whois,
    get_securitytrails_data, get_securitytrails_reverse_ip, get_alienvault_otx_pdns,
    check_internetdb_risk, get_vpnapi_data, resolve_ip_nslookup, fetch_ipinfo_bulk,
    fetch_rdap_data_async, fetch_domain_rdap_data_async,
    get_securitytrails_data_async, get_securitytrails_reverse_ip_async,
    get_alienvault_otx_pdns_async, check_internetdb_risk_async, get_vpnapi_data_async
)

@st.cache_data(max_entries=10)
def get_world_map_data():
    try:
        world_geojson = alt.topo_feature('https://cdn.jsdelivr.net/npm/vega-datasets@v1.29.0/data/world-110m.json', 'countries')
        return world_geojson
    except:
        return None

WORLD_MAP_GEOJSON = get_world_map_data()

# --- ヘルパー関数群 ---
from utils import (
    extract_actual_ip, clean_ocr_error_chars, is_valid_ip, is_bogon_ip,
    is_valid_domain, is_ipv4, ip_to_int, get_cidr_block,classify_local_proxy,
)

def get_authoritative_rir_link(ip, country_code):
    rir_name = COUNTRY_CODE_TO_RIR.get(country_code)
    # RIR共通のポップアップ説明文
    desc = "IPアドレスを管轄する公式レジストリ。法的な保有組織などの最も正確な情報を確認できます。"
    
    if rir_name and rir_name in RIR_LINKS:
        encoded_ip = quote(ip, safe='')
        if rir_name in ['RIPE', 'ARIN']:
            link_url = RIR_LINKS[rir_name].format(ip=encoded_ip)
            return f"[{rir_name} ]({link_url} \"{desc}\")"
        elif rir_name in ['JPNIC', 'APNIC', 'LACNIC', 'AFRINIC']:
            link_url = RIR_LINKS[rir_name]  
            return f"[{rir_name} (手動検索) ]({link_url} \"{desc}\")"
    return f"[Whois (汎用検索) ]({RIR_LINKS.get('APNIC', 'https://wq.apnic.net/static/search.html')} \"{desc}\")"

def create_secondary_links(target):
    actual_ip = extract_actual_ip(target)
    is_composite = (actual_ip != target and "(" in target) # ドメインとIPの複合型か判定
    is_ip = is_valid_ip(target) and not is_composite
    
    # --- ツールごとの解説文（オンマウス時のツールチップ用） ---
    tool_tips = {
        'VirusTotal': '世界中のウイルス対策エンジンで一括スキャン。危険なIPか即座に判別。',
        'Aguse': '日本語表示。ブラックリスト判定や、サーバー証明書情報が見やすい。',
        'Aguse (Domain)': '日本語表示。ブラックリスト判定や、サーバー証明書情報が見やすい。',
        'ipinfo.io': '地図上の位置、ホスティング(クラウド)かどうかの詳細判定に強い。',
        'IP2Proxy': '匿名プロキシやVPNからのアクセスかどうかを専門的に判定。',
        'VPNAPI.io': '匿名プロキシやVPNからのアクセスかどうかを専門的に判定。(本ツールでAPI実装済み)',
        'IP Location': 'IPアドレスの地理的位置をGoogleマップ等で視覚的に表示。',
        'Whois.com': 'ドメインの保有者情報（英語）を確認するのに最適。',
        'DNS Checker': 'IPv6のWhois情報が世界中でどう見えているかを確認。',
        'CP-WHOIS (手動)': '利用者認証が必要な検索ツール。ここでの検索結果はデータとして信頼性が高い。',
        'DNS History (手動)': '過去のDNSレコードの変更履歴を確認。'
    }

    links = {}

    if is_composite:
        # --- ドメイン(IP) 複合型専用 厳選リンク ---
        domain_part = target.split("(")[0].strip()
        encoded_domain = quote(domain_part, safe='')
        encoded_ip = quote(actual_ip, safe='')
        
        links['VirusTotal'] = f'https://www.virustotal.com/gui/search/{encoded_domain}'
        links['Aguse (Domain)'] = f'https://www.aguse.jp/?url={encoded_domain}'
        links['ipinfo.io'] = f'https://ipinfo.io/{encoded_ip}'
        links['IP Location'] = f'https://iplocation.io/ip/{encoded_ip}'
        links['DNS History (手動)'] = 'https://dnshistory.org/'

    elif is_ip:
        encoded_target = quote(actual_ip, safe='')
        if is_ipv4(actual_ip):
            links['VirusTotal'] = f'https://www.virustotal.com/gui/search/{encoded_target}'
            links['Aguse'] = f'https://www.aguse.jp/?url={encoded_target}'
            links['ipinfo.io'] = f'https://ipinfo.io/{encoded_target}'
            links['IP2Proxy'] = f'https://www.ip2proxy.com/{encoded_target}'
            links['VPNAPI.io'] = f'https://vpnapi.io/api/{encoded_target}'
            links['IP Location'] = f'https://iplocation.io/ip/{encoded_target}'
        else:
            links['VirusTotal'] = f'https://www.virustotal.com/gui/search/{encoded_target}'
            links['ipinfo.io'] = f'https://ipinfo.io/{encoded_target}'
            links['IP2Proxy'] = f'https://www.ip2proxy.com/{encoded_target}'
            links['VPNAPI.io'] = f'https://vpnapi.io/api/{encoded_target}'
            links['IP Location'] = f'https://iplocation.io/ip/{encoded_target}'
            links['DNS Checker'] = f'https://dnschecker.org/ipv6-whois-lookup.php?query={encoded_target}'
    else:
        # --- 純粋なドメイン用 厳選リンク (DNS解決失敗時) ---
        encoded_target = quote(target, safe='')
        links['VirusTotal'] = f'https://www.virustotal.com/gui/search/{encoded_target}'
        links['Aguse'] = f'https://www.aguse.jp/?url={encoded_target}'
        links['Whois.com'] = f'https://www.whois.com/whois/{encoded_target}'
        links['DNS History (手動)'] = 'https://dnshistory.org/'

    links['CP-WHOIS (手動)'] = 'https://doco.cph.jp/whoisweb.php'

    link_html = ""
    for name, url in links.items():
        if url: 
            # 辞書から説明文を取得（なければ空文字）
            desc = tool_tips.get(name, "")
            link_html += f"[{name} ]({url} \"{desc}\") | "
    
    return link_html.rstrip(' | ')

# --- API通信関数 (Main) ---
def get_ip_details_from_api(ip, cidr_cache_snapshot, learned_isps_snapshot, delay_between_requests, rate_limit_wait_seconds, tor_nodes, cloud_ip_data, use_rdap, use_internetdb, use_rdns, use_st_reverse_ip, skip_whois=False, api_key=None, vpnapi_key=None, st_api_key=None, otx_api_key=None, st_start_date=None, st_end_date=None, use_st_rev_fetchall=False, is_single_target=False, bulk_ipinfo_cache=None, threat_intel_list=None, proxy_intel_list=None):
    actual_ip = extract_actual_ip(ip)
    
    result = {
        'Target_IP': ip, 
        'ISP_API_Raw': 'N/A', 'ISP_JP': 'N/A', 
        'RDAP_Name_Raw': '', 'RDAP_JP': '',    
        'ISP': 'N/A', 
        'Country': 'N/A', 'Country_JP': 'N/A', 'CountryCode': 'N/A', 
        'RIR_Link': 'N/A', 'Secondary_Security_Links': 'N/A', 'Status': 'N/A',
        'RDAP_JSON': None, 'VPNAPI_JSON': None, 'RDAP_URL': '', 'IPINFO_JSON': None, 'IoT_Risk': '',
        'DOMAIN_RDAP_JSON': None, 'DOMAIN_RDAP_URL': '', 'ST_JSON': None, 'RDNS_DATA': None,
        'Proxy_Type': '', 'ST_REVERSE_IP_JSON': None,
        'DOMAIN_WHOIS_TEXT': None, 'DOMAIN_WHOIS_SERVER': None,
        'IP_WHOIS_TEXT': None, 'IP_WHOIS_SERVER': None,
        'RDNS_Hosts': '',
        'ST_Reverse_Hosts': ''
    }
    new_cache_entry = None
    new_learned_isp = None
    cidr_block = get_cidr_block(actual_ip)
    
    if cidr_block and cidr_block in cidr_cache_snapshot:
        cached_data = cidr_cache_snapshot[cidr_block]
        # KeyError回避のため .get() を使用 (キーがない場合は0を返し、必ず再取得させる)
        if time.time() - cached_data.get('Timestamp', 0) < 86400:
            result.update(cached_data) 
            result['Target_IP'] = ip  # 本来のリクエストIPを再設定し、キャッシュによる上書きを防ぐ
            result['Status'] = "Success (Cache)" 
            result['Secondary_Security_Links'] = create_secondary_links(ip)
            return result, None, None

    try:
        # --- 動的スリープ判定（バルク処理のボトルネック解消） ---
        has_bulk_cache = bool(api_key and bulk_ipinfo_cache and actual_ip in bulk_ipinfo_cache and isinstance(bulk_ipinfo_cache[actual_ip], dict))
                
        # 1. 脅威インテリジェンス (Feodo Tracker) の判定
        if threat_intel_list and actual_ip in threat_intel_list:
            result['IoT_Risk'] = "🚨 Threat Intel Match (Source: Feodo Tracker)"
        
        # 2. ローカルDB (IP2Location / FireHOL) の判定
        proxy_type_val = classify_local_proxy(actual_ip, threat_intel_list, proxy_intel_list)
        if proxy_type_val:
            result['Proxy_Type'] = proxy_type_val
            
        # skip_whoisがオンでも、Reverse IP等にチェックが入っている場合は通信が発生するため待機が必要
        needs_other_apis = any([
            vpnapi_key and not skip_whois, 
            use_rdap and not skip_whois, 
            use_internetdb and not skip_whois, 
            use_st_reverse_ip,
            use_rdns,
            is_single_target and not skip_whois
        ])

        if has_bulk_cache and not needs_other_apis:
            pass 
        elif skip_whois and not use_st_reverse_ip and not use_rdns:
            time.sleep(0.1) 
        else:
            time.sleep(delay_between_requests) 
        
        # --- API通信セクション ---
        if skip_whois:
            result['ISP_API_Raw'] = 'N/A (Skipped)'
            result['CountryCode'] = 'N/A'
            result['Country'] = 'N/A'
            status_api = 'Success (Skipped)'
            # 完全にWhois通信を行わないフラグ
        elif api_key:
            # バルクキャッシュが存在する場合はそれを優先使用して通信をスキップ
            if bulk_ipinfo_cache and actual_ip in bulk_ipinfo_cache and isinstance(bulk_ipinfo_cache[actual_ip], dict):
                data = bulk_ipinfo_cache[actual_ip]
                result['IPINFO_JSON'] = data 
                    
                # None(null)による正規表現クラッシュを回避
                org_raw = data.get('org') or ''
                raw_isp = re.sub(r'^AS\d+\s+', '', str(org_raw)) if org_raw else 'N/A'
                
                # orgが空の場合、asnフィールドからのフォールバックを試みる
                if raw_isp == 'N/A' and data.get('asn') and isinstance(data['asn'], dict):
                    raw_isp = data['asn'].get('name', 'N/A')
                    
                result['ISP_API_Raw'] = raw_isp
                
                country_code = data.get('country') or 'N/A'
                result['CountryCode'] = str(country_code).upper() if country_code != 'N/A' else 'N/A'
                result['Country'] = result['CountryCode']
                    
                status_api = 'Success (Pro Bulk)'
            else:
                # キャッシュミス時のみ個別にリクエスト
                url = IPINFO_API_URL.format(ip=actual_ip) 
                headers = {"Authorization": f"Bearer {api_key}"}
                response = session.get(url, headers=headers, timeout=10)
                    
                if response.status_code == 429:
                    result['Status'] = 'エラー: API利用制限 (待機後に自動再試行します)'
                    result['Defer_Until'] = time.time() + rate_limit_wait_seconds
                    return result, None, None
                        
                response.raise_for_status()
                data = response.json()
                result['IPINFO_JSON'] = data 
                    
                # 個別リクエスト側も同様に安全処理とフォールバックを適用
                org_raw = data.get('org') or ''
                raw_isp = re.sub(r'^AS\d+\s+', '', str(org_raw)) if org_raw else 'N/A'
                
                if raw_isp == 'N/A' and data.get('asn') and isinstance(data['asn'], dict):
                    raw_isp = data['asn'].get('name', 'N/A')
                    
                result['ISP_API_Raw'] = raw_isp
                
                country_code = data.get('country') or 'N/A'
                result['CountryCode'] = str(country_code).upper() if country_code != 'N/A' else 'N/A'
                result['Country'] = result['CountryCode']
                    
                status_api = 'Success (Pro)'

        else:
            url = IP_API_URL.format(ip=actual_ip)
            response = session.get(url, timeout=45)
            
            if response.status_code == 429:
                result['Status'] = 'エラー: API利用制限 (待機後に自動再試行します)'
                result['Defer_Until'] = time.time() + rate_limit_wait_seconds
                return result, None, None
            
            response.raise_for_status()
            data = response.json()
            
            if data.get('status') == 'success':
                result['CountryCode'] = data.get('countryCode', 'N/A')
                result['Country'] = data.get('country', 'N/A')
                raw_isp_val = data.get('isp', 'N/A')
                raw_org_val = data.get('org', '')
                result['ISP_API_Raw'] = raw_isp_val if raw_org_val == raw_isp_val else f"{raw_isp_val} / {raw_org_val}"
                
                status_api = 'Success (API)'
            else:
                result['Status'] = f"エラー: IP情報取得失敗 ({data.get('message', '原因不明')})"
                return result, None, None

        # --- 匿名通信・クラウドインフラ 高精度判定 ---
        
        # 1. 公式リスト・Torリストに基づく自前判定
        cloud_provider = check_cloud_provider(actual_ip, cloud_ip_data)
        
        # 既にローカルDBで判定済みの場合、Tor判定以外の上書きはしない（信頼性重視のため）
        if actual_ip in tor_nodes:
            result['Proxy_Type'] = "TorNode (Source: Tor Project)"
        elif cloud_provider and not result['Proxy_Type']: # 既存判定がなければ設定
            result['Proxy_Type'] = f"Hosting ({cloud_provider})"

        # 2. VPNAPI.io による実地検証 (APIキーがあり、かつまだ判定がない場合のみ実行)
        if vpnapi_key and not skip_whois:
            # ローカルDB等で判定済みの場合は補足情報として結合する
            proxy_data = get_vpnapi_data(actual_ip, vpnapi_key)
            if proxy_data:
                result['VPNAPI_JSON'] = proxy_data
                sec = proxy_data.get('security', {})
                if any(sec.values()):
                    detected = [k.upper() for k, v in sec.items() if v]
                    p_type = "/".join(detected)
                    
                    if result['Proxy_Type']:
                        result['Proxy_Type'] += f" / API Confirmed ({p_type})"
                    else:
                        result['Proxy_Type'] = f"[{p_type}] (Source: API VPNAPI.io)"
                else:
                    if not result['Proxy_Type']:
                        result['Proxy_Type'] = "Standard Connection"

        # ---------------------------------------------
        # ローカル検知にもAPIにも引っかからなかったクリーンなIP
        # ---------------------------------------------
        if not result['Proxy_Type'] and not skip_whois:
            result['Proxy_Type'] = "Standard Connection"

        # --- RDAP等の補助データ取得 ---
        if use_rdap and not skip_whois:
            rdap_res = fetch_rdap_data(actual_ip) 
            if rdap_res:
                raw_rdap_name = rdap_res['name']
                result['RDAP_Name_Raw'] = raw_rdap_name 
                result['RDAP_JSON'] = rdap_res['json']
                result['RDAP_URL'] = rdap_res['url']
                rdap_jp, _ = get_jp_names(raw_rdap_name, result['CountryCode'])
                result['RDAP_JP'] = rdap_jp

        is_composite = (actual_ip != ip and "(" in ip)

        # 複合ターゲット（ドメインから解決されたIP）の場合は、生WHOISの取得をスキップしてIP-BANを防ぐ
        if not is_composite and is_single_target and not skip_whois:
            w_text_ip, w_server_ip = fetch_classic_whois(actual_ip)

            if w_text_ip:
                result['IP_WHOIS_TEXT'] = w_text_ip
                result['IP_WHOIS_SERVER'] = w_server_ip

        if is_composite and not skip_whois:
            domain_part = ip.split("(")[0].strip()
            res_d = fetch_domain_rdap_data(domain_part)
            if res_d:
                result['DOMAIN_RDAP_JSON'] = res_d['json']
                result['DOMAIN_RDAP_URL'] = res_d['url']
            
            # RDAPの成否に関わらず、生のWHOISテキストは証拠として常に取得を試みる
            if is_single_target and not skip_whois:
                w_text, w_server = fetch_classic_whois(domain_part)
                if w_text:
                    result['DOMAIN_WHOIS_TEXT'] = w_text
                    result['DOMAIN_WHOIS_SERVER'] = w_server

        is_composite = (actual_ip != ip and "(" in ip)
        if is_composite and st_api_key:
            st_res = get_securitytrails_data(ip.split("(")[0].strip(), st_api_key, st_start_date, st_end_date)
            if st_res: result['ST_JSON'] = st_res

        if use_rdns:
            rdns_hosts, rdns_raw = resolve_ip_nslookup(actual_ip)
            if rdns_raw: result['RDNS_DATA'] = {'hosts': rdns_hosts, 'raw': rdns_raw}
            if rdns_hosts: result['RDNS_Hosts'] = " / ".join(rdns_hosts)

        if use_st_reverse_ip and (st_api_key or otx_api_key):
            rev_res = None
            
            # AlienVault OTXを優先して利用 (API利用制限回避のため)
            if otx_api_key:
                rev_res = get_alienvault_otx_pdns(actual_ip, otx_api_key)
            # OTXキーがない場合はSecurityTrailsにフォールバック
            elif st_api_key:
                rev_res = get_securitytrails_reverse_ip(actual_ip, st_api_key, use_st_rev_fetchall)

            if rev_res: 
                result['ST_REVERSE_IP_JSON'] = rev_res
                records = rev_res.get('records', [])
                
                # 順序を保持したまま重複を排除してホスト名を抽出
                hosts = []
                for r in records:
                    h = r.get('hostname')
                    if h and h not in hosts:
                        hosts.append(h)
                
                if hosts:
                    # 一覧表・Excelでの視認性崩壊を防ぐため、表示上限を3件に設定
                    display_limit = 3
                    if len(hosts) > display_limit:
                        result['ST_Reverse_Hosts'] = " / ".join(hosts[:display_limit]) + f" (他 {len(hosts) - display_limit}件)"
                    else:
                        result['ST_Reverse_Hosts'] = " / ".join(hosts)

        if use_internetdb and not skip_whois:
            result['IoT_Risk'] = check_internetdb_risk(actual_ip)
        else:
            result['IoT_Risk'] = "[Not Checked]" 

        result['Status'] = status_api
        result['RIR_Link'] = get_authoritative_rir_link(actual_ip, result['CountryCode'])
        result['Secondary_Security_Links'] = create_secondary_links(ip)

        isp_jp, country_jp = get_jp_names(result['ISP_API_Raw'], result['CountryCode'])
        result['ISP_JP'] = isp_jp
        result['Country_JP'] = country_jp
        result['ISP'] = result['ISP_JP'] if result['ISP_JP'] != 'N/A' else result['ISP_API_Raw']

        # キャッシュの鮮度判定用に現在時刻のタイムスタンプを付与
        result['Timestamp'] = time.time()

        if cidr_block:
            new_cache_entry = { cidr_block: result } 

    except requests.exceptions.ConnectionError:
        # 物理的なネットワーク切断（Wi-Fi切れ等）を検知した場合、15秒間保留キューに入れる
        result['Status'] = '待機: ネットワーク切断 (自動再試行します)'
        result['Defer_Until'] = time.time() + 15
        return result, None, None
    except requests.exceptions.Timeout:
        result['Status'] = 'エラー: 応答タイムアウト (相手サーバーの混雑または停止)'
    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code if e.response is not None else "不明"
        result['Status'] = f'エラー: 通信拒否または存在なし (HTTP {status_code})'
    except requests.exceptions.RequestException as e:
        result['Status'] = f'エラー: ネットワーク接続失敗 ({type(e).__name__})'
    except ValueError:
        result['Status'] = 'エラー: データ形式が不正 (JSON解析失敗)'
    except Exception as e:
        result['Status'] = f'エラー: 予期せぬシステム例外 ({type(e).__name__})'

    return result, new_cache_entry, new_learned_isp

async def get_ip_details_from_api_async(
    sem,
    session,
    ip, 
    cidr_cache_snapshot, 
    learned_isps_snapshot, 
    delay_between_requests,
    rate_limit_wait_seconds,
    tor_nodes,
    cloud_ip_data,
    use_rdap,
    use_internetdb,
    use_rdns,
    use_st_reverse_ip,
    skip_whois,
    pro_api_key,
    vpnapi_key,
    st_api_key,
    otx_api_key,
    st_start_date,
    st_end_date,
    use_st_rev_fetchall,
    is_single_target,
    bulk_ipinfo_cache,
    threat_intel_list,
    proxy_intel_list
):
    async with sem:
        import time
        actual_ip = extract_actual_ip(ip)
        
        result = {
            'Target_IP': ip, 
            'ISP_API_Raw': 'N/A', 'ISP_JP': 'N/A', 
            'RDAP_Name_Raw': '', 'RDAP_JP': '',    
            'ISP': 'N/A', 
            'Country': 'N/A', 'Country_JP': 'N/A', 'CountryCode': 'N/A', 
            'RIR_Link': 'N/A', 'Secondary_Security_Links': 'N/A', 'Status': 'N/A',
            'RDAP_JSON': None, 'VPNAPI_JSON': None, 'RDAP_URL': '', 'IPINFO_JSON': None, 'IoT_Risk': '',
            'DOMAIN_RDAP_JSON': None, 'DOMAIN_RDAP_URL': '', 'ST_JSON': None, 'RDNS_DATA': None,
            'Proxy_Type': '', 'ST_REVERSE_IP_JSON': None,
            'DOMAIN_WHOIS_TEXT': None, 'DOMAIN_WHOIS_SERVER': None,
            'IP_WHOIS_TEXT': None, 'IP_WHOIS_SERVER': None,
            'RDNS_Hosts': '',
            'ST_Reverse_Hosts': ''
        }
        new_cache_entry = None
        new_learned_isp = None
        cidr_block = get_cidr_block(actual_ip)
        
        if cidr_block and cidr_block in cidr_cache_snapshot:
            cached_data = cidr_cache_snapshot[cidr_block]
            if time.time() - cached_data.get('Timestamp', 0) < 86400:
                result.update(cached_data) 
                result['Target_IP'] = ip 
                result['Status'] = "Success (Cache)" 
                result['Secondary_Security_Links'] = create_secondary_links(ip)
                return result, None, None

        try:
            has_bulk_cache = bool(pro_api_key and bulk_ipinfo_cache and actual_ip in bulk_ipinfo_cache and isinstance(bulk_ipinfo_cache[actual_ip], dict))
            
            # 1. 脅威インテリジェンス (Feodo Tracker) の判定
            if threat_intel_list and actual_ip in threat_intel_list:
                result['IoT_Risk'] = "🚨 Threat Intel Match (Source: Feodo Tracker)"
            
            # 2. ローカルDB (IP2Location / FireHOL) の判定 — 同期版と完全同一のヘルパーを使う
            from utils import classify_local_proxy
            proxy_type_val = classify_local_proxy(actual_ip, threat_intel_list, proxy_intel_list)
            if proxy_type_val:
                result['Proxy_Type'] = proxy_type_val


            needs_other_apis = any([
                vpnapi_key and not skip_whois, 
                use_rdap and not skip_whois, 
                use_internetdb and not skip_whois, 
                use_st_reverse_ip,
                use_rdns,
                is_single_target and not skip_whois
            ])

            if has_bulk_cache and not needs_other_apis:
                pass 
            elif skip_whois and not use_st_reverse_ip and not use_rdns:
                await asyncio.sleep(0.1) 
            else:
                await asyncio.sleep(delay_between_requests) 
            
            if skip_whois:
                result['ISP_API_Raw'] = 'N/A (Skipped)'
                result['CountryCode'] = 'N/A'
                result['Country'] = 'N/A'
                status_api = 'Success (Skipped)'
            elif pro_api_key:
                if bulk_ipinfo_cache and actual_ip in bulk_ipinfo_cache and isinstance(bulk_ipinfo_cache[actual_ip], dict):
                    data = bulk_ipinfo_cache[actual_ip]
                    result['IPINFO_JSON'] = data 
                        
                    org_raw = data.get('org') or ''
                    raw_isp = re.sub(r'^AS\d+\s+', '', str(org_raw)) if org_raw else 'N/A'
                    
                    if raw_isp == 'N/A' and data.get('asn') and isinstance(data['asn'], dict):
                        raw_isp = data['asn'].get('name', 'N/A')
                        
                    result['ISP_API_Raw'] = raw_isp
                    
                    country_code = data.get('country') or 'N/A'
                    result['CountryCode'] = str(country_code).upper() if country_code != 'N/A' else 'N/A'
                    result['Country'] = result['CountryCode']
                        
                    status_api = 'Success (Pro Bulk)'
                else:
                    url = IPINFO_API_URL.format(ip=actual_ip) 
                    headers = {"Authorization": f"Bearer {pro_api_key}"}
                    async with session.get(url, headers=headers, timeout=10) as response:
                        if response.status == 429:
                            result['Status'] = 'エラー: API利用制限 (待機後に自動再試行します)'
                            result['Defer_Until'] = time.time() + rate_limit_wait_seconds
                            return result, None, None
                            
                        response.raise_for_status()
                        data = await response.json()
                        result['IPINFO_JSON'] = data 
                        
                        org_raw = data.get('org') or ''
                        raw_isp = re.sub(r'^AS\d+\s+', '', str(org_raw)) if org_raw else 'N/A'
                        
                        if raw_isp == 'N/A' and data.get('asn') and isinstance(data['asn'], dict):
                            raw_isp = data['asn'].get('name', 'N/A')
                            
                        result['ISP_API_Raw'] = raw_isp
                        
                        country_code = data.get('country') or 'N/A'
                        result['CountryCode'] = str(country_code).upper() if country_code != 'N/A' else 'N/A'
                        result['Country'] = result['CountryCode']
                            
                        status_api = 'Success (Pro)'

            else:
                url = IP_API_URL.format(ip=actual_ip)
                async with session.get(url, timeout=45) as response:
                    if response.status == 429:
                        result['Status'] = 'エラー: API利用制限 (待機後に自動再試行します)'
                        result['Defer_Until'] = time.time() + rate_limit_wait_seconds
                        return result, None, None
                    
                    response.raise_for_status()
                    data = await response.json()
                    
                    if data.get('status') == 'success':
                        result['CountryCode'] = data.get('countryCode', 'N/A')
                        result['Country'] = data.get('country', 'N/A')
                        raw_isp_val = data.get('isp', 'N/A')
                        raw_org_val = data.get('org', '')
                        result['ISP_API_Raw'] = raw_isp_val if raw_org_val == raw_isp_val else f"{raw_isp_val} / {raw_org_val}"
                        
                        status_api = 'Success (API)'
                    else:
                        result['Status'] = f"エラー: IP情報取得失敗 ({data.get('message', '原因不明')})"
                        return result, None, None

            cloud_provider = check_cloud_provider(actual_ip, cloud_ip_data)
            
            if actual_ip in tor_nodes:
                result['Proxy_Type'] = "TorNode (Source: Tor Project)"
            elif cloud_provider and not result['Proxy_Type']:
                result['Proxy_Type'] = f"Hosting ({cloud_provider})"

            if vpnapi_key and not skip_whois:
                proxy_data = await get_vpnapi_data_async(actual_ip, vpnapi_key, session)
                if proxy_data:
                    result['VPNAPI_JSON'] = proxy_data
                    sec = proxy_data.get('security', {})
                    if any(sec.values()):
                        detected = [k.upper() for k, v in sec.items() if v]
                        p_type = "/".join(detected)
                        
                        if result['Proxy_Type']: 
                            result['Proxy_Type'] += f" / API Confirmed ({p_type})"
                        else:
                            result['Proxy_Type'] = f"[{p_type}] (Source: API VPNAPI.io)"
                    else:
                        if not result['Proxy_Type']:
                            result['Proxy_Type'] = "Standard Connection"

            # ---------------------------------------------
            # ローカル検知にもAPIにも引っかからなかったクリーンなIP
            # ---------------------------------------------
            if not result['Proxy_Type'] and not skip_whois:
                result['Proxy_Type'] = "Standard Connection"

            if use_rdap and not skip_whois:
                rdap_res = await fetch_rdap_data_async(actual_ip, session) 
                if rdap_res:
                    raw_rdap_name = rdap_res['name']
                    result['RDAP_Name_Raw'] = raw_rdap_name 
                    result['RDAP_JSON'] = rdap_res['json']
                    result['RDAP_URL'] = rdap_res['url']
                    rdap_jp, _ = get_jp_names(raw_rdap_name, result['CountryCode'])
                    result['RDAP_JP'] = rdap_jp

            is_composite = (actual_ip != ip and "(" in ip)

            if not is_composite and is_single_target and not skip_whois:
                # 同期関数である旧式WHOIS取得を非同期ループ上でブロックさせないため、別スレッドに逃がす
                w_text_ip, w_server_ip = await asyncio.to_thread(fetch_classic_whois, actual_ip)
                if w_text_ip:
                    result['IP_WHOIS_TEXT'] = w_text_ip
                    result['IP_WHOIS_SERVER'] = w_server_ip

            if is_composite and not skip_whois:
                domain_part = ip.split("(")[0].strip()
                res_d = await fetch_domain_rdap_data_async(domain_part, session)
                if res_d:
                    result['DOMAIN_RDAP_JSON'] = res_d['json']
                    result['DOMAIN_RDAP_URL'] = res_d['url']
                
                if is_single_target and not skip_whois:
                    # こちらも同期関数のため別スレッド化
                    w_text, w_server = await asyncio.to_thread(fetch_classic_whois, domain_part)
                    if w_text:
                        result['DOMAIN_WHOIS_TEXT'] = w_text
                        result['DOMAIN_WHOIS_SERVER'] = w_server

            if is_composite and st_api_key:
                st_res = await get_securitytrails_data_async(ip.split("(")[0].strip(), st_api_key, session, st_start_date, st_end_date)
                if st_res: result['ST_JSON'] = st_res

            if use_rdns:
                # DNS解決も同期処理のため別スレッド化
                rdns_hosts, rdns_raw = await asyncio.to_thread(resolve_ip_nslookup, actual_ip)
                if rdns_raw: result['RDNS_DATA'] = {'hosts': rdns_hosts, 'raw': rdns_raw}
                if rdns_hosts: result['RDNS_Hosts'] = " / ".join(rdns_hosts)

            if use_st_reverse_ip and (st_api_key or otx_api_key):
                rev_res = None
                
                if otx_api_key:
                    rev_res = await get_alienvault_otx_pdns_async(actual_ip, otx_api_key, session)
                elif st_api_key:
                    rev_res = await get_securitytrails_reverse_ip_async(actual_ip, st_api_key, session, use_st_rev_fetchall)

                if rev_res: 
                    result['ST_REVERSE_IP_JSON'] = rev_res
                    records = rev_res.get('records', [])
                    
                    hosts = []
                    for r in records:
                        h = r.get('hostname')
                        if h and h not in hosts:
                            hosts.append(h)
                    
                    if hosts:
                        display_limit = 3
                        if len(hosts) > display_limit:
                            result['ST_Reverse_Hosts'] = " / ".join(hosts[:display_limit]) + f" (他 {len(hosts) - display_limit}件)"
                        else:
                            result['ST_Reverse_Hosts'] = " / ".join(hosts)

            if use_internetdb and not skip_whois:
                result['IoT_Risk'] = await check_internetdb_risk_async(actual_ip, session)
            else:
                result['IoT_Risk'] = "[Not Checked]" 

            result['Status'] = status_api
            result['RIR_Link'] = get_authoritative_rir_link(actual_ip, result['CountryCode'])
            result['Secondary_Security_Links'] = create_secondary_links(ip)

            isp_jp, country_jp = get_jp_names(result['ISP_API_Raw'], result['CountryCode'])
            result['ISP_JP'] = isp_jp
            result['Country_JP'] = country_jp
            result['ISP'] = result['ISP_JP'] if result['ISP_JP'] != 'N/A' else result['ISP_API_Raw']

            result['Timestamp'] = time.time()

            if cidr_block:
                new_cache_entry = { cidr_block: result } 

        except aiohttp.ClientConnectionError:
            result['Status'] = '待機: ネットワーク切断 (自動再試行します)'
            result['Defer_Until'] = time.time() + 15
            return result, None, None
        except asyncio.TimeoutError:
            result['Status'] = 'エラー: 応答タイムアウト (相手サーバーの混雑または停止)'
        except aiohttp.ClientResponseError as e:
            status_code = e.status
            result['Status'] = f'エラー: 通信拒否または存在なし (HTTP {status_code})'
        except aiohttp.ClientError as e:
            result['Status'] = f'エラー: ネットワーク接続失敗 ({type(e).__name__})'
        except ValueError:
            result['Status'] = 'エラー: データ形式が不正 (JSON解析失敗)'
        except Exception as e:
            result['Status'] = f'エラー: 予期せぬシステム例外 ({type(e).__name__})'

        return result, new_cache_entry, new_learned_isp

def get_domain_details(domain, nslookup_raw="", st_api_key=None, st_start_date=None, st_end_date=None, is_single_target=False, skip_whois=False):
    # 捨てアド検知を実行
    detected_disposables = check_disposable_domain(domain, nslookup_raw)
    proxy_type_val = f"⚠️ 捨てアド ({' / '.join(detected_disposables)})" if detected_disposables else "N/A (Domain)"

    # TLD情報辞書から公式レジストリのリンクと日本語名を動的生成
    tld_val = domain.split('.')[-1].lower() if '.' in domain else ""
    tld_jp_name = ""
    if tld_val in TLD_INFO and TLD_INFO[tld_val]["url"] != "N/A":
        reg_name = TLD_INFO[tld_val]["jp_name"]
        tld_jp_name = f"{reg_name} (.{tld_val.upper()})"
        reg_url = TLD_INFO[tld_val]["url"]
        domain_link = f"[{reg_name} (.{tld_val.upper()} Registry)]({reg_url})"
    else:
        tld_jp_name = f"未分類 (.{tld_val.upper()})" if tld_val else "不明"
        domain_link = f"[ICANN Whois (手動検索)]({RIR_LINKS['ICANN Whois']})"
    
    # --- 1. SecurityTrails (日付フィルタ対応) ---
    st_json = None
    if st_api_key:
        st_json = get_securitytrails_data(domain, st_api_key, st_start_date, st_end_date)
    
    # --- 2. ドメインRDAPとWHOISの取得  ---
    domain_rdap_json = None
    domain_rdap_url = ''
    domain_whois_text = None
    domain_whois_server = None
    rdap_name_raw = '' # 初期値を空にする

    try:
        rdap_res = None
        if not skip_whois:
            rdap_res = fetch_domain_rdap_data(domain)
            
        if rdap_res:
            domain_rdap_json = rdap_res['json']
            domain_rdap_url = rdap_res['url']
            
            # RDAPからレジストラ（登録代行業者）の特定を試みる
            entities = domain_rdap_json.get("entities", [])
            for ent in entities:
                roles = ent.get("roles", [])
                vcard_array = ent.get("vcardArray", [])
                if len(vcard_array) > 1:
                    for vcard in vcard_array[1]:
                        if "registrar" in roles and vcard[0] == "fn":
                            rdap_name_raw = vcard[3] # 確定した業者名を入れる
                            break
                if rdap_name_raw: break
        
        # 生のWHOISテキストは常に裏で取得しておく（個別レポート用）
        if is_single_target and not skip_whois:
            domain_whois_text, domain_whois_server = fetch_classic_whois(domain)
            
    except Exception:
        pass

    # --- 3. 結果の返却 ---
    return {
        'Target_IP': domain, 
        'ISP_API_Raw': '', # ドメイン時は一覧のWhois列を空にする
        'ISP_JP': '',      # ドメイン時は一覧のWhois列を空にする
        'RDAP_Name_Raw': rdap_name_raw, # RDAPで取れた業者名（なければ空）
        'RDAP_JP': tld_jp_name,        # 唯一の確定情報である国名/TLDを表示
        'ISP': 'Domain/Host', 
        'Country': tld_val.upper() if tld_val else 'N/A',
        'Country_JP': reg_name if 'reg_name' in locals() else 'N/A',
        'CountryCode': tld_val.upper() if tld_val else 'N/A',
        'RIR_Link': domain_link,
        'Secondary_Security_Links': create_secondary_links(domain),
        'Status': 'Success (Domain)',
        
        'RDAP': '', 'RDAP_JSON': None, 'VPNAPI_JSON': None, 'RDAP_URL': '', 'IPINFO_JSON': None, 'IoT_Risk': '',
        'Proxy_Type': proxy_type_val,
        'DISPOSABLE_SERVICES': detected_disposables,
        'DOMAIN_RDAP_JSON': domain_rdap_json,
        'DOMAIN_RDAP_URL': domain_rdap_url,
        'DOMAIN_WHOIS_TEXT': domain_whois_text,
        'DOMAIN_WHOIS_SERVER': domain_whois_server,
        'ST_JSON': st_json, 
        'RDNS_DATA': None,
        'RDNS_Hosts': '',
        'ST_Reverse_Hosts': '',
        'ST_REVERSE_IP_JSON': None,
        'IP_WHOIS_TEXT': None,
        'IP_WHOIS_SERVER': None
    }

def get_simple_mode_details(target):
    if is_valid_ip(target):
        rir_link_content = f"[Whois (汎用検索 - APNIC窓口)]({RIR_LINKS['APNIC']})"
    else:
        tld_val = target.split('.')[-1].lower() if '.' in target else ""
        if tld_val in TLD_INFO and TLD_INFO[tld_val]["url"] != "N/A":
            reg_name = TLD_INFO[tld_val]["jp_name"]
            reg_url = TLD_INFO[tld_val]["url"]
            rir_link_content = f"[{reg_name} (.{tld_val.upper()} Registry)]({reg_url})"
        else:
            rir_link_content = f"[ICANN Whois (手動検索)]({RIR_LINKS['ICANN Whois']})"
        
    return {
        'Target_IP': target, 
        'ISP': 'N/A (簡易モード)',
        'Country': 'N/A (簡易モード)',
        'CountryCode': 'N/A',
        'RIR_Link': rir_link_content,
        'Secondary_Security_Links': create_secondary_links(target),
        'Status': 'Success (簡易モード)',
        'RDAP': '', 'RDAP_JSON': None, 'VPNAPI_JSON': None, 'RDAP_URL': '', 'IPINFO_JSON': None, 'IoT_Risk': '',
        'DOMAIN_RDAP_JSON': None, 'DOMAIN_RDAP_URL': '', 'ST_JSON': None, 'RDNS_DATA': None, 'RDNS_Hosts': '', 'ST_Reverse_Hosts': '',
        'DISPOSABLE_SERVICES': [],
        'DOMAIN_WHOIS_TEXT': None, 'DOMAIN_WHOIS_SERVER': None,
        'IP_WHOIS_TEXT': None, 'IP_WHOIS_SERVER': None
    }

# --- ヘルパー関数群 ---

def group_results_by_isp(results):
    grouped = {}
    final_grouped_results = []
    non_aggregated_results = []
    successful_results = [res for res in results if res['Status'].startswith('Success')]

    for res in successful_results:
        is_ip = is_valid_ip(res['Target_IP'])
        if not is_ip or not is_ipv4(res['Target_IP']) or res['ISP'] == 'N/A' or res['Country'] == 'N/A' or res['ISP'] == 'N/A (簡易モード)':
            if res['Status'].startswith('Success (IPv4 CIDR Cache)'):
                non_aggregated_results.append(res)
            else:
                non_aggregated_results.append(res)
            continue
        
        key = (res['ISP'], res['CountryCode']) 
        
        if key not in grouped:
            grouped[key] = {
                'IP_Ints': [], 'IPs_List': [], 'RIR_Link': res['RIR_Link'],
                'Secondary_Security_Links': res['Secondary_Security_Links'],
                'ISP': res['ISP'], 
                'Country': res['Country'], 
                'Status': res['Status'],
                'ISP_JP': res.get('ISP_JP', 'N/A'),
                'Country_JP': res.get('Country_JP', 'N/A')
            }
        ip_int = ip_to_int(res['Target_IP'])
        if ip_int != 0:
            grouped[key]['IP_Ints'].append(ip_int)
            grouped[key]['IPs_List'].append(res['Target_IP'])
        else:
            res['Status'] = 'Error: IPv4 Int Conversion Failed'
            non_aggregated_results.append(res)

    non_aggregated_results.extend([res for res in results if not res['Status'].startswith('Success')])
    
    for key, data in grouped.items():
        if not data['IP_Ints']: 
            continue
            
        sorted_ip_ints = sorted(data['IP_Ints'])
        min_int = sorted_ip_ints[0]
        max_int = sorted_ip_ints[-1]
        count = len(data['IPs_List'])
        try:
            min_ip = str(ipaddress.IPv4Address(min_int))
            max_ip = str(ipaddress.IPv4Address(max_int))
        except ValueError:
            min_ip = data['IPs_List'][0]
            max_ip = data['IPs_List'][-1]
        
        target_ip_display = min_ip if count == 1 else f"{min_ip} - {max_ip} (x{count} IPs)"
        status_display = data['Status'] if count == 1 else f"Aggregated ({count} IPs)"
        
        final_grouped_results.append({
            'Target_IP': target_ip_display, 
            'Country': data['Country'], 
            'Country_JP': data['Country_JP'], 
            'ISP': data['ISP'],
            'ISP_JP': data['ISP_JP'], 
            'RIR_Link': data['RIR_Link'], 
            'Secondary_Security_Links': data['Secondary_Security_Links'],
            'Status': status_display,
            'IoT_Risk': 'Aggr Mode (Skip)' # 集約時はShodan個別判定は省略
        })
    
    final_grouped_results.extend(non_aggregated_results)

    return final_grouped_results

# --- リアルタイム集計関数 ---
def summarize_in_realtime(raw_results):
    isp_counts = {}
    country_counts = {}
    country_code_counts = {}
    proxy_counts = {} 

    target_frequency = st.session_state.get('target_freq_map', {})
    st.session_state['debug_summary'] = {} 

    country_all_df_raw = pd.DataFrame({
        'NumericCode': pd.Series(dtype='int64'), 
        'Count': pd.Series(dtype='int64'),
        'Country': pd.Series(dtype='str')
    })

    success_ipv4 = [
        r for r in raw_results 
        if r['Status'].startswith('Success') and is_ipv4(r['Target_IP'])
    ]

    for r in success_ipv4:
        ip = r.get('Target_IP')
        frequency = target_frequency.get(ip, 1) 

        isp_name = r.get('ISP_JP', r.get('ISP', 'N/A'))
        
        # 画像やダッシュボードの可視化向上のため「株式会社」等の法人格表記を削除
        if isp_name and isp_name not in ['N/A', 'N/A (簡易モード)']:
            isp_name = re.sub(r'(株式会社|有限会社|合同会社|一般社団法人|財団法人|\(株\)|（株）|Inc\.|Co\.,\s*Ltd\.|Corp\.|Corporation)', '', isp_name, flags=re.IGNORECASE).strip()
            
        country_name = r.get('Country_JP', r.get('Country', 'N/A'))
        cc = r.get('CountryCode', 'N/A')
        
        # プロキシ判定の取得
        proxy_val = r.get('Proxy_Type', '')
        if not proxy_val: 
            proxy_val = "未検証"
        else:
            # グラフの凡例用に情報をクリーンアップ（プロキシ種別のみ抽出）
            proxy_val = re.sub(r'\s*\((Source:|API Verified|Local DB)[^)]*\)', '', proxy_val)
            proxy_val = re.sub(r'API Confirmed \((.*?)\)', r'\1', proxy_val)
            proxy_val = re.sub(r'\[(.*?)\]', r'\1', proxy_val)
            proxy_val = proxy_val.strip(' /')
            
        if isp_name and isp_name not in ['N/A', 'N/A (簡易モード)']:
            isp_counts[isp_name] = isp_counts.get(isp_name, 0) + frequency
        
        if country_name and country_name != 'N/A':
            country_counts[country_name] = country_counts.get(country_name, 0) + frequency
            
        if cc and cc != 'N/A':
            country_code_counts[cc] = country_code_counts.get(cc, 0) + frequency
            
        proxy_counts[proxy_val] = proxy_counts.get(proxy_val, 0) + frequency # ⬅️ NEW: 集計

    # --- ISP集計 ---
    isp_full_df = pd.DataFrame(list(isp_counts.items()), columns=['ISP', 'Count']).sort_values('Count', ascending=False)
    isp_df = isp_full_df.head(10).copy() if not isp_full_df.empty else pd.DataFrame(columns=['ISP', 'Count'])
    if not isp_df.empty: isp_df['ISP'] = isp_df['ISP'].str.wrap(25)

    # --- 国集計 ---
    country_full_df = pd.DataFrame(list(country_counts.items()), columns=['Country', 'Count']).sort_values('Count', ascending=False)
    country_df = country_full_df.head(10).copy() if not country_full_df.empty else pd.DataFrame(columns=['Country', 'Count'])
    if not country_df.empty: country_df['Country'] = country_df['Country'].str.wrap(25)

    # --- プロキシ集計 ---
    proxy_full_df = pd.DataFrame(list(proxy_counts.items()), columns=['Proxy_Type', 'Count']).sort_values('Count', ascending=False)
    proxy_df = proxy_full_df.copy() if not proxy_full_df.empty else pd.DataFrame(columns=['Proxy_Type', 'Count'])

    # ヒートマップ用
    if country_code_counts:
        map_data = []
        for cc, cnt in country_code_counts.items():
            num = COUNTRY_CODE_TO_NUMERIC_ISO.get(cc)
            if num is not None:
                map_data.append({'NumericCode': int(num), 'Count': int(cnt), 'Country': COUNTRY_JP_NAME.get(cc, cc)})
        
        # DataFrame構築時のKeyErrorを完全に防ぐフェイルセーフ
        if map_data:
            country_all_df_raw = pd.DataFrame(map_data).astype({'NumericCode': 'int64', 'Count': 'int64'})
        else:
            country_all_df_raw = pd.DataFrame(columns=['NumericCode', 'Count', 'Country'])
            
    st.session_state['debug_summary']['country_code_counts'] = country_code_counts
    st.session_state['debug_summary']['country_all_df'] = country_all_df_raw.to_dict('records')

    # --- ターゲット頻度集計 ---
    freq_map = st.session_state.get('target_freq_map', {})
    finished = st.session_state.get('finished_ips', set())
    freq_list = [{'Target_IP': t, 'Count': c} for t, c in freq_map.items() if t in finished]
    freq_full_df = pd.DataFrame(freq_list).sort_values('Count', ascending=False) if freq_list else pd.DataFrame(columns=['Target_IP', 'Count'])
    freq_df = freq_full_df.head(10).copy() if not freq_full_df.empty else pd.DataFrame(columns=['Target_IP', 'Count'])

    # 戻り値に proxy_df を追加
    return isp_df, country_df, freq_df, country_all_df_raw, isp_full_df, country_full_df, freq_full_df, proxy_df

# --- 集計結果描画ヘルパー関数 (2x2ダッシュボード & 1枚絵出力対応) ---
def draw_summary_content(isp_summary_df, country_summary_df, target_frequency_df, country_all_df, proxy_df, title):
    # --- 以下の変数を初期化 ---
    c_map_img = None
    c_pie_img = None
    c_isp_img = None
    c_proxy_img = None
    # ------------------------------------
    st.markdown(f"**{title}**")
    
    # データがない場合のエラー回避用プレースホルダー作成関数
    def get_empty_chart():
        return alt.Chart(pd.DataFrame({'x': [1]})).mark_text(size=14, color='gray').encode(
            text=alt.value('データなし')
        )

    # グラフの右側に配置するテキストテーブル生成関数 (2段表示・文字潰れ回避版)
    def get_table_chart(df, name_col, count_col, use_color=False, color_scheme=None, domain_list=None):
        if df.empty:
            return alt.Chart(pd.DataFrame({'x': [1]})).mark_text().encode(text=alt.value(''))
        
        # 上位10件に絞る
        top_df = df.copy().sort_values(count_col, ascending=False).head(10)
        
        limit_len = 22 
        top_df['Display_Name'] = top_df[name_col].astype(str).apply(lambda x: x if len(x) <= limit_len else x[:limit_len-1] + '…')
        top_df['Display_Count'] = top_df[count_col].astype(str) + " 件"
        
        # 行を縦に並べるためのベース
        base_table = alt.Chart(top_df).encode(
            y=alt.Y(f'{name_col}:N', sort=alt.EncodingSortField(field=count_col, op='sum', order='descending'), axis=None)
        )
        
        if use_color:
            # 色付き四角形（ブロック）
            color_encoding = alt.Color(
                f'{name_col}:N',
                scale=alt.Scale(domain=domain_list, scheme=color_scheme),
                legend=None
            )
            color_mark = base_table.mark_square(size=200, opacity=1).encode(
                color=color_encoding,
                x=alt.value(10) # ブロックのX座標
            )
            
            # 名称 (1行目: 上寄せ)
            name_text = base_table.mark_text(align='left', baseline='bottom', fontSize=12, color='black', fontWeight='bold', dy=-2).encode(
                text='Display_Name:N',
                x=alt.value(35) # ブロックの右側に配置
            )
            # 件数 (2行目: 下寄せ・少しグレーにして視認性アップ)
            count_text = base_table.mark_text(align='left', baseline='top', fontSize=11, color='#555555', dy=2).encode(
                text='Display_Count:N',
                x=alt.value(35)
            )
            
            table = alt.layer(color_mark, name_text, count_text).properties(width=220, height=280) # 高さを少し広げて余裕を持たせる
            
        else:
            # 色なしの場合 (ISPなど)
            name_text = base_table.mark_text(align='left', baseline='bottom', fontSize=12, color='black', fontWeight='bold', dy=-2).encode(
                text='Display_Name:N',
                x=alt.value(10)
            )
            count_text = base_table.mark_text(align='left', baseline='top', fontSize=11, color='#555555', dy=2).encode(
                text='Display_Count:N',
                x=alt.value(10)
            )
            table = alt.layer(name_text, count_text).properties(width=220, height=280)
            
        return table

    # ----------------------------------------------------
    # データの前処理 (色順固定用ドメイン抽出)
    # ----------------------------------------------------
    if not proxy_df.empty:
        proxy_order = proxy_df.sort_values('Count', ascending=False)['Proxy_Type'].tolist()
    else:
        proxy_order = []

    if not country_summary_df.empty:
        country_order = country_summary_df.sort_values('Count', ascending=False)['Country'].tolist()
    else:
        country_order = []

    # ==========================================
    # ブラウザ表示用 (Tab1) のベースチャート生成
    # ==========================================
    
    # 1. 国別ヒートマップ
    if WORLD_MAP_GEOJSON and not country_all_df.empty:
        base = alt.Chart(WORLD_MAP_GEOJSON).mark_geoshape(
            stroke='black', strokeWidth=0.1, fill="#f0f0f052"
        ).project(type='mercator', scale=65, translate=[220, 150]) 
        
        heatmap = alt.Chart(WORLD_MAP_GEOJSON).mark_geoshape(
            stroke='black', strokeWidth=0.1
        ).encode(
            color=alt.Color('Count:Q', scale=alt.Scale(type='log', scheme='yelloworangered'), legend=None),
            tooltip=[alt.Tooltip('Country:N', title='国名'), alt.Tooltip('Count:Q', title='件数', format=',')]
        ).transform_lookup(
            lookup='id', from_=alt.LookupData(country_all_df, key='NumericCode', fields=['Count', 'Country'])
        ).project(type='mercator', scale=65, translate=[220, 150])
        
        chart_map_base = alt.layer(base, heatmap).resolve_scale(color='independent')
    else:
        chart_map_base = get_empty_chart()

    # 2. ISP横棒グラフの構築
    if not isp_summary_df.empty:
        chart_isp_base = alt.Chart(isp_summary_df).mark_bar(color="#1e3a8a").encode(
            x=alt.X('Count:Q', title='件数', axis=alt.Axis(tickMinStep=1, format='d')),
            y=alt.Y('ISP:N', sort='-x', title='')
        )
    else:
        chart_isp_base = get_empty_chart()

    # 3. 国別パイチャート
    if not country_summary_df.empty:
        chart_pie_base = alt.Chart(country_summary_df).mark_arc().encode(
            theta=alt.Theta(field="Count", type="quantitative"),
            color=alt.Color(
                field="Country", 
                type="nominal", 
                scale=alt.Scale(domain=country_order, scheme="spectral"), 
                legend=alt.Legend(title="国名", orient="right")
            ),
            tooltip=["Country", "Count"]
        )
    else:
        chart_pie_base = get_empty_chart()

    # 4. プロキシドーナツチャート
    if not proxy_df.empty:
        chart_proxy_base = alt.Chart(proxy_df).mark_arc(innerRadius=50).encode(
            theta=alt.Theta(field="Count", type="quantitative"),
            color=alt.Color(
                field="Proxy_Type", 
                type="nominal", 
                scale=alt.Scale(domain=proxy_order, scheme="category10"),
                legend=alt.Legend(title="判定", orient="right")
            ),
            tooltip=["Proxy_Type", "Count"]
        )
    else:
        chart_proxy_base = get_empty_chart()

    # ----------------------------------------------------
    # タブによる表示切り替え
    # ----------------------------------------------------
    tab1, tab2 = st.tabs(["🖥️ 分割ダッシュボード (ブラウザ閲覧用)", "🖼️ IP分析画像"])
    
    with tab1:
        row1_col1, row1_col2 = st.columns(2)
        row2_col1, row2_col2 = st.columns(2)
        
        with row1_col1:
            st.markdown("📍 **国別 ヒートマップ**")
            st.altair_chart(chart_map_base.properties(height=250), width="stretch")
        with row1_col2:
            st.markdown("🏢 **ISP別 件数 (Top 10)**")
            st.altair_chart(chart_isp_base.properties(height=250), width="stretch")
        with row2_col1:
            st.markdown("🌍 **国別 割合 (Pie Chart)**")
            st.altair_chart(chart_pie_base.properties(height=250), width="stretch")
        with row2_col2:
            st.markdown("🕵️ **プロキシ・VPN 割合 (Donut)**")
            st.altair_chart(chart_proxy_base.properties(height=250), width="stretch")
        
    with tab2:
        st.info("💡 **Tips:** 下のチャートの右上にある `...` ボタンから **「Save as PNG」** を選択すると画像が保存できます。")
        
        # 1. 画像用 世界マップ ＆ 表
        if WORLD_MAP_GEOJSON and not country_all_df.empty:
            map_chart = chart_map_base.properties(title="国別 ヒートマップ", height=280, width=400)
            map_table = get_table_chart(country_all_df, 'Country', 'Count', use_color=False)
            c_map_img = alt.hconcat(map_chart, map_table).resolve_scale(y='independent')
        else:
            c_map_img = alt.Chart(pd.DataFrame({'x': [1]})).mark_text(text='データなし').properties(title="国別 ヒートマップ", height=280, width=620)

        # 2. 画像用 国別円グラフ ＆ 表
        if not country_summary_df.empty:
            pie_chart = alt.Chart(country_summary_df).mark_arc().encode(
                theta=alt.Theta(field="Count", type="quantitative"),
                color=alt.Color(field="Country", type="nominal", scale=alt.Scale(domain=country_order, scheme="spectral"), legend=None)
            ).properties(title="国別 割合 (Pie Chart)", height=280, width=400)
            pie_table = get_table_chart(country_summary_df, 'Country', 'Count', use_color=True, color_scheme='spectral', domain_list=country_order) 
            c_pie_img = alt.hconcat(pie_chart, pie_table).resolve_scale(y='independent')
        else:
            c_pie_img = alt.Chart(pd.DataFrame({'x': [1]})).mark_text(text='データなし').properties(title="国別 割合 (Pie Chart)", height=280, width=620)

        # 3. 画像用 ISP横棒 ＆ 表 (順番変更 ＆ Y軸ラベル消去)
        if not isp_summary_df.empty:
            isp_chart = alt.Chart(isp_summary_df).mark_bar(color="#1e3a8a").encode(
                x=alt.X('Count:Q', title='件数', axis=alt.Axis(tickMinStep=1, format='d')),
                y=alt.Y('ISP:N', sort='-x', axis=None) 
            ).properties(title="ISP別 件数 (Top 10)", height=280, width=400)
            isp_table = get_table_chart(isp_summary_df, 'ISP', 'Count', use_color=False)
            c_isp_img = alt.hconcat(isp_chart, isp_table).resolve_scale(y='independent')

        # 4. 画像用 プロキシドーナツ ＆ 表
        if not proxy_df.empty:
            proxy_chart = alt.Chart(proxy_df).mark_arc(innerRadius=50).encode(
                theta=alt.Theta(field="Count", type="quantitative"),
                color=alt.Color(field="Proxy_Type", type="nominal", scale=alt.Scale(domain=proxy_order, scheme="category10"), legend=None) 
            ).properties(title="プロキシ・VPN 割合 (Donut)", height=280, width=400)
            proxy_table = get_table_chart(proxy_df, 'Proxy_Type', 'Count', use_color=True, color_scheme='category10', domain_list=proxy_order) 
            c_proxy_img = alt.hconcat(proxy_chart, proxy_table).resolve_scale(y='independent')
        else:
            c_proxy_img = alt.Chart(pd.DataFrame({'x': [1]})).mark_text(text='データなし').properties(title="プロキシ・VPN 割合 (Donut)", height=280, width=620)

        # 結合処理 ＆ 左側に80pxの余白を追加
        # 1. 生成できたグラフ（Noneではないもの）だけをリスト化する
        valid_charts = [c for c in [c_map_img, c_pie_img, c_isp_img, c_proxy_img] if c is not None]

        # 2. 有効なグラフが1つ以上ある場合のみ連結を実行する
        if valid_charts:
        # リストにアスタリスク(*)をつけて展開し、連結する
            combined_chart = alt.vconcat(*valid_charts).configure(
                background='white',
                padding={'left': 80, 'top': 20, 'right': 20, 'bottom': 20} 
            ).configure_view(
            strokeWidth=0
            ).configure_title(
                fontSize=16, anchor='middle', offset=15, color="black", fontWeight="bold"
            ).configure_axis(
                labelColor='black', titleColor='black', gridColor='#e5e5e5', domainColor='black'
            )
        
            st.altair_chart(combined_chart, width="content")

from reports import (
    generate_full_report_html, generate_stix2_bundle, generate_cross_analysis_html,
    convert_df_to_excel, create_advanced_excel, generate_individual_html_report,
    generate_combined_html_report, get_copy_target
)

def display_results(results, current_mode_full_text, display_mode, use_rdap_option, pro_api_key, vpnapi_key, st_api_key, use_rdns_option, use_st_reverse_ip):
    st.markdown("### 📝 検索結果")

    # SecurityTrails API制限到達時のグローバル警告
    st_limit_hit = False
    for r in results:
        st_j = r.get('ST_JSON')
        st_r = r.get('ST_REVERSE_IP_JSON')
        if isinstance(st_j, dict) and st_j.get('error') == 'rate_limit':
            st_limit_hit = True
            break
        if isinstance(st_r, dict) and st_r.get('error') == 'rate_limit':
            st_limit_hit = True
            break
            
    if st_limit_hit:
        st.error("🚨 **SecurityTrails API 利用制限の警告**: 月間の無料リクエスト枠（50回）に到達しました。一部のターゲットにおいて過去の履歴やReverse IP情報が取得できていません。")

    # --- 2. 判定アイコンと表示ルールの解説 ---
    with st.expander("⚠️ 判定アイコンと表示ルールについて"):
        st.info("""
        ### 🔍 判定ロジックの概要
        本ツールは、起動時に取得する**最新のTorノードリスト**および、**VPNAPI.io 専門データベース**とのAPI連携により、通信主体の属性を判定しています。
        
        インターネット上の通信は、その用途に応じて「個人宅・法人拠点からの直接接続」と「非対面的な中継・ホスティング経由の接続」に大別されます。本機能は後者を検知し、調査の優先順位判断を支援することを目的としています。
        
        ---
        
        ### 📌 判定種別の定義と技術的背景
        - **🧅 [Tor Node]**
            - **定義**: Tor（The Onion Router）ネットワークにおける「Exit Node（出口ノード）」を指します。
            - **背景**: 起動時にTor Project公式サイトより最新のノードリストを取得し、照合を行っています。高い匿名性を維持した通信であるため、セキュリティリスクの検討が必要です。

        - **💀 [IoT Risk]** (Shodan InternetDB連携時のみ)
            - **定義**: 外部からアクセス可能な危険なポートが開放されています。
            - **背景**: Shodanのポートスキャン履歴と照合し、ファイアウォールを通過して露出している以下の「踏み台リスク」を警告します。
                - **Telnet (23) / FTP (21)**: 暗号化されていない危険な旧式プロトコル
                - **ADB (5555/5554)**: 認証なしで操作可能なAndroid/FireTV端末・エミュレータ
                - **TR-069 (7547)**: 乗っ取りリスクのあるルーター管理機能
                - **Proxy (1080/3128/8080)**: 攻撃中継点として悪用されるプロキシ
                - **UPnP (1900)**: 外部からLAN内機器を探査される恐れのある機能
            
        - **🍏 [iCloud Private Relay]**
            - **定義**: Appleデバイス（iPhone/Mac）の標準プライバシー保護機能による通信です。
            - **背景**: Appleの提携パートナー（Cloudflare, Akamai等）が提供する出口IPを使用します。ISP名称に含まれる特定のタグ（例: "iCloud Private Relay"）に基づき判別します。基本的には一般ユーザーですが、真のIPは隠蔽されています。
            
        - **☁️ [VPN/Proxy]**
            - **定義**: 商用VPNサービス、公開プロキシ、またはプライバシー保護を目的とした中継団体に属するIPです。
            - **背景**: ISP名称に含まれる特定のキーワード（VPN, Proxy等）および既知の匿名化サービス運営組織名に基づき判別します。
            
        - **☁️ [Hosting/Infra]**
            - **定義**: クラウドサービス（AWS, Azure, GCP等）や、データセンター、ホスティング事業者のインフラストラクチャです。
            - **背景**: 一般的なコンシューマ回線とは異なり、サーバー間通信やBot、クローラー、あるいは攻撃用インフラとして利用されるケースが多いノードです。
            
        ---
        
        ※ VPNAPI.ioの設定がされていない場合は、Tor判定のみを行います。
        """)

    if not results:
        st.info("検索結果がここに表示されます。")
        return

    # --- 1. データフレーム構築 ---
    df_list = []
    original_cols = []
    
    if "集約" in current_mode_full_text:
        # 集約モードの場合は従来通り、集約された結果をそのまま表示する
        for idx, res in enumerate(results):
            c_code = res.get('CountryCode', 'N/A')
            c_jp = res.get('Country_JP', 'N/A')
            country_display = f"{c_jp} ({c_code})" if c_code != 'N/A' else 'N/A'
            target_ip = res.get('Target_IP', 'N/A')
            
            row_data = {"No.": idx + 1}
            row_data.update({
                "IPアドレス": target_ip,
                "Whois(元データ)": res.get('ISP_API_Raw', 'N/A'),
                "Whois(日本語名)": res.get('ISP_JP', 'N/A'),
                "RDAP(元データ)": res.get('RDAP_Name_Raw', ''),
                "RDAP(日本語名)": res.get('RDAP_JP', ''),
                "国名": country_display,
                "プロキシ種別": res.get('Proxy_Type', ''),
                "IoTリスク": res.get('IoT_Risk', ''),
                "逆引き結果": res.get('RDNS_Hosts', ''),
                "Reverse IP": res.get('ST_Reverse_Hosts', ''),
                "ステータス": res.get('Status', 'N/A')
            })
            df_list.append(row_data)
    else:
        # 標準モード等：入力された全行をそのまま一覧ビューに表示する
        # マッチング精度を高めるための多重キー辞書の構築
        result_lookup = {}
        for r in results:
            target = r.get('Target_IP', '')
            actual = extract_actual_ip(target)
            result_lookup[target] = r
            if actual and actual != target:
                result_lookup[actual] = r

        def get_result_info(raw_ip_str):
            if pd.isna(raw_ip_str): return {}
            val = str(raw_ip_str).strip()
            cleaned = clean_ocr_error_chars(val)
            actual = extract_actual_ip(cleaned)
            return result_lookup.get(actual) or result_lookup.get(cleaned) or result_lookup.get(val) or {}

        full_input_list = st.session_state.get('original_input_list', [])

        if st.session_state.get('original_df') is not None and st.session_state.get('ip_column_name'):
            orig_df = st.session_state['original_df']
            ip_col = st.session_state['ip_column_name']
            original_cols = [c for c in orig_df.columns if c != ip_col]
            
            for idx, row in orig_df.iterrows():
                raw_val = str(row[ip_col]).strip()
                res = get_result_info(raw_val)
                # 検索で弾かれた無効なデータは一覧から除外する
                if not res:
                    continue
                
                c_code = res.get('CountryCode', 'N/A')
                c_jp = res.get('Country_JP', 'N/A')
                country_display = f"{c_jp} ({c_code})" if c_code != 'N/A' else 'N/A'
                
                row_data = {"No.": len(df_list) + 1}
                # 元データの列情報をそれぞれそのまま格納
                for col in original_cols:
                    row_data[col] = str(row.get(col, ''))
                
                row_data.update({
                    "IPアドレス": raw_val,
                    "Whois(元データ)": res.get('ISP_API_Raw', 'N/A'),
                    "Whois(日本語名)": res.get('ISP_JP', 'N/A'),
                    "RDAP(元データ)": res.get('RDAP_Name_Raw', ''),
                    "RDAP(日本語名)": res.get('RDAP_JP', ''),
                    "国名": country_display,
                    "プロキシ種別": res.get('Proxy_Type', ''),
                    "IoTリスク": res.get('IoT_Risk', ''),
                    "逆引き結果": res.get('RDNS_Hosts', ''),
                    "Reverse IP": res.get('ST_Reverse_Hosts', ''),
                    "ステータス": res.get('Status', 'N/A')
                })
                df_list.append(row_data)
        else:
            # テキスト貼り付けの場合
            for idx, raw_val in enumerate(full_input_list):
                res = get_result_info(raw_val)
                if not res:
                    continue
                
                c_code = res.get('CountryCode', 'N/A')
                c_jp = res.get('Country_JP', 'N/A')
                country_display = f"{c_jp} ({c_code})" if c_code != 'N/A' else 'N/A'
                
                row_data = {"No.": len(df_list) + 1}
                row_data.update({
                    "IPアドレス": raw_val,
                    "Whois(元データ)": res.get('ISP_API_Raw', 'N/A'),
                    "Whois(日本語名)": res.get('ISP_JP', 'N/A'),
                    "RDAP(元データ)": res.get('RDAP_Name_Raw', ''),
                    "RDAP(日本語名)": res.get('RDAP_JP', ''),
                    "国名": country_display,
                    "プロキシ種別": res.get('Proxy_Type', ''),
                    "IoTリスク": res.get('IoT_Risk', ''),
                    "逆引き結果": res.get('RDNS_Hosts', ''),
                    "Reverse IP": res.get('ST_Reverse_Hosts', ''),
                    "ステータス": res.get('Status', 'N/A')
                })
                df_list.append(row_data)

    df = pd.DataFrame(df_list)

    # UIの一覧ビューからも不要なカラムを動的に消去する
    ui_cols_to_drop = []
    if not use_rdap_option:
        ui_cols_to_drop.extend(["RDAP(元データ)", "RDAP(日本語名)"])
        
    # IoTリスクが取得されていない（オフ または 集約モード）場合はカラムごと消す
    if all(r.get('IoT_Risk', '') in ['[Not Checked]', 'Aggr Mode (Skip)', '', 'N/A'] for r in results):
        ui_cols_to_drop.append("IoTリスク")
        
    if not use_rdns_option:
        ui_cols_to_drop.append("逆引き結果")
        
    # APIキーの種類(ST or OTX)に関わらず、Reverse IPの実行フラグのみで判定する
    if not use_st_reverse_ip:
        ui_cols_to_drop.append("Reverse IP")
        
    if ui_cols_to_drop:
        df = df.drop(columns=[c for c in ui_cols_to_drop if c in df.columns], errors='ignore')

    # --- 2. マスタービュー (on_select有効化) ---
    st.markdown("#### 📊 一覧ビュー (行クリックで選択)")
    
    # カラム設定を動的に生成
    col_config = {
        "No.": st.column_config.NumberColumn(width="small"),
        "IPアドレス": st.column_config.TextColumn(width="medium"),
        "Whois(元データ)": st.column_config.TextColumn(width="medium"),
        "Whois(日本語名)": st.column_config.TextColumn(width="medium"),
    }
    if "RDAP(元データ)" not in ui_cols_to_drop:
        col_config["RDAP(元データ)"] = st.column_config.TextColumn(width="medium")
        col_config["RDAP(日本語名)"] = st.column_config.TextColumn(width="medium")
    if "IoTリスク" not in ui_cols_to_drop:
        col_config["IoTリスク"] = st.column_config.TextColumn(width="medium")
    if "逆引き結果" not in ui_cols_to_drop:
        col_config["逆引き結果"] = st.column_config.TextColumn(width="medium")
    if "Reverse IP" not in ui_cols_to_drop:
        col_config["Reverse IP"] = st.column_config.TextColumn(width="medium")

    for col in original_cols:
        col_config[col] = st.column_config.TextColumn(width="medium")

    selection_state = st.dataframe(
        df,
        hide_index=True,
        width="stretch",
        height=450,
        on_select="rerun", 
        selection_mode="multi-row",
        column_config=col_config
    )

    st.markdown("---")

    # --- 3. ディテールビュー (一括表示対応) ---
    if "集約" in current_mode_full_text:
        st.info("💡 集約モードでは個別レポート出力はできません。")
        return

    st.markdown("#### 🔍 個別調査 ＆ レポート出力 (Detail View)")
    
    # 選択されたターゲットのリストを作成
    selected_indices = selection_state.selection.rows
    target_results_dict = {} # 重複排除のため辞書を使用 (Key: Target_IP)

    # A. 行が選択されている場合 (手動選択の取得)
    if selected_indices:
        for idx in selected_indices:
            if idx < len(df):
                target_ip = df.iloc[idx]['IPアドレス']
                
                # dfに表示されているIPから、元の検索結果(results)のデータを逆引きする
                actual_ip_searched = extract_actual_ip(clean_ocr_error_chars(target_ip))
                for r in results:
                    r_target = r.get('Target_IP', '')
                    r_actual = extract_actual_ip(r_target)
                    if r_target == target_ip or r_actual == actual_ip_searched:
                        target_results_dict[r_target] = r
                        break

    # B. フィルタリングUIを常に表示し、条件指定の取得を行う
    st.info("👆 一覧の行クリック選択と、以下の条件指定は同時に併用可能です。")
    with st.expander("🔎 条件でターゲットを一括指定する", expanded=True):
        col_f1, col_f2 = st.columns(2)
        with col_f1:
            all_countries = sorted(list(set([r.get('Country_JP', 'N/A') for r in results])))
            sel_countries = st.multiselect("国名で選択:", all_countries)
        with col_f2:
            all_isps = sorted(list(set([r.get('ISP_JP', 'N/A') for r in results])))
            sel_isps = st.multiselect("Whois(日本語名)で選択:", all_isps)
            
        # --- 元データの属性フィルタUI ---
        orig_filters = {}
        if original_cols and not df.empty:
            st.markdown("---")
            st.markdown("**📁 元データ (アップロードファイル) の属性で絞り込む**")
            
            filter_cols = st.columns(min(len(original_cols), 3) or 1)
            col_idx = 0
            
            for col_name in original_cols:
                with filter_cols[col_idx % 3]:
                    # UIフィルターは、結合された表示用dfではなく、元の生データから正確な選択肢を生成する
                    raw_series = st.session_state['original_df'][col_name] if st.session_state.get('original_df') is not None else df[col_name]
                    
                    # 列が日時として解釈できるか判定
                    is_datetime = False
                    if any(k in col_name.lower() for k in ['date', 'time', '日時', '時間', '時刻']):
                        try:
                            try:
                                parsed_dates = pd.to_datetime(raw_series, errors='coerce', format='mixed').dropna()
                            except ValueError:
                                parsed_dates = pd.to_datetime(raw_series, errors='coerce', infer_datetime_format=True).dropna()
                            if not parsed_dates.empty:
                                is_datetime = True
                                min_date = parsed_dates.min().date()
                                max_date = parsed_dates.max().date()
                        except:
                            pass
                    
                    if is_datetime:
                        date_range = st.date_input(f"📅 {col_name} (範囲)", value=[min_date, max_date], key=f"filter_{col_name}")
                        orig_filters[col_name] = {'type': 'date', 'value': date_range}
                    else:
                        # 結合文字列ではなく、個別のユニークな値を抽出
                        unique_vals = [str(v) for v in raw_series.dropna().unique() if str(v).strip() != '']
                        if 0 < len(unique_vals) <= 50:
                            selected_vals = st.multiselect(f"🏷️ {col_name}", sorted(unique_vals), key=f"filter_{col_name}")
                            orig_filters[col_name] = {'type': 'multiselect', 'value': selected_vals}
                        else:
                            text_search = st.text_input(f"🔍 {col_name} (部分一致)", key=f"filter_{col_name}")
                            orig_filters[col_name] = {'type': 'text', 'value': text_search}
                col_idx += 1
        
        # --- フィルタリング実行 ---
        # 何らかのフィルタ指定が存在するかチェック
        has_filter_input = bool(sel_countries or sel_isps)
        for f in orig_filters.values():
            if f['type'] == 'date' and len(f['value']) == 2:
                has_filter_input = True
            elif f['type'] in ('multiselect', 'text') and f['value']:
                has_filter_input = True

        if has_filter_input:
            for res in results:
                target_ip = res.get('Target_IP')
                actual_ip = extract_actual_ip(target_ip)
                
                c_match = res.get('Country_JP', 'N/A') in sel_countries if sel_countries else True
                i_match = res.get('ISP_JP', 'N/A') in sel_isps if sel_isps else True
                
                orig_match = True
                if orig_filters:
                    rows_list = orig_data_map.get(actual_ip, [])
                    if rows_list:
                        any_row_match = False
                        # IPに紐づく複数の履歴(行)のうち、いずれか1行でも全てのフィルタ条件を満たせば抽出対象とする
                        for row_data in rows_list:
                            row_match = True
                            for col_name, filter_info in orig_filters.items():
                                val = str(row_data.get(col_name, ''))
                                f_type = filter_info['type']
                                f_val = filter_info['value']
                                
                                if f_type == 'date' and len(f_val) == 2:
                                    if val:
                                        try:
                                            try:
                                                row_date = pd.to_datetime(val, format='mixed').date()
                                            except ValueError:
                                                row_date = pd.to_datetime(val, infer_datetime_format=True).date()
                                            if not (f_val[0] <= row_date <= f_val[1]):
                                                row_match = False
                                                break
                                        except:
                                            row_match = False
                                            break
                                    else:
                                        row_match = False
                                        break
                                elif f_type == 'multiselect' and f_val:
                                    if val not in f_val:
                                        row_match = False
                                        break
                                elif f_type == 'text' and f_val:
                                    if f_val.lower() not in val.lower():
                                        row_match = False
                                        break
                            
                            if row_match:
                                any_row_match = True
                                break
                                
                        if not any_row_match:
                            orig_match = False
                    else:
                        orig_match = False # 元データが存在しないIPはフィルタ除外
                
                if c_match and i_match and orig_match:
                    target_results_dict[target_ip] = res

    # 辞書から最終的なリストを生成 (重複は自動的に上書き・排除される)
    target_results = list(target_results_dict.values())
    
    if target_results:
        st.success(f"✅ 合計 **{len(target_results)}** 件が選択されています（手動選択: {len(selected_indices)}件 / フィルタ条件と結合済）。")

    # --- 4. 選択された全ターゲットに対してレポートを表示 ---
    if target_results:
        total_selected = len(target_results)

        st.markdown("##### ⚙️ レポート出力項目の選択")
        st.caption("※ APIキーが未入力の項目や、検索設定でオフになっていた機能はグレーアウト（無効化）されます。")
        
        # 選択されたターゲットにドメインが含まれているか、IPが含まれているかを判定
        has_domain_in_selection = any(not is_valid_ip(r.get('Target_IP', '')) or "(" in r.get('Target_IP', '') for r in target_results)
        has_ip_in_selection = any(is_valid_ip(extract_actual_ip(r.get('Target_IP', ''))) for r in target_results)

        # WHOISデータが実際に取得されているかを判定（複数入力時はIP-BAN回避のためスキップされている）
        has_whois_in_selection = False
        for r in target_results:
            target_ip = r.get('Target_IP', 'N/A')
            detailed = st.session_state.get('detailed_data', {}).get(target_ip, {})
            if detailed.get('IP_WHOIS_TEXT') or detailed.get('DOMAIN_WHOIS_TEXT'):
                has_whois_in_selection = True
                break

        # チェックボックスを10列に拡張し、Reverse IPを独立させます
        col_opt1, col_opt2, col_opt3, col_opt4, col_opt5, col_opt6, col_opt7, col_opt8, col_opt9, col_opt10 = st.columns(10)
        
        with col_opt1: opt_tld = st.checkbox("ドメイン情報", value=has_domain_in_selection, disabled=not has_domain_in_selection)
        with col_opt2: opt_dns = st.checkbox("正引き", value=has_domain_in_selection, disabled=not has_domain_in_selection)
        
        # サブネットはRDAPオプションが有効で、IPが含まれる場合のみ表示
        with col_opt3: opt_subnet = st.checkbox("サブネット", value=use_rdap_option and has_ip_in_selection, disabled=not (use_rdap_option and has_ip_in_selection))
        with col_opt4: opt_rdap = st.checkbox("RDAP", value=use_rdap_option, disabled=not use_rdap_option)
        
        # Reverse IPが実行されている場合、CDNの無用なWHOIS情報を省くためデフォルトをオフ(False)にする
        default_whois = has_whois_in_selection and not use_st_reverse_ip
        with col_opt5: opt_whois = st.checkbox("WHOIS", value=default_whois, disabled=not has_whois_in_selection)
        
        with col_opt6: opt_ipinfo = st.checkbox("IPinfo", value=bool(pro_api_key) and has_ip_in_selection, disabled=not bool(pro_api_key) or not has_ip_in_selection)
        
        # ローカルDBで検知されたプロキシ情報が含まれているか確認
        has_proxy_alert_in_selection = any(r.get('Proxy_Type', '') not in ["", "Standard Connection", "N/A", "N/A (Domain)"] for r in target_results)
        
        # VPNAPIキーがあるか、またはローカルDBでの検知があればチェックを有効化
        enable_proxy_tab = (bool(vpnapi_key) and has_ip_in_selection) or has_proxy_alert_in_selection
        with col_opt7: opt_vpnapi = st.checkbox("匿名通信判定", value=enable_proxy_tab, disabled=not enable_proxy_tab)
        
        # 履歴機能の分離 (ドメイン用のDNS履歴 と IP用のReverse IP)
        with col_opt8: opt_st_dns = st.checkbox("DNS履歴", value=bool(st_api_key) and has_domain_in_selection, disabled=not bool(st_api_key) or not has_domain_in_selection)
        with col_opt9: opt_rdns = st.checkbox("逆引き", value=use_rdns_option and has_ip_in_selection, disabled=not use_rdns_option or not has_ip_in_selection)
        
        # レポート出力対象のIPにReverse IPのJSONデータが含まれているかを判定して活性化する
        has_revip_in_selection = False
        for r in target_results:
            target_ip = r.get('Target_IP', 'N/A')
            detailed = st.session_state.get('detailed_data', {}).get(target_ip, {})
            if detailed.get('ST_REVERSE_IP_JSON'):
                has_revip_in_selection = True
                break

        with col_opt10: opt_revip = st.checkbox("Reverse IP", value=has_revip_in_selection, disabled=not has_revip_in_selection)
        
        current_report_opts = {
            "tld": opt_tld,
            "dns": opt_dns,
            "subnet": opt_subnet,
            "rdap": opt_rdap,
            "whois": opt_whois,
            "ipinfo": opt_ipinfo,
            "vpnapi": opt_vpnapi,
            "st": opt_st_dns,     # ドメイン専用
            "rdns": opt_rdns,
            "revip": opt_revip    # Reverse IP専用のキーを追加
        }

        # 📦 一括ダウンロードボタン (複数選択時のみ表示)
        if total_selected > 1:
            st.markdown("##### 📦 複数レポート一括ダウンロード")
            col_btn1, col_btn2 = st.columns(2)
            
            # 重い処理の前にスピナーを割り込ませ、フリーズではなく「処理中」であることを明示する
            with st.spinner(f"⏳ {total_selected} 件のレポートデータを構築中... (しばらくお待ちください)"):
                
                # メモリ節約のため分離されていた詳細データ(detailed_data)を統合した完全なリストを構築
                full_target_results = []
                for res in target_results:
                    clean_ip = get_copy_target(res.get('Target_IP', 'N/A'))
                    full_res = {**res}
                    if clean_ip in st.session_state.get('detailed_data', {}):
                        full_res.update(st.session_state['detailed_data'][clean_ip])
                    full_target_results.append(full_res)

                # 1. 統合レポート(HTML)の生成 (完全なデータリストを渡す)
                combined_html = generate_combined_html_report(full_target_results, current_report_opts)
                
                # 2. ZIPファイルの生成 (tempfileを利用してディスクに書き出し)
                with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp:
                    tmp_zip_path = tmp.name
                    
                try:
                    with zipfile.ZipFile(tmp_zip_path, "w", zipfile.ZIP_DEFLATED, False) as zip_file:
                        valid_reports_count = 0
                        # 構築済みの full_target_results をループ処理する
                        for full_res in full_target_results:
                            target_ip = full_res.get('Target_IP', 'N/A')
                            clean_ip = get_copy_target(target_ip)
                            
                            html_report = generate_individual_html_report(full_res, clean_ip, current_report_opts)
                            if html_report:
                                safe_filename = re.sub(r'[\\/*?:"<>|]', "_", clean_ip)
                                zip_file.writestr(f"Report_{safe_filename}.html", html_report.encode('utf-8'))
                                valid_reports_count += 1
                
                    if valid_reports_count > 0:
                        current_time = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                        html_filename = f"Combined_Report_{current_time}.html"
                        zip_filename = f"Whois_Reports_Batch_{current_time}.zip"
                        
                        with col_btn1:
                            if combined_html: # ✅ None書き込みエラーを防ぐフェイルセーフ
                                if IS_PUBLIC_MODE:
                                    st.download_button(
                                        label=f"📜 {valid_reports_count} 件を1つの統合レポート(HTML)で保存",
                                        data=combined_html.encode('utf-8'),
                                        file_name=html_filename,
                                        mime="text/html",
                                        type="primary",
                                        width="stretch",
                                        help="選択した全件のレポートが1つのWebページに目次付きでまとまります。"
                                    )
                                else:
                                    render_local_save_ui(
                                        f"💾 {valid_reports_count} 件の統合レポートをローカル保存", 
                                        html_filename, combined_html, "batch_html", "primary"
                                    )
                            else:
                                st.error("統合レポートのデータ生成に失敗しました。")
                                    
                        with col_btn2:
                            with open(tmp_zip_path, "rb") as f:
                                zip_data = f.read()
                            
                            if IS_PUBLIC_MODE:
                                st.download_button(
                                    label=f"🗜️ {valid_reports_count} 件の個別レポートをZIPで保存",
                                    data=zip_data,
                                    file_name=zip_filename,
                                    mime="application/zip",
                                    type="secondary",
                                    width="stretch",
                                    help="各IPごとに独立したHTMLファイルを作成し、ZIPに圧縮してダウンロードします。"
                                )
                            else:
                                render_local_save_ui(
                                    f"💾 {valid_reports_count} 件のZIPをローカル保存 (無制限)", 
                                    zip_filename, zip_data, "batch_zip", "secondary"
                                )
                finally:
                    if os.path.exists(tmp_zip_path):
                        os.remove(tmp_zip_path) # 送信後、またはエラー発生時に確実に削除する
            st.divider()
        
        # Rendering Overload（UI崩壊）を防ぐためのハードリミット設定
        DISPLAY_LIMIT = 50 
        if total_selected > DISPLAY_LIMIT:
            st.warning(f"⚠️ **ブラウザ保護制限**: 選択された件数（{total_selected}件）が上限を超えています。UIのフリーズを防ぐため、画面上での個別プレビューは最初の {DISPLAY_LIMIT} 件のみ表示しています。")
            display_targets = target_results[:DISPLAY_LIMIT]
        else:
            display_targets = target_results

        for i, res in enumerate(display_targets):
            target_ip = res.get('Target_IP', 'N/A')
            clean_ip = get_copy_target(target_ip)
            
            with st.container():
                # チェックボックス用のユニークなキーを生成
                done_key = f"done_target_{clean_ip}_{i}"
                
                # タイトルとチェックボックスを横に並べる
                col_title, col_chk = st.columns([4, 1])
                with col_chk:
                    is_done = st.checkbox("✅ 調査完了", key=done_key)

                        # チェック状態に応じて表示UIを動的に切り替える
            if is_done:
                with col_title:
                    safe_target_ip = html.escape(str(target_ip))
                    safe_total_selected = html.escape(str(total_selected))
                    safe_i = html.escape(str(i + 1))
                    st.markdown(
                        f"<h5 style='color: #9e9e9e; text-decoration: line-through;'>"
                        f"🎯 [{safe_i}/{safe_total_selected}] Target: {safe_target_ip}</h5>",
                        unsafe_allow_html=True
                    )
                
                container_context = st.expander("📁 完了済みの詳細データを再確認する", expanded=False)
            else:
                with col_title:
                    st.markdown(f"##### 🎯 [{i+1}/{total_selected}] Target: `{target_ip}`")
                
                # 詳細情報を Container に格納し、そのまま展開して表示する
                container_context = st.container()


                # 詳細情報の描画（完了・未完了問わず中身は同じ）
                with container_context:
                    c1, c2 = st.columns([2, 1])
                    with c1:
                        # リンク集
                        st.markdown(f"**🛡️ 外部調査リンク:**")
                        st.markdown(f"{res.get('Secondary_Security_Links', '-')}")
                        
                        # RIRリンク
                        st.markdown(f"**📚 RIR / Whois 窓口:** {res.get('RIR_Link', '-')}")
                        
                        # コピー枠の横幅を絞り、マウス移動の負担を極小化する
                        code_col, _ = st.columns([1, 2])
                        with code_col:
                            st.code(clean_ip, language=None)
                        
                        # 補足情報
                        st.caption(f"ISP: {res.get('ISP_JP', '-')} / RDAP: {res.get('RDAP_JP', '-')}")    
                    with c2:
                        # HTMLレポート生成
                        full_res = {**res}
                        target_ip = res.get('Target_IP', 'N/A')
                        if target_ip in st.session_state.get('detailed_data', {}):
                            full_res.update(st.session_state['detailed_data'][target_ip])
                            
                        html_report = generate_individual_html_report(full_res, clean_ip, current_report_opts)
                        if html_report:
                            st.download_button(
                                label=f"⬇️ レポートDL ({clean_ip})",
                                data=html_report,
                                file_name=f"Report_{clean_ip}.html",
                                mime="text/html",
                                key=f"dl_btn_multi_{clean_ip}_{i}", # if分岐で片方しか実行されないため同じキーでOK
                                width="stretch"
                            )
                        else:
                            st.button("データなし", disabled=True, key=f"no_dl_{i}")
                
                st.divider()
    else:
        st.caption("詳細を表示するには、一覧の行をクリックするか、条件を指定してください。")

# --- リンク分析エンジン ---
def render_spider_web_analysis(df):
    """
    ノードベースの相関グラフ表示機能。Graphvizを使用して描画する。
    """
    st.info("IPアドレス、ISP、国、およびリスクの繋がりを視覚化します。共通のISPやリスクを持つIPが中心に集まり、攻撃インフラの『ハブ』を特定できます。")

    if df.empty:
        st.warning("データがありません。")
        return

    # ============================================================
    # ★ Graphviz DOT 言語インジェクション対策: ユーザ入力をサニタイズ
    # ============================================================
    def _sanitize_dot(s, max_len=80):
        """
        Graphviz DOT の特殊文字 (, ; [ ] { } = \n \r) を全て除去し、
        ラベル文字列として安全なASCIIのみを残す。
        """
        if s is None:
            return ""
        s = str(s)
        # 制御文字・改行・引用符・括弧・演算子を全て無害な文字に置換
        for bad in ['\\', '"', '\n', '\r', '\t', '[', ']', '{', '}', '(', ')', ';', '=', '<', '>']:
            s = s.replace(bad, '_')
        # 長さ制限でグラフの見た目を維持
        s = s.strip()
        if len(s) > max_len:
            s = s[:max_len - 1] + "…"
        return s or "(empty)"

    # GraphvizのDOT言語でグラフ構造を定義
    dot_lines = [
        'graph {',
        '  layout=neato;',  # ノードを物理的な反発力で自動配置するエンジン
        '  overlap=false;',
        '  splines=true;',
        '  node [fontname="Helvetica", fontsize=10];'
    ]

    nodes = set()
    edges = set()

    # 描画負荷を考慮し、上位50件程度でプロット
    plot_df = df.head(50).fillna("N/A")

    for _, row in plot_df.iterrows():
        # ★ 修正: replace('"', '') ではなく _sanitize_dot() を使う
        ip = _sanitize_dot(row.get('IPアドレス', row.get('Target_IP', 'Unknown')))

        isp = _sanitize_dot(row.get('Whois結果（日本語名称）', row.get('ISP_JP', row.get('ISP', 'N/A'))))
        country = _sanitize_dot(row.get('国名', row.get('Country_JP', row.get('Country', 'N/A'))))
        risk = _sanitize_dot(row.get('IoTリスク', row.get('IoT_Risk', '')))
        proxy = _sanitize_dot(row.get('プロキシ種別', row.get('Proxy Type', '')))

        # 1. IPノード (水色の丸)
        nodes.add(f'"{ip}" [shape=circle, style=filled, fillcolor="#E0F2F1", width=0.8];')

        # 2. ISPノード (オレンジの四角) - IPと線を結ぶ
        if isp != "N/A" and isp != "(empty)":
            nodes.add(f'"{isp}" [shape=box, style=filled, fillcolor="#FFF3E0", color="#FF9800", penwidth=2];')
            edges.add(f'"{ip}" -- "{isp}" [color="#FF980080"];')

        # 3. 国ノード (緑の楕円)
        if country != "N/A" and country != "(empty)":
            nodes.add(f'"{country}" [shape=ellipse, style=filled, fillcolor="#F1F8E9", color="#8BC34A"];')
            edges.add(f'"{ip}" -- "{country}" [style=dotted, color="#8BC34A"];')

        # 4. リスクノード (赤の二重丸) - 複数リスクは分割して線を結ぶ
        if risk and risk not in ("[No Match]", "[Not Checked]", "[No Data]", "N/A", "", "(empty)"):
            for r in risk.split(" / "):
                r_clean = _sanitize_dot(r)
                if not r_clean or r_clean == "(empty)":
                    continue
                nodes.add(f'"{r_clean}" [shape=doublecircle, style=filled, fillcolor="#FFEBEE", color="#F44336", fontcolor="#B71C1C", penwidth=3];')
                edges.add(f'"{ip}" -- "{r_clean}" [color="#F44336", penwidth=2];')

        # 5. プロキシノード (紫の六角形)
        if proxy and proxy != "Standard Connection" and proxy != "(empty)":
            nodes.add(f'"{proxy}" [shape=hexagon, style=filled, fillcolor="#F3E5F5", color="#9C27B0"];')
            edges.add(f'"{ip}" -- "{proxy}" [color="#9C27B0"];')

    dot_lines.extend(list(nodes))
    dot_lines.extend(list(edges))
    dot_lines.append('}')

    dot_string = "\n".join(dot_lines)

    # Streamlit標準のGraphviz描画機能を使用
    st.graphviz_chart(dot_string)

    with st.expander("💡 読み解きのヒント"):
        st.write("""
        - **大きな塊（ハブ）**: 複数のIPから線が集まっているノード（ISPやリスク）は、今回の調査対象に共通するインフラです。
        - **赤い二重丸**: 危険なポートが露出している共通のリスク要因です。攻撃者の踏み台リストの可能性があります。
        - **独立したノード**: 他と繋がりのないIPは、今回のグループとは別の背景を持つ可能性があります。
        """)


# 📊 元データ結合分析機能 (タブ化対応 & 時間クロス分析対応)
def render_merged_analysis(df_merged):

    st.markdown("### 📈 分析センター")
    
    # グループ化した際のカラーパレット（配色テーマ）を選べるように拡張
    with st.expander("🎨 グラフのカスタムカラー設定", expanded=False):
        st.markdown("クロス分析や時間分析において、グラフの色を変更できます。")
        col_c1, col_c2 = st.columns(2)
        with col_c1:
            base_color = st.color_picker("単一グラフ用ベースカラー:", "#1e3a8a", help="グループ化を使用しない場合の単一色を指定します。")
        with col_c2:
            color_scheme = st.selectbox(
                "グループ化用カラーパレット:", 
                ["tableau10", "category10", "category20", "set1", "set2", "dark2", "accent", "paired", "pastel1", "pastel2"],
                index=0, 
                help="グループ化/色分けを使用した際に、各カテゴリに割り当てられる配色のテーマを選択します。"
            )

    # モードに応じて時間分析タブの表示/非表示を切り替え
    if IS_PUBLIC_MODE:
        tab_cross, tab_spider = st.tabs(["📊 クロス分析 (マクロ視点)", "🕸️ リンク分析 (ミクロ視点)"])
    else:
        tab_cross, tab_time, tab_spider = st.tabs(["📊 クロス分析 (マクロ視点)", "🕒 時間分析 (時系列・グループ化対応)", "🕸️ リンク分析 (ミクロ視点)"])
    
    # --- 共通の列整理処理 ---
    exclude_cols = ['Whois(元データ)', 'Whois(日本語名)', '国名（英語）', '国名', 'プロキシ種別', 'ステータス', 'IoTリスク', 'RDAP(元データ)', 'RDAP(日本語名)', 'ISP', 'ISP_JP', 'Country', 'Country_JP']
    original_cols = [c for c in df_merged.columns if c not in exclude_cols]
    base_whois_cols = ['Whois(日本語名)', '国名', 'プロキシ種別', 'IoTリスク', 'ステータス']
    whois_cols = [c for c in base_whois_cols if c in df_merged.columns]

    with tab_cross:
        st.info("アップロードされたファイルの元の列と、検索で得られたWhois情報を組み合わせて可視化します。")
        col_x, col_grp, col_chart_type = st.columns(3)
        with col_x:
            x_col = st.selectbox("X軸 (カテゴリ/元の列)", original_cols + whois_cols, index=0, key="merged_x_col")
        with col_grp:
            grp_options = ['(なし)'] + whois_cols + original_cols
            default_grp_idx = 1 if len(grp_options) > 1 else 0
            group_col = st.selectbox("積み上げ/色分け (Whois情報など)", grp_options, index=default_grp_idx, key="merged_group_col")
        with col_chart_type:
            chart_type = st.radio("グラフタイプ", ["バーチャート (集計)", "ヒートマップ"], horizontal=True, key="merged_chart_type")

        if not df_merged.empty:
            chart = None
            chart_df = df_merged.fillna("N/A").astype(str)
            
            if len(chart_df) > 5000:
                st.warning(f"⚠️ **データ量警告**: データが {len(chart_df)} 件あります。ブラウザのクラッシュを防ぐため、ランダムに抽出した 5000 件のデータでグラフを描画しています。")
                chart_df = chart_df.sample(n=5000, random_state=42)

            if chart_type == "バーチャート (集計)":
                if group_col != '(なし)':
                    # 選択した color_scheme (パレット) を積み上げグラフに適用
                    chart = alt.Chart(chart_df).mark_bar().encode(
                        x=alt.X(x_col, title=x_col),
                        y=alt.Y('count()', title='件数', axis=alt.Axis(tickMinStep=1, format='d')),
                        color=alt.Color(group_col, title=group_col, scale=alt.Scale(scheme=color_scheme)),
                        tooltip=[x_col, group_col, 'count()']
                    ).properties(height=400)
                else:
                    chart = alt.Chart(chart_df).mark_bar(color=base_color).encode(
                        x=alt.X(x_col, title=x_col),
                        y=alt.Y('count()', title='件数', axis=alt.Axis(tickMinStep=1, format='d')),
                        tooltip=[x_col, 'count()']
                    ).properties(height=400)
            elif chart_type == "ヒートマップ":
                 if group_col != '(なし)':
                    chart = alt.Chart(chart_df).mark_rect().encode(
                        x=alt.X(x_col, title=x_col),
                        y=alt.Y(group_col, title=group_col),
                        color=alt.Color('count()', title='件数', scale=alt.Scale(scheme='viridis')),
                        tooltip=[x_col, group_col, 'count()']
                    ).properties(height=400)
                 else:
                     st.warning("ヒートマップには「積み上げ/色分け」項目の選択が必要です。")

            if chart:
                st.altair_chart(chart, width="stretch")
                chart_json = chart.to_dict()
                html_content = generate_cross_analysis_html(chart_json, x_col, group_col if group_col != '(なし)' else 'Count')
                base_fname = st.session_state.get('base_filename', 'WhoisSearchResult')
                ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                st.download_button(
                    label="⬇️ クロス分析レポート(HTML)をダウンロード",
                    data=html_content,
                    file_name=f"{base_fname}_CrossAnalysis_{x_col}_vs_{group_col}_{ts}.html",
                    mime="text/html"
                )

    # --- 時間分析タブ (グループ化対応 / Local版専用) ---
    if not IS_PUBLIC_MODE:
        with tab_time:
            st.info("日時列とWhois情報（ISPなど）を組み合わせて、時系列でのアクセス傾向を分析します。")
            
            time_cols = []
            for col in original_cols:
                if any(k in col.lower() for k in ['date', 'time', '日時', '時間', '時刻', 'jst']):
                    time_cols.append(col)
            
            all_cols_for_time = time_cols + [c for c in original_cols if c not in time_cols]
        
            if not all_cols_for_time:
                st.warning("時間分析に利用できるデータ列がありません。")
            else:
                col_t1, col_t2, col_t3 = st.columns(3)
                with col_t1:
                    selected_time_col = st.selectbox("分析に使用する日時列:", all_cols_for_time, key="time_col_selector_merged")
                with col_t2:
                    time_group_col = st.selectbox("グループ化 / 色分け:", ['(なし)'] + whois_cols, key="time_group_col_merged")
                with col_t3:
                    display_group_col = time_group_col
                    if time_group_col != '(なし)':
                        default_label = time_group_col.replace('（日本語名称）', '').replace('（元データ）', '')
                        display_group_col = st.text_input("📝 画像の表示名 (任意に変更可):", value=default_label, key="custom_group_name_input")
                        if not display_group_col.strip():
                            display_group_col = time_group_col
                
                if selected_time_col:
                    df_time = df_merged.copy()
                    try:
                        try:
                            df_time['JST_Datetime'] = pd.to_datetime(df_time[selected_time_col], errors='coerce', format='mixed')
                        except ValueError:
                            df_time['JST_Datetime'] = pd.to_datetime(df_time[selected_time_col], errors='coerce', infer_datetime_format=True)
                        df_time = df_time.dropna(subset=['JST_Datetime'])
                        
                        if df_time.empty:
                            st.error("選択された列から有効な日時データを抽出できませんでした。")
                        else:
                            # 共通の前処理
                            df_time['Date'] = df_time['JST_Datetime'].dt.date
                            df_time['Month'] = df_time['JST_Datetime'].dt.strftime('%Y/%m')
                            weekday_order = ['月曜日', '火曜日', '水曜日', '木曜日', '金曜日', '土曜日', '日曜日']
                            df_time['Weekday'] = df_time['JST_Datetime'].dt.dayofweek.map(
                                {0: '月曜日', 1: '火曜日', 2: '水曜日', 3: '木曜日', 4: '金曜日', 5: '土曜日', 6: '日曜日'}
                            )
                            df_time['Hour'] = df_time['JST_Datetime'].dt.hour
                            
                            # --- パターンA: 色分けなし (シンプルな時系列) ---
                            if time_group_col == '(なし)':
                                daily_df = df_time.groupby('Date').size().reset_index(name='Count')
                                daily_df['Date'] = pd.to_datetime(daily_df['Date'])
                                
                                monthly_df = df_time.groupby('Month').size().reset_index(name='Count')
                                weekday_df = df_time.groupby('Weekday').size().reset_index(name='Count')
                                
                                hour_df = df_time.groupby('Hour').size().reset_index(name='Count')
                                hour_full_df = pd.DataFrame({'Hour': range(24)}).merge(hour_df, on='Hour', how='left').fillna(0)
                                
                                heatmap_df = df_time.groupby(['Hour', 'Weekday']).size().reset_index(name='Count')

                                chart_daily = alt.Chart(daily_df).mark_line(point=True, color=base_color).encode(
                                    # X軸に tickCount='day' と labelAngle=-45 等を追加
                                    x=alt.X('Date:T', title='日付', axis=alt.Axis(format='%m/%d', tickCount='day', labelAngle=-45, labelOverlap=True)),
                                    y=alt.Y('Count:Q', title='件数', axis=alt.Axis(tickMinStep=1, format='d')),
                                    tooltip=[alt.Tooltip('Date:T', title='日付', format='%Y/%m/%d'), 'Count:Q']
                                ).properties(title='日次推移')
                                
                                chart_monthly = alt.Chart(monthly_df).mark_bar(color=base_color).encode(
                                    x=alt.X('Month:N', title='月'),
                                    y=alt.Y('Count:Q', title='件数', axis=alt.Axis(tickMinStep=1, format='d')),
                                    tooltip=['Month:N', 'Count:Q']
                                ).properties(title='月次傾向')
                                    
                                chart_weekday = alt.Chart(weekday_df).mark_bar(color=base_color).encode(
                                    x=alt.X('Weekday:N', sort=weekday_order, title='曜日'),
                                    y=alt.Y('Count:Q', title='件数', axis=alt.Axis(tickMinStep=1, format='d')),
                                    tooltip=['Weekday:N', 'Count:Q']
                                ).properties(title='曜日別傾向')
                                    
                                chart_hour = alt.Chart(hour_full_df).mark_bar(color=base_color).encode(
                                    x=alt.X('Hour:O', title='時刻 (時)'),
                                    y=alt.Y('Count:Q', title='件数', axis=alt.Axis(tickMinStep=1, format='d')),
                                    tooltip=['Hour:O', 'Count:Q']
                                ).properties(title='時間帯別傾向')
                                
                                chart_heatmap_base = alt.Chart(heatmap_df).mark_rect().encode(
                                    x=alt.X('Hour:O', title='時刻 (時)'),
                                    y=alt.Y('Weekday:N', sort=weekday_order, title='曜日'),
                                    color=alt.Color('Count:Q', scale=alt.Scale(scheme='yelloworangered'), title='件数'),
                                    tooltip=['Weekday:N', 'Hour:O', 'Count:Q']
                                ).properties(title='曜日 × 時間帯 ヒートマップ')

                            # --- パターンB: グループ化(色分け)あり ---
                            else:
                                df_time[time_group_col] = df_time[time_group_col].fillna('N/A').astype(str)
                                
                                # 正式名称から「株式会社」等を削除して可視化を向上
                                df_time[time_group_col] = df_time[time_group_col].apply(
                                    lambda x: re.sub(r'(株式会社|有限会社|合同会社|一般社団法人|財団法人|\(株\)|（株）|Inc\.|Co\.,\s*Ltd\.|Corp\.|Corporation)', '', x, flags=re.IGNORECASE).strip()
                                )
                                
                                # ブラウザクラッシュ回避のため、上位10件に絞り残りを「その他」にまとめる
                                top_categories = df_time[time_group_col].value_counts().nlargest(10).index
                                df_time[time_group_col] = df_time[time_group_col].where(df_time[time_group_col].isin(top_categories), 'その他')
                                
                                # 利用者が任意に変更したグループ名を反映するため、列名をリネーム
                                if time_group_col != display_group_col:
                                    df_time = df_time.rename(columns={time_group_col: display_group_col})
                                
                                daily_df = df_time.groupby(['Date', display_group_col]).size().reset_index(name='Count')
                                daily_df['Date'] = pd.to_datetime(daily_df['Date'])
                                
                                monthly_df = df_time.groupby(['Month', display_group_col]).size().reset_index(name='Count')
                                weekday_df = df_time.groupby(['Weekday', display_group_col]).size().reset_index(name='Count')
                                hour_full_df = df_time.groupby(['Hour', display_group_col]).size().reset_index(name='Count')
                                
                                # ヒートマップのY軸を「曜日」ではなく「選択したカテゴリ」に変更
                                heatmap_df = df_time.groupby(['Hour', display_group_col]).size().reset_index(name='Count')

                                # 時間分析の各チャートにも color_scheme (選択したパレット) を適用
                                chart_daily = alt.Chart(daily_df).mark_line(point=True).encode(
                                    # X軸に tickCount='day' と labelAngle=-45 等を追加
                                    x=alt.X('Date:T', title='日付', axis=alt.Axis(format='%m/%d', tickCount='day', labelAngle=-45, labelOverlap=True)),
                                    y=alt.Y('Count:Q', title='件数', axis=alt.Axis(tickMinStep=1, format='d')),
                                    color=alt.Color(f'{display_group_col}:N', title=display_group_col, scale=alt.Scale(scheme=color_scheme), legend=alt.Legend(orient='right')),
                                    tooltip=[alt.Tooltip('Date:T', title='日付', format='%Y/%m/%d'), f'{display_group_col}:N', 'Count:Q']
                                ).properties(title=f'日次推移 ({display_group_col}別)')
                                
                                chart_monthly = alt.Chart(monthly_df).mark_bar().encode(
                                    x=alt.X('Month:N', title='月'),
                                    y=alt.Y('Count:Q', title='件数', axis=alt.Axis(tickMinStep=1, format='d')),
                                    color=alt.Color(f'{display_group_col}:N', title=display_group_col, scale=alt.Scale(scheme=color_scheme), legend=alt.Legend(orient='right')),
                                    tooltip=['Month:N', f'{display_group_col}:N', 'Count:Q']
                                ).properties(title=f'月次傾向 ({display_group_col}別)')
                                    
                                chart_weekday = alt.Chart(weekday_df).mark_bar().encode(
                                    x=alt.X('Weekday:N', sort=weekday_order, title='曜日'),
                                    y=alt.Y('Count:Q', title='件数', axis=alt.Axis(tickMinStep=1, format='d')),
                                    color=alt.Color(f'{display_group_col}:N', title=display_group_col, scale=alt.Scale(scheme=color_scheme), legend=alt.Legend(orient='right')),
                                    tooltip=['Weekday:N', f'{display_group_col}:N', 'Count:Q']
                                ).properties(title=f'曜日別傾向 ({display_group_col}別)')
                                    
                                chart_hour = alt.Chart(hour_full_df).mark_bar().encode(
                                    x=alt.X('Hour:O', title='時刻 (時)'),
                                    y=alt.Y('Count:Q', title='件数', axis=alt.Axis(tickMinStep=1, format='d')),
                                    color=alt.Color(f'{display_group_col}:N', title=display_group_col, scale=alt.Scale(scheme=color_scheme), legend=alt.Legend(orient='right')),
                                    tooltip=['Hour:O', f'{display_group_col}:N', 'Count:Q']
                                ).properties(title=f'時間帯別傾向 ({display_group_col}別)')
                                
                                chart_heatmap_base = alt.Chart(heatmap_df).mark_rect().encode(
                                    x=alt.X('Hour:O', title='時刻 (時)'),
                                    y=alt.Y(f'{display_group_col}:N', title=display_group_col),
                                    color=alt.Color('Count:Q', scale=alt.Scale(scheme='yelloworangered'), title='件数'),
                                    tooltip=[f'{display_group_col}:N', 'Hour:O', 'Count:Q']
                                ).properties(title=f'時間帯 × {display_group_col} ヒートマップ')

                            # ヒートマップ数値テキスト (共通)
                            text_heatmap = chart_heatmap_base.mark_text(baseline='middle').encode(
                                text='Count:Q',
                                color=alt.condition(
                                    alt.datum.Count > heatmap_df['Count'].max() / 2,
                                    alt.value('white'),
                                    alt.value('black')
                                )
                            )
                            chart_heatmap = chart_heatmap_base + text_heatmap

                            # ----------------------------------------------------
                            # タブによる表示切り替え (ブラウザ閲覧用 vs 画像出力用)
                            # ----------------------------------------------------
                            tab_t1, tab_t2 = st.tabs(["🖥️ ブラウザ閲覧用", "🖼️ 画像出力用"])
                            
                            dynamic_group_col = time_group_col if time_group_col == '(なし)' else display_group_col
                            
                            with tab_t1:
                                st.altair_chart(chart_daily.properties(height=250), width="stretch")
                                
                                c_time1, c_time2 = st.columns(2)
                                with c_time1:
                                    st.altair_chart(chart_monthly.properties(height=250), width="stretch")
                                with c_time2:
                                    st.altair_chart(chart_weekday.properties(height=250), width="stretch")
                                    
                                st.altair_chart(chart_hour.properties(height=250), width="stretch")
                                
                                # ヒートマップはY軸のカテゴリが多い場合に潰れないよう、高さを動的に拡張
                                dynamic_height = 300 if time_group_col == '(なし)' else max(300, len(heatmap_df[dynamic_group_col].unique()) * 20)
                                st.altair_chart(chart_heatmap.properties(height=dynamic_height), width="stretch")
                                
                            with tab_t2:
                                st.info("💡 **Tips:** 下のチャートの右上にある `...` ボタンから **「Save as PNG」** を選択すると、それぞれのブロックごとに白背景の画像が保存できます。")
                                
                                # 画像出力用は各グラフのサイズをピクセルで固定化する
                                c_daily_img = chart_daily.properties(width=800, height=250)
                                c_monthly_img = chart_monthly.properties(width=365, height=250)
                                c_weekday_img = chart_weekday.properties(width=365, height=250)
                                c_hour_img = chart_hour.properties(width=800, height=250)
                                
                                # ブラウザの描画クラッシュを防ぐため、ヒートマップの高さに上限(1500px)を設ける
                                MAX_HEATMAP_HEIGHT = 1500
                                unique_items_count = len(heatmap_df[dynamic_group_col].unique()) if time_group_col != '(なし)' else 0
                                calculated_height = max(300, unique_items_count * 20)
                                dynamic_height_img = 300 if time_group_col == '(なし)' else min(calculated_height, MAX_HEATMAP_HEIGHT)
                                
                                c_heatmap_img = chart_heatmap.properties(width=800, height=dynamic_height_img)
                                
                                # --- 分割出力 1: 傾向分析 (日次・月次・曜日) ---
                                st.markdown("**■ 傾向分析 (日次・月次・曜日)**")
                                chart_part1 = alt.vconcat(
                                    c_daily_img,
                                    alt.hconcat(c_monthly_img, c_weekday_img)
                                ).resolve_legend(
                                    color='independent'
                                ).configure(
                                    background='white',
                                    padding={'left': 30, 'top': 20, 'right': 30, 'bottom': 20} 
                                ).configure_view(
                                    strokeWidth=0
                                ).configure_title(
                                    fontSize=16, anchor='middle', offset=15, color="black", fontWeight="bold"
                                ).configure_axis(
                                    labelColor='black', titleColor='black', gridColor='#e5e5e5', domainColor='black'
                                ).configure_legend(
                                    labelColor='black', titleColor='black'
                                )
                                st.altair_chart(chart_part1, use_container_width=False)
                                
                                st.markdown("<br><br>", unsafe_allow_html=True)
                                
                                # --- 分割出力 2: 時間帯分析 (時間・ヒートマップ) ---
                                st.markdown("**■ 時間帯分析 (時間・ヒートマップ)**")
                                chart_part2 = alt.vconcat(
                                    c_hour_img,
                                    c_heatmap_img
                                ).resolve_legend(
                                    color='independent'
                                ).configure(
                                    background='white',
                                    padding={'left': 30, 'top': 20, 'right': 30, 'bottom': 20} 
                                ).configure_view(
                                    strokeWidth=0
                                ).configure_title(
                                    fontSize=16, anchor='middle', offset=15, color="black", fontWeight="bold"
                                ).configure_axis(
                                    labelColor='black', titleColor='black', gridColor='#e5e5e5', domainColor='black'
                                ).configure_legend(
                                    labelColor='black', titleColor='black'
                                )
                                st.altair_chart(chart_part2, use_container_width=False)
                                
                    except Exception as e:
                        st.error(f"日時の解析中にエラーが発生しました: {e}")
                        
    with tab_spider:
        render_spider_web_analysis(df_merged)

# ==========================================
# 状態管理（Session State）用ヘルパー関数
# ==========================================
def init_session_state():
    """ アプリケーション起動時・リセット時に必要なSession Stateを初期化する """
    default_states = {
        'cancel_search': False,
        'raw_results': [],
        'targets_cache': [],
        'is_searching': False,
        'deferred_ips': {},
        'finished_ips': set(),
        'search_start_time': 0.0,
        'target_freq_map': {},
        'cidr_cache': {},
        'debug_summary': {},
        'detailed_data': {},
        'learned_proxy_isps': {}
    }
    
    for key, default_value in default_states.items():
        if key not in st.session_state:
            st.session_state[key] = default_value

def reset_search_state():
    """ 新規検索を開始する際に、前回の巨大なデータを明示的にメモリから解放する """
    # 巨大なリストや辞書を削除してガベージコレクションを促す
    if 'detailed_data' in st.session_state:
        st.session_state['detailed_data'].clear()
    if 'raw_results' in st.session_state:
        st.session_state['raw_results'].clear()
        
    st.session_state.is_searching = True
    st.session_state.cancel_search = False
    st.session_state.deferred_ips = {}
    st.session_state.finished_ips = set()
    st.session_state.search_start_time = time.time()
    clear_recovery_data()


# --- メイン処理 ---
def main():
    # 状態管理の初期化関数を呼び出し
    init_session_state()

    # リカバリUI
    if not IS_PUBLIC_MODE and os.path.exists(BACKUP_FILE) and not st.session_state.is_searching and not st.session_state.raw_results:
        st.warning("⚠️ 前回中断された検索セッションが残っています。")
        col_rec1, col_rec2 = st.columns(2)
        with col_rec1:
            if st.button("🔄 検索を途中から再開する", type="primary"):
                if load_recovery_data():
                    st.rerun()
        with col_rec2:
            if st.button("🗑️ バックアップを破棄する"):
                clear_recovery_data()
                st.rerun()

    tor_nodes = fetch_tor_exit_nodes()
    threat_intel_list = fetch_threat_intel_list()
    proxy_intel_list = fetch_proxy_intel_list()
    disposable_domains = fetch_disposable_domains()
    cloud_ip_data = fetch_cloud_ip_ranges()

    # 外部データベース取得エラー時の警告表示
    if not tor_nodes or not disposable_domains:
        st.warning("⚠️ **外部データベース取得エラー**: ネットワークの切断等により、Torノードリストまたは使い捨てメアドリストの取得に失敗しました。該当する検知機能が一時的に停止しています。")
    
    with st.sidebar:
        st.markdown("### 🛠️ Menu")
        selected_menu = option_menu(
            menu_title=None,
            options=["Whois検索", "仕様・解説"],
            icons=["search", "book"],
            default_index=0,
            styles={
                "nav-link": {"font-size": "16px", "text-align": "left", "margin": "5px", "--hover-color": "#eee"},
                "nav-link-selected": {"background-color": "#1e3a8a"},
            }
        )
        st.markdown("---")
        
        # --- Local Mode専用: 出力先設定 ---
        if not IS_PUBLIC_MODE:
            st.markdown("##### 📂 ローカル保存先設定")
            default_export_dir = os.path.join(os.getcwd(), "exports")
            st.session_state['local_export_dir'] = st.text_input("保存先フォルダの絶対パス", value=default_export_dir, help="ファイルの直接保存先を指定します。存在しない場合は自動作成されます。")
            st.markdown("---")
        
        # Proモード設定 (APIキー入力)
        with st.expander("🔑 APIキー設定 (Pro Mode)", expanded=False):
            st.caption("高精度な分析を行うためのAPIキーを設定します。")
        
            # 1. IPinfo (Pro Mode) の設定
            pro_api_key = ""
            if HARDCODED_IPINFO_KEY:
                use_hc_ipinfo = st.checkbox("埋め込みキー (IPinfo) を使用", value=True, help="オフにすると、埋め込まれたAPIキーを無効化し、空欄または手動入力モードに切り替えます。")
                if use_hc_ipinfo:
                    pro_api_key = HARDCODED_IPINFO_KEY
                    st.success(f"✅ IPinfo Key Loaded: {pro_api_key[:4]}***")
                else:
                    pro_api_key = st.text_input("ipinfo.io API Key", type="password", key="input_ipinfo", help="入力するとipinfo.ioの高精度データベースを使用します。空欄の場合はip-api.comを使用します。").strip()
            else:
                pro_api_key = st.text_input("ipinfo.io API Key", type="password", key="input_ipinfo", help="入力するとipinfo.ioの高精度データベースを使用します。空欄の場合はip-api.comを使用します。").strip()

            # 2. VPNAPI.io の設定
            vpnapi_key = ""
            if HARDCODED_VPNAPI_KEY:
                use_hc_vpnapi = st.checkbox("埋め込みキー (VPNAPI.io) を使用", value=True, help="オフにすると、埋め込まれたAPIキーを無効化し、空欄または手動入力モードに切り替えます。")
                if use_hc_vpnapi:
                    vpnapi_key = HARDCODED_VPNAPI_KEY
                    st.success(f"✅ VPNAPI Key Loaded: {vpnapi_key[:4]}***")
                else:
                    vpnapi_key = st.text_input("VPNAPI.io API Key", type="password", key="input_vpnapi", help="VPNAPI.ioのAPIキーを入力することで、IPアドレスの匿名通信判定を取得します。").strip()    
            else:
                vpnapi_key = st.text_input("VPNAPI.io API Key", type="password", key="input_vpnapi", help="VPNAPI.ioのAPIキーを入力することで、IPアドレスの匿名通信判定を取得します。").strip()

            # 3. SecurityTrails の設定
            st_api_key = ""
            if HARDCODED_SECURITYTRAILS_KEY:
                use_hc_st = st.checkbox("埋め込みキー (SecurityTrails) を使用", value=True, help="オフにすると、埋め込まれたAPIキーを無効化し、空欄または手動入力モードに切り替えます。")
                if use_hc_st:
                    st_api_key = HARDCODED_SECURITYTRAILS_KEY
                    st.success(f"✅ SecurityTrails Key Loaded: {st_api_key[:4]}***")
                else:
                    st_api_key = st.text_input("SecurityTrails API Key", type="password", key="input_st", help="FQDN（ドメイン）が入力された際、過去のA/AAAAレコードの履歴を取得するために使用します。").strip()
            else:
                st_api_key = st.text_input("SecurityTrails API Key", type="password", key="input_st", help="FQDN（ドメイン）が入力された際、過去のA/AAAAレコードの履歴を取得するために使用します。").strip()

            # 4. AlienVault OTX (Passive DNS) の設定
            otx_api_key = ""
            if HARDCODED_OTX_KEY:
                use_hc_otx = st.checkbox("埋め込みキー (AlienVault OTX) を使用", value=True, help="オフにすると、埋め込まれたAPIキーを無効化し、空欄または手動入力モードに切り替えます。")
                if use_hc_otx:
                    otx_api_key = HARDCODED_OTX_KEY
                    st.success(f"✅ AlienVault OTX Key Loaded: {otx_api_key[:4]}***")
                else:
                    otx_api_key = st.text_input("AlienVault OTX API Key", type="password", key="input_otx", help="Reverse IP (Passive DNS) を無制限に取得するために使用します。SecurityTrailsの無料枠枯渇対策に有効です。").strip()
            else:
                otx_api_key = st.text_input("AlienVault OTX API Key", type="password", key="input_otx", help="Reverse IP (Passive DNS) を無制限に取得するために使用します。SecurityTrailsの無料枠枯渇対策に有効です。").strip()

            st_start_date = None
            st_end_date = None
            if st_api_key:
                st.markdown("##### 📅 履歴取得期間 (SecurityTrails)")
                use_st_date_filter = st.checkbox("期間を指定して全件抽出する", value=False, help="チェックを入れると指定期間の履歴を制限なく抽出します。チェックがない場合は最新20件のみを取得します。")
            
                if use_st_date_filter:
                    # 本日の日付と、約3ヶ月前（90日前）の日付を動的に計算
                    today_date = datetime.date.today()
                    three_months_ago = today_date - datetime.timedelta(days=90)
                    
                    col_dt1, col_dt2 = st.columns(2)
                    with col_dt1:
                        st_start_date = st.date_input("開始日", three_months_ago, help="この日以降に観測された履歴のみを抽出します。期間が長い場合はレポート生成がスキップされる可能性があります。")
                    with col_dt2:
                        st_end_date = st.date_input("終了日", today_date, help="この日以前に観測された履歴のみを抽出します。")
                
                # Reverse IPの設定
                st.markdown("##### ⚙️ Reverse IP 追加設定")
                use_st_rev_fetchall = st.checkbox("Reverse IP 全件取得 (API消費大)", value=False, help="オンにすると、同一IPに紐づくドメインが100件を超える場合、APIを複数回消費して全件取得を試みます。CDNのIPなどを対象にするとクレジットが枯渇する恐れがあります。")
            else:
                use_st_rev_fetchall = False

        st.markdown("---")
        if st.button("🔄 システム/キャッシュを完全リセット", help="キャッシュが古くなった場合やメモリを解放したい場合にクリック"):
            # セッションステートを完全に削除してガベージコレクションを促す
            keys_to_delete = ['cidr_cache', 'detailed_data', 'raw_results', 'resolved_dns_map', 'original_df', 'original_input_list', 'targets_cache']
            for key in keys_to_delete:
                if key in st.session_state:
                    del st.session_state[key]
            
            st.cache_data.clear()
            st.cache_resource.clear()
            init_session_state() # 必要なキーを再構築
            
            st.info("IP/CIDRキャッシュ、検索履歴、およびメモリを完全にクリアしました。")
            time.sleep(1)
            st.rerun()

    

    if selected_menu == "仕様・解説":
        st.title("📖 マニュアル & ガイド")
        
        # タブで情報を整理して見やすくする
        tab1, tab2, tab3 = st.tabs(["🔰 使い方・モード選択", "⚙️ 仕様・技術詳細", "❓ FAQ"])

        with tab1:
            st.markdown("### 🚀 クイックスタート")
            
            if IS_PUBLIC_MODE:
                st.markdown("""
                1. **入力**: 左側の**テキストエリアにIPアドレスを貼り付ける**か、`.txt` ファイルをアップロードします。
                   > ⚠️ **注意**: 公開サーバー環境のため、Excel/CSVファイルのアップロードは制限されています。
                """)
            else:
                st.markdown("""
                1. **入力**: 左側のテキストエリアに貼り付けるか、**テキスト、CSV、Excelファイル**をアップロードします。
                   > ✅ **Local Mode**: ローカル環境で動作しているため、機密情報を含むファイルの処理も可能です。
                """)

            st.markdown("""
            2. **設定**: 基本的にはそのままでOKです。大量のデータを処理する場合や、より詳細な情報が必要な場合は、下部の設定を変更してください。
            3. **実行**: 「🚀 検索開始」ボタンを押します。
            """)
            
            st.info("💡 **ヒント**: 結果が出たあと、画面下のボタンからExcelファイルをダウンロードすると、自動でグラフ化された分析レポートが見れます。")

            st.markdown("---")
            st.markdown("### ⚙️ 設定項目の解説")
            
            st.markdown("#### 1. 表示モード (Display Mode)")
            st.markdown("検索結果をどのようにリストアップするかを選択します。")
            
            display_mode_df = pd.DataFrame({
                "モード名": ["標準モード", "集約モード", "簡易モード"],
                "API通信": ["あり (消費)", "あり (消費)", "なし (節約)"],
                "説明とメリット": [
                    "入力されたIPを1行ずつ表示します。個別の判定結果を詳しく確認したい場合に最適です。",
                    "同じISP・国で、連続するIPアドレスを1行にまとめます。（例: `1.1.1.1 - 1.1.1.5 (x5)`）。大量のログから「どこの会社からのアクセスが多いか」を概観するのに便利です。",
                    "API通信を行わず、調査用リンクの生成のみ行います。API制限にかかった場合や、外部へIPを送信したくない場合に利用します。"
                ]
            })
            st.table(display_mode_df.set_index("モード名"))

            st.markdown("#### 2. API処理モード (Processing Speed)")
            st.markdown("検索スピードと安定性のバランスを調整します。")
            
            api_mode_df = pd.DataFrame({
                "モード名": ["安定性重視", "速度優先"],
                "動作イメージ": ["🐢 ゆっくり・確実", "🚀 素早く・並列"],
                "説明": [
                    "待機時間を長め(2.5秒)に取り、1件ずつ処理します。APIのレートリミット（制限）にかかりにくく、エラーが出にくい安全運転設定です。",
                    "待機時間を短く(1.4秒)し、2つの処理を同時に走らせます。大量のリストを早く処理したい場合に推奨されますが、回線状況によっては制限にかかりやすくなります。"
                ]
            })
            st.table(api_mode_df.set_index("モード名"))

            st.markdown("#### 3. 詳細オプション")
            st.markdown("""
            - **🔍 公式レジストリ情報 (RDAP)**
                - `ip-api.com` (通常版） の情報に加え、各地域の**公式レジストリ(RDAP)** にも問い合わせを行います。
                - **メリット**: 「運用者(ISP)」だけでなく「法的な保有組織(Org)」まで特定できる確率が上がります。
            
            - **🔑 高精度判定 (ipinfo Key)**
                - **メリット**: VPN/Proxy/Hostingの判定精度が劇的に向上し、企業名の特定精度も高まります。
                - **注意**: データプランの種類（無料プラン、有料プラン）やAPIの利用状況に応じて、提供される情報の項目が異なり、無料版は、地理的位置情報やISP情報などの基本的なデータに限定されます。
                        
            - **🕵️ 匿名通信判定 (VPNAPI.io Key)**
                - **メリット**: VPN、Proxy、Tor等の利用が疑われる不審なIPに対し、VPNAPI.ioの専門データベースから「匿名通信該当結果」を自動取得します。

            - **📜 過去のDNS履歴取得 (SecurityTrails Key)**
                - **メリット**: ドメイン（FQDN）を入力した際、WAF（Cloudflare等）で秘匿される前の過去の生IP（オリジンサーバー）や、紐づいていたIPアドレスの変遷を取得できます。
                - **注意**: 月間50回までの無料枠が存在します。IPアドレス単体の検索では消費されません。
                        
            - **🔄 IP逆引き (Reverse DNS)**
                - **メリット**: IPアドレスに紐づくホスト名（PTRレコード）を取得します。プロバイダの特定や、サーバー用途の推測に役立ちます。
                - **動作仕様**: 精度と網羅性を優先するため、本オプション有効時は自動的に「シングルスレッド・待機延長モード」へ切り替わります。

            - **🔎 IoT Risk Check (InternetDB)**
                - **メリット**: ポート5555(ADB/FireStick)や1080(Proxy)等の露出を検知し、踏み台リスクを警告します（APIキー不要）。
            """)

            st.markdown("---")
            st.markdown("### 💻 動作モードとローカル版の導入")
            
            st.info("""
            このアプリは、実行環境（クラウドかローカルか）によって機能とセキュリティポリシーが変化します。
            機密性の高いデータ（顧客ログ等）を扱う場合や、大量のCSV/Excelを処理したい場合は、**Local版** の利用を強く推奨します。
            """)

            # モード比較表
            mode_compare_df = pd.DataFrame({
                "機能 / 特徴": ["Excel/CSV アップロード", "機密情報の取扱", "実行環境", "主な用途"],
                "☁️ Public Cloud版": ["❌ 不可 (.txtのみ)", "△ 推奨しない (共有サーバー)", "Streamlit Community Cloud", "手軽な単発検索・デモ利用"],
                "🏠 Local Private版": ["✅ 可能 ", "◎ 安全 (自PC内で完結)", "ローカルPC / 社内サーバー", "実務・ログ解析・大量処理"]
            })
            st.table(mode_compare_df.set_index("機能 / 特徴"))

            st.markdown("#### 📥 ローカル版 (Local Private Edition) の導入方法")
            st.markdown("Python環境があれば、どなたでも制限なしのローカル版を使用できます。ソースコードはGitHubで公開されています。")
            
            st.markdown("""
            **1. ソースコードの取得**
            以下のリポジトリからコードをダウンロード（Clone）してください。
            - 🔗 **GitHub Repository**: [github.com/x04z/WhoisApp](https://github.com/x04z/WhoisApp)
            
            **2. 必要なライブラリのインストール**
            ```bash
            pip install streamlit pandas requests streamlit-option-menu altair openpyxl dnspython duckdb aiohttp
            ```
            
            **3. アプリの起動**
            コマンドプロンプトまたはターミナルで以下を実行します。
            ```bash
            streamlit run WhoisAppxxxx.py
            ```
            """)
 
        with tab2:
            st.markdown("""
            #### 1. 情報収集基盤（データソース）
            - **IP Geolocation / 運用組織情報**: 
                - 標準照会: `ip-api.com` <span title="Artia International d.o.o.が提供。グローバルなBGP経路情報に基づき、自律システム(ASN)やISPのネットワーク構成をリアルタイムに解析する商用API。" style="cursor: help; color: #888;">ⓘ</span> (帯域制限適用・毎分45リクエスト)
                - 高精度照会: `ipinfo.io` <span title="米国IPinfo社が提供。大規模プローブ網とISPとの直接的データ共有により構築され、フォーチュン500企業や政府機関の監査基盤として広く採用される高精度インテリジェンス。" style="cursor: help; color: #888;">ⓘ</span> (認証トークンによる商用精度の位置・ASN情報取得)
            - **匿名通信・中継サーバー判定**: `VPNAPI.io` <span title="VPNAPI社が提供。商用データセンターのIPブロック、実世界のハニーポット観測等に基づく動的データを統合した特化型インテリジェンスであり、高い即応性を有します。" style="cursor: help; color: #888;">ⓘ</span> (動的API評価)、`IP2Location LITE` <span title="IP2Location社が提供するリスト。オープンプロキシ等の静的データに基づくローカルDB評価であり、網羅性に優れます。" style="cursor: help; color: #888;">ⓘ</span> / `FireHOL` <span title="FireHOLプロジェクトが収集・提供するリスト。サイバー攻撃に関連するIPアドレス等の静的データに基づくローカルDB評価です。" style="cursor: help; color: #888;">ⓘ</span> (静的ローカルDB評価)
            - **脅威インテリジェンス (C2/Botnet)**: `Abuse.ch Feodo Tracker` <span title="スイスの非営利セキュリティ研究機関「Abuse.ch」が運営。マルウェアのC2(コマンド＆コントロール)サーバーやボットネット基盤を追跡する権威ある脅威インテリジェンスであり、各国のCERTやセキュリティベンダーが標準フィードとして広く採用する極めて高い信頼性を誇ります。" style="cursor: help; color: #888;">ⓘ</span> (マルウェア通信先ノードリスト)
            - **DNSレコード履歴 (Passive DNS)**: `SecurityTrails` <span title="米Recorded Future社傘下のSecurityTrailsが提供。世界規模のDNSセンサーを基盤とし、DNSの変更履歴を蓄積・提供する、商用最高水準のフォレンジック・データソースです。" style="cursor: help; color: #888;">ⓘ</span>, `AlienVault OTX` <span title="米AT&T Cybersecurity社傘下のAlienVaultが提供。コミュニティ主導の脅威観測網を基盤とし、グローバルな侵害痕跡(IoC)を蓄積・提供するデータソースです。" style="cursor: help; color: #888;">ⓘ</span> (ドメインおよびIPの過去の運用履歴)
            - **DNS名前解決 (正引き/逆引き)**: `dnspython` <span title="RFC準拠の標準DNSプロトコル実装。OSのキャッシュやローカルネットワーク設定の介在を論理的に排除し、権威DNSサーバーから直接かつ客観的な応答を取得するための、透過的かつ改ざん耐性のある技術基盤として機能します。" style="cursor: help; color: #888;">ⓘ</span> (OS設定に依存しない権威サーバーへの直接照会)
            - **法的保有組織情報 (RDAP)**: APNIC等の各地域インターネットレジストリ (RIR) <span title="APNIC等の各RIR(地域インターネットレジストリ)は、国際的なIPアドレス空間の割り当ておよび管理を委譲された公式非営利組織です。RDAPプロトコルを通じ、これら公式機関が維持する真正な登録者台帳へ直接アクセスするため、法的・管理的な保有権限を特定する上で最も権威ある一次情報源となります。" style="cursor: help; color: #888;">ⓘ</span> が提供する公式台帳
            - **IoT / 脆弱性リスク評価**: `Shodan InternetDB` <span title="米国Shodan社が提供。インターネット上の全公開IPに対する継続的なポートスキャン結果を収集するグローバルインテリジェンス。対象IPで稼働するサービスや潜在的な脆弱性リスクを客観的に可視化する基盤として、公的機関やサイバー軍等のインシデント調査で標準的に活用されています。" style="cursor: help; color: #888;">ⓘ</span> (グローバルポートスキャン履歴に基づく踏み台リスク判定)
            - **Tor出口ノード情報**: Tor Project 公式ディレクトリアーカイブ <span title="米国501(c)(3)非営利組織であるThe Tor Project, Inc.が公式に提供するディレクトリ・アーカイブ。匿名化ネットワークの運用主体自身が定期的に公開する公式台帳情報であるため、Tor利用の有無を判定する上で完全な正確性と真正性が担保されています。" style="cursor: help; color: #888;">ⓘ</span>

            #### 2. 多角的解析アーキテクチャ（ハイブリッド処理方式）
            本システムは、大規模な通信ログに対して効率的かつ高精度なフォレンジック調査を実施するため、ローカル静的解析と外部動的API解析を統合した「ハイブリッド処理方式」を採用しています。

            - **第1段階：ローカルDBによる初期スクリーニング（静的解析）**
                - **機能概要**: 外部ネットワークへAPI照会を行う前に、システム内部に展開された数万件規模の脅威インテリジェンス（ボットネットC2等）および匿名化ノードリスト（IP2Location / FireHOL等）との高速突合処理を実行します。
                - **導入効果**: 既知の悪意ある通信基盤や公開プロキシ等の匿名化インフラをミリ秒単位で即時特定します。これにより調査対象のノイズや通信オーバーヘッドを排除し、外部APIのリクエスト許容枠（レートリミット）を極大化・温存します。
            
            - **第2段階：運用実態および法的権限の特定（動的解析）**
                - **実運用者判定 (Geolocation API)**: 対象IPアドレスが、現在どの自律システム (AS) や通信事業者のネットワーク下でルーティングされているか、技術的な「運用主体」を特定します。
                - **法的保有権限の特定 (RDAP)**: 地域インターネットレジストリの公式台帳へ直接照会し、IPアドレスブロックに対する法的な「割当先・管理責任組織」を特定します。これにより、実運用者と法的保有者の乖離関係（インフラの再販や間借り等）を客観的に浮き彫りにします。
                - **高度匿名化検証 (VPNAPI.io)**: 初期スクリーニングを通過したIPに対し、商用VPNやクラウドインフラ（Hosting）を利用した高度な秘匿通信に該当するか、専門APIによる最終検証を実施します。
            
            - **アーキテクチャの総合的優位性**
                - ローカルスクリーニングによる「自律的なノイズ遮断」と、動的APIによる「精緻な実態把握」をシームレスに結合。これにより、大規模ログ調査における処理遅延とランニングコストを最小化しつつ、公的機関や法務・セキュリティ部門への報告要求に耐えうる、客観的かつ追跡可能な証跡（フォレンジック・データ）の保全を高い水準で実現しています。

            #### 3. 技術的仕様
            - **非同期I/O処理アーキテクチャ**: `asyncio` および `aiohttp` を用いた完全非同期並行処理を実装し、I/Oバウンドな通信遅延を極小化。
            - **ローカルデータベースエンジン**: `DuckDB` を採用し、巨大なIPレンジデータのオンメモリ検索・照合を高速化。
            - **フェイルセーフ機構**: APIのレートリミット到達時の自動バックオフ（待機と再試行）機能、およびイベントループ競合回避処理を実装。
            """, unsafe_allow_html=True)
            st.markdown("#### 4. 判定ステータスの意味")
            
            st.error("🧅 **Tor Node**")
            st.markdown("Tor（The Onion Router）匿名化ネットワークの出口ノードです。発信元の完全な隠蔽を目的としており、攻撃の前兆や違法取引に関連する通信である可能性が高いです。")

            st.error("⚠️ **IoT露出 / 高リスクポート検知**")
            st.markdown("""
            Shodan InternetDBにより、以下の危険なポート開放が確認されたIPです。
            
            - **Telnet (23)**: 暗号化されていない古いプロトコル。**「開いているだけで高リスク」**とみなされます。
            - **ADB (5555/5554)**: Android端末（FireTVなど）のデバッグ機能が認証なしで公開されています。
            - **TR-069 (7547)**: ルーター管理用プロトコル。脆弱性がある場合、ルーターごと乗っ取られる恐れがあります。
            - **Proxy (1080/3128)**: 踏み台として悪用されるプロキシサーバー（SOCKS/Squid）が稼働しています。
            - **UPnP (1900)**: ネットワーク内の機器探索用プロトコルが外部に漏れています。
            """)

            st.warning("🍏 **iCloud Private Relay**")
            st.markdown("Appleデバイス（iPhone/Mac）のプライバシー保護機能による通信です。IPアドレスはAppleの提携パートナー（Cloudflare/Akamai等）のものに置き換わっており、真の発信元は隠蔽されていますが、基本的には一般ユーザーによるアクセスです。")

            st.warning("☁️ **Hosting/VPN/Proxy**")
            st.markdown("データセンター、商用VPN、プロキシ経由の通信です。一般家庭からのアクセスではなく、ボットや匿名化ツールを使用している可能性があります。")
            

        with tab3:
            # --- モード別案内: FAQ ---
            if IS_PUBLIC_MODE:
                st.markdown("""
                **Q. ファイルをアップロードしても大丈夫ですか？**\n
                A. 現在は **Public (Cloud) Mode** で動作しています。サーバーは共有環境のため、**機密情報を含むファイルのアップロードは推奨されません**。テキストエリアへのIP貼り付けを利用するか、個人情報を含まないデータのみを使用してください。
                """)
            else:
                st.markdown("""
                **Q. ファイルをアップロードしても大丈夫ですか？**\n
                A. はい。現在は **Local Mode** で動作しています。データはあなたのPC（またはプライベートサーバー）内で処理され、外部の開発者等に送信されることはありません。安心して機密データを取り扱えます。
                """)

            st.markdown("""
            **Q. 検索が途中で止まりました。**\n
            A. APIの制限（レートリミット）にかかった可能性があります。ツールは自動的に待機して再開しますが、大量（数千件）の検索を行う場合は時間がかかります。「待機中」の表示が出ている場合はそのままお待ちください。なお、通常版API（ip-api）は流量制限が厳しく、数十件程度のバーストで保留（Deferred）状態になることがあります。スムーズな解析が必要な場合は「Local版」の利用、または「Pro Mode (IPinfo)」の適用を検討してください。\n
                        
            **Q. 各種APIキーはどこで手に入りますか？**\n
            A. 本ツールで利用可能な高度判定用APIキーは、以下の公式サイトから無料で登録・取得できます（いずれも無料枠が存在します）。
            * **高精度判定 (ipinfo)**: [ipinfo.io サインアップ](https://ipinfo.io/signup)
            * **匿名通信判定 (VPNAPI.io)**: [VPNAPI.io サインアップ](https://vpnapi.io/signup)
            * **過去のDNS履歴取得 (SecurityTrails)**: [SecurityTrails サインアップ](https://securitytrails.com/app/signup)
            * **Reverse IP無制限取得 (AlienVault OTX)**: [AlienVault OTX サインアップ](https://otx.alienvault.com/)

            **Q. ISP名と [RDAP: 〇〇] の名前が違うのですが？**\n
            A. **それは「運用者」と「持ち主」の違いです。** 例えば `1.1.1.1` というIPアドレスの場合：
            * **ISP (API)**: `Cloudflare, Inc.` (DNSサービスを提供している運用者)
            * **RDAP (台帳)**: `APNIC-LABS` (IPアドレスブロックを保有している研究組織)
            このように表示されるのはバグではなく、公式レジストリ情報 (RDAP)が、**IPアドレスの「表の運用者」と「裏の保有者」の両方を正しく表している証拠**です。
            
            **Q. ISP名とRDAPの名前が異なる場合、発信者情報開示をどちらに請求すればいいでしょうか？**\n
            A. 個人（契約者）の情報を持っているのは**表の運用者である「ISP / プロバイダ」**の方です。RDAPの情報はあくまで「そのIPアドレスブロックを管理している組織」の情報であり、実際の利用者情報は持っていないことが多いです。発信者情報開示請求を行う場合は、**ISP名を使って手続きを行ってください**。

            **Q. IoT Risk判定が出ましたが、これは確定ですか？**\n
            A. いいえ。まず、本機能はリアルタイムのスキャンではなく、**「Shodanが過去に実施したポートスキャン結果（履歴）」**を参照しています。そのため、現在すでにポートが塞がれている可能性（または新たに開いている可能性）が常に存在します。また、一般回線の場合、そのIPを共有している**多数人の中の1人**が脆弱性を露出させているだけで、無関係な利用者の通信も同じIPとして判定されます。絶対的な証拠ではなく、あくまで「過去にリスクが確認されたノードである」という調査優先度の指標として扱ってください。
            
            **Q. 検知されるポートのリスク詳細を教えてください**\n
            A. 本ツールでは、以下のポート開放状況を監視しています。
                        
            * **⚠️ 23 (Telnet) / 21 (FTP)**
                * **判定**: **極めて危険な古いプロトコル** です。通信が暗号化されないため、パスワード等が盗聴されるリスクがあります。現代のインターネットで意図的に公開する正当な理由はほぼありません。
            
            * **🔥 1080 (SOCKS) / 3128 (Squid) / 8080 (HTTP)**
                * **判定**: **プロキシ (Proxy)** として悪用される典型的なポートです。一般家庭の回線でこれが開いている場合、意図しないプロキシ機能が植え付けられ、踏み台化している可能性が極めて高いです。
            
            * **💀 7547 (CWMP)**
                * **判定**: **ルーター乗っ取りの兆候** です。ISPが管理するためのポートですが、脆弱性がある場合、ルーターそのものがボット化され、「ネットワークの出口」全体が支配されている深刻な状態を示唆します。
            
            * **🤖 5555 / 5554 (ADB/Emu)**
                * **判定**: **Androidデバイスの露出** です。Fire TV StickやAndroid TV、開発用エミュレータなどが、認証なしで外部操作可能な状態で放置されています。
            
            * **📡 1900 (UPnP)**
                * **判定**: **ネットワーク機器の偵察拠点** です。これらが露出していると、攻撃者がネットワーク内の他のデバイスを探査するための入り口として利用されるリスクがあります。
            """)
        return

    # --- メインコンテンツ：Whois検索タブ ---   
    if IS_PUBLIC_MODE:
        mode_title = "☁️ Public Cloud Edition (機能制限あり)"
        mode_color = "gray"
    else:
        mode_title = "🏠 Local Private Edition (フル機能版)"
        mode_color = "green"

    st.title("🔎 検索大臣 - IP/Domain OSINT -")
    st.markdown(f"**Current Mode:** <span style='color:{mode_color}; font-weight:bold;'>{mode_title}</span>", unsafe_allow_html=True)
    # --- アップデート通知エリア  ---
    with st.expander("🍉アップデート情報 (令和8年7月18日) - ローカル脅威検知・最適化 🍉", expanded=False):
        st.markdown("""
        **Update:**\n
        **🛡️ ローカル脅威・匿名検知エンジンの追加**:
        * 外部APIに依存しない軽量な脅威インテリジェンス（Abuse.ch Feodo Tracker）およびプロキシリスト（FireHOL）をローカル実装しました。API消費なしでC2サーバーや悪意のあるプロキシを即座に特定可能です。\n
        **🌐 AlienVault OTX (Passive DNS) APIの実装**:
        * SecurityTrailsの厳しい無料枠（月50回）を回避するため、無制限にReverse IP検索が可能なAlienVault OTXに対応しました。\n
        **⚡ CDN調査用 WHOISスキップ機能**:
        * Reverse IP検索を実行する際、調査のノイズとなる不要なWHOIS取得（Cloudflare等）を検索前に遮断するトグルを追加し、処理速度を大幅に向上させました。\n
        **⚡ 非同期処理 (asyncio/aiohttp) の完全実装**:
        * 従来のマルチスレッド (`ThreadPoolExecutor`) と同期通信 (`requests`) を廃止し、非同期I/Oエンジンによるノンブロッキング通信へアーキテクチャを全面移行しました。\n
        **🚀 UIフリーズの解消と劇的な高速化**:
        * APIの通信待ち（特に応答の遅いRDAP等）の間も別のIPの処理を同時進行させることで、処理中の画面のフリーズ（固まり）を完全に排除し、大規模リストの処理速度が飛躍的に向上しました。\n
        **🛡️ 実行環境に依存しない安定性の確保**:
        * クラウド環境（Streamlit Community Cloud等）の特殊な仕様に起因する「イベントループの競合」を自動検知して回避するフェイルセーフを導入し、あらゆる環境での安定稼働を実現しました。
        """)
    # ------------------------------------------------
    # タブを使って入力モードを切り替え、画面を広く使う
    input_tab1, input_tab2, input_tab3 = st.tabs(["📋 テキスト貼り付け", "📂 ファイル読み込み", "🔍 単一検索 (WHOIS)"])

    with input_tab1:
        manual_input = st.text_area(
            "検索対象を入力 (複数行可: IPアドレス または ドメイン)",
            height=200, 
            placeholder="8.8.8.8\nexample.com\n2404:6800:...",
            help="1行に1つのターゲットを入力してください。"
        )

    with input_tab2:
        # --- モードによるアップロード制限の切り替え ---
        if IS_PUBLIC_MODE:
            # 公開モード (StreamlitCloud版の挙動): txtのみ許可、警告あり
            allowed_types = ['txt']
            label_text = "IPリストをアップロード (.txtのみ)"
            help_text = "※ 1行に1つのターゲットを記載"
        else:
            # ローカルモード (ローカル版の挙動): csv/excel許可
            allowed_types = ['txt', 'csv', 'xlsx', 'xls']
            label_text = "リストをアップロード (txt/csv/xlsx)"
            help_text = "※ 1行に1つのターゲットを記載、またはCSV/ExcelのIP列を自動検出します"

        uploaded_file = st.file_uploader(label_text, type=allowed_types)
        st.caption(help_text)
        
    with input_tab3:
        single_input = st.text_input(
            "単一の検索対象を入力 (IPアドレス または ドメイン)",
            placeholder="8.8.8.8 または example.com",
            help="1つのターゲットだけを素早く検索してレポートを生成します。"
        )

    raw_targets = []
    df_orig = None

    # 元のファイル名をセッションに保存（ダウンロード時のプレフィックス用）
    if uploaded_file:
        st.session_state['base_filename'] = os.path.splitext(uploaded_file.name)[0]
    else:
        st.session_state['base_filename'] = "WhoisSearchResult"

    if manual_input:
        raw_targets.extend(manual_input.splitlines())
        
    if single_input:
        raw_targets.append(single_input.strip())
    
    if uploaded_file:
        # --- 公開モードの場合の読み込み処理 (StreamlitCloud版ロジック) ---
        if IS_PUBLIC_MODE:
             try:
                # シンプルにテキストとして読み込む
                string_data = uploaded_file.read().decode("utf-8")
                raw_targets.extend(string_data.splitlines())
                
                # 元データフレーム機能は無効化
                st.session_state['original_df'] = None
                st.session_state['ip_column_name'] = None
                
                st.info(f"📄 テキスト読み込み完了: {len(raw_targets)} 行")

             except Exception as e:
                st.error(f"ファイル読み込みエラー: {e}")
        
        # --- ローカルモードの場合の読み込み処理  ---
        else:
            ip_col = None
            try:
                # 既にファイルが読み込まれ、セッションに保存されている場合は再読み込みをスキップ（タイムゾーン変換の維持のため）
                if st.session_state.get('uploaded_filename') == uploaded_file.name and st.session_state.get('original_df') is not None:
                    df_orig = st.session_state['original_df']
                else:
                    if uploaded_file.name.endswith('.csv'):
                        df_orig = pd.read_csv(uploaded_file)
                    elif uploaded_file.name.endswith(('.xlsx', '.xls')):
                        df_orig = pd.read_excel(uploaded_file)
                    else:
                        # TXTファイル
                        raw_targets.extend(uploaded_file.read().decode("utf-8").splitlines())
                        st.session_state['original_df'] = None
                        st.session_state['ip_column_name'] = None
                        df_orig = None
                    
                    st.session_state['uploaded_filename'] = uploaded_file.name
                    st.session_state['original_df'] = df_orig
                
                if df_orig is not None:
                    for col in df_orig.columns:
                        sample = df_orig[col].dropna().head(10).astype(str)
                        if any(is_valid_ip(val.strip()) for val in sample):
                            ip_col = col
                            break
                    
                    if ip_col:
                        st.session_state['ip_column_name'] = ip_col
                        raw_targets.extend(df_orig[ip_col].dropna().astype(str).tolist())
                        
                        # 高度なタイムゾーン変換ロジック (日本名＋Code名表示対応) ---
                        # 画面表示用(日本名+Code名)と内部処理用(IANA名)のマッピング
                        TZ_DISPLAY_MAPPING = {
                            "協定世界時 (UTC)": "UTC",
                            "日本標準時 (JST)": "Asia/Tokyo",
                            "米国太平洋標準時 (PST/PDT)": "US/Pacific",
                            "米国東部標準時 (EST/EDT)": "US/Eastern",
                            "米国中部標準時 (CST/CDT)": "US/Central",
                            "英国標準時 (GMT/BST)": "Europe/London",
                            "中央ヨーロッパ時間 (CET/CEST)": "Europe/Berlin",
                            "中国標準時 (CST)": "Asia/Shanghai",
                            "シンガポール標準時 (SGT)": "Asia/Singapore",
                            "豪州東部標準時 (AEST/AEDT)": "Australia/Sydney"
                        }

                        def convert_tz_smartly_advanced(df, time_col, dest_col, source_tz_type, dest_tz_type):
                        # 変換元の情報を保存（変換のトレーサビリティを確保）
                            df[f"{dest_col}_Original"] = df[time_col]
                    
                            # さまざまな時刻表記（yyyy/mm/dd h:m:sなど）や混在フォーマットに対応するためのパース処理
                            try:
                                # Pandas 2.0以降の推奨オプション（mixed指定による複数フォーマット解析）
                                converted_time = pd.to_datetime(df[time_col], errors='coerce', utc=False, format='mixed')
                            except ValueError:
                                # Pandas 1.x系へのフォールバック処理
                                converted_time = pd.to_datetime(df[time_col], errors='coerce', utc=False, infer_datetime_format=True)

                            def apply_tz_logic(dt_val, src_tz, dst_tz):
                                if pd.isna(dt_val): return dt_val, "N/A", "N/A"
                                
                                # タイムゾーン情報を持たない場合(Naive)、指定の元のタイムゾーンとみなす
                                if dt_val.tzinfo is None:
                                    # 存在しない時間などは shift_forward でエラー回避
                                    dt_aware = dt_val.tz_localize(src_tz, ambiguous='NaT', nonexistent='shift_forward')
                                else:
                                    # 既に情報がある場合は元のタイムゾーンを上書き(指定を優先)
                                    dt_aware = dt_val.tz_convert(src_tz)
                                
                                # 変換先のタイムゾーンへ変換
                                dest_dt = dt_aware.tz_convert(dst_tz)
                                
                                # 壁時計時間（ローカル時刻）同士の差分をとることで、何時間加減算されたかを計算
                                offset = (dest_dt.tz_localize(None) - dt_aware.tz_localize(None)).total_seconds() / 3600
                                offset_str = f"{offset:+.1f}h"
                                
                                # dt_aware.tzname() により、その時刻が夏時間か冬時間かを自動判定してPST/PDT等の正確な略称を取得
                                src_name = dt_aware.tzname()
                                dst_name = dest_dt.tzname()
                                tz_info_str = f"{src_name} -> {dst_name} ({offset_str})"
                                
                                return dest_dt.tz_localize(None), offset_str, tz_info_str
                        
                            # 結果をマッピング
                            results = [apply_tz_logic(x, source_tz_type, dest_tz_type) for x in converted_time]
                            df[dest_col] = [r[0] for r in results]
                            df[f"{dest_col}_Offset"] = [r[1] for r in results]
                            df[f"{dest_col}_TZ"] = [r[2] for r in results]
                            
                            return df

                        # --- アップロードデータのプレビュー (空枠の作成) ---
                        st.info(f"📄 ファイル読み込み完了: {len(df_orig)} 行 / IP列: `{ip_col}`")
                        
                        # 【新機能】ローカル版専用：タイムゾーン変換UI
                        st.markdown("### 🕒 タイムゾーン変換 (ローカル専用)")
                        st.caption("対象列の時間を指定のタイムゾーンへ変換し上書きします。変換履歴(元値, Offset, 変換経路)が自動で列追加されます。")

                        with st.container():
                            col_tz1, col_tz2, col_tz3, col_tz4 = st.columns(4)
                            tz_display_options = list(TZ_DISPLAY_MAPPING.keys())
                            
                            with col_tz1:
                                src_col = st.selectbox("変換元の列:", list(df_orig.columns), key="tz_src")
                            with col_tz2:
                                dest_col = st.text_input("変換後の列名:", value=f"{src_col}_Conv", key="tz_dest")
                            with col_tz3:
                                source_tz_disp = st.selectbox("元のTZ:", tz_display_options, index=2, key="tz_source") # デフォルト: 米国太平洋標準時
                            with col_tz4:
                                dest_tz_disp = st.selectbox("変換先のTZ:", tz_display_options, index=1, key="tz_dest_tz") # デフォルト: 日本標準時
                                
                            if st.button("🔄 変換実行", width="stretch"):
                                if src_col:
                                    # 表示名から内部処理用のIANA名を取得
                                    actual_source_tz = TZ_DISPLAY_MAPPING.get(source_tz_disp, "UTC")
                                    actual_dest_tz = TZ_DISPLAY_MAPPING.get(dest_tz_disp, "UTC")
                                    
                                    with st.spinner("タイムゾーンを変換中..."):
                                        st.session_state['original_df'] = convert_tz_smartly_advanced(
                                            st.session_state['original_df'].copy(), src_col, dest_col, actual_source_tz, actual_dest_tz
                                        )
                                    st.success(f"変換完了！ '{dest_col}' 列を追加しました。")
                                    time.sleep(1)
                                    st.rerun() 
                                    
                        # --- API調査前のデータクレンジング結果のエクスポート ---
                        if st.session_state.get('original_df') is not None:
                            with st.expander("💾 現在のデータを保存 (API実行前)", expanded=False):
                                st.caption("タイムゾーン変換などを適用した状態のデータを、API調査を実施する前にExcelとして保存します。")
                                tmp_df = st.session_state['original_df']
                                ts_export = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                                base_filename = st.session_state.get('base_filename', 'LogData')
                                export_fname = f"{base_filename}_PreAPI_{ts_export}.xlsx"
                                
                                col_dl1, col_dl2 = st.columns(2)
                                with col_dl1:
                                    excel_bytes = convert_df_to_excel(tmp_df)
                                    st.download_button(
                                        label="📥 Excel形式でダウンロード",
                                        data=excel_bytes,
                                        file_name=export_fname,
                                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                        width="stretch"
                                    )
                                with col_dl2:
                                    # ローカルモードの場合のみ、直接保存UIを表示
                                    if not IS_PUBLIC_MODE:
                                        render_local_save_ui(
                                            "📁 ローカルに直接保存",
                                            export_fname,
                                            excel_bytes,
                                            "export_preapi_excel",
                                            "secondary"
                                        )

                        with st.expander("👀 アップロードデータ・プレビュー", expanded=False):
                            preview_container = st.empty() 

                        # ---------------------------------------------
                    else:
                        st.error("ファイル内にIPアドレスの列が見つかりませんでした。")

            except Exception as e:
                st.error(f"ファイル読み込みエラー: {e}")
    
    cleaned_raw_targets_list = []
    target_freq_counts = {}

    # 生データからすべての空白文字（半角・全角スペース、タブ等）を完全に除去し、空行を排除する
    raw_targets = [re.sub(r'\s+', '', t) for t in raw_targets if t.strip()]

    if raw_targets:
        cleaned_raw_targets_list = [clean_ocr_error_chars(t) for t in raw_targets]
        target_freq_counts = pd.Series(cleaned_raw_targets_list).value_counts().to_dict()
    else:
        target_freq_counts = {}

    targets = []
    invalid_targets_skipped = [] # 無効としてスキップされたターゲットを記録
    private_targets_skipped = [] # ボゴンIP(プライベートIP等)としてスキップされたターゲットを記録
    ocr_error_chars = set('Iil|OoSsAaBⅡ')
    resolved_dns_map = {} # nslookupの生出力保存用辞書

    def resolve_domain_nslookup(domain):
    
        ips = []
        raw_lines = []
    
        try:
            # システムのリゾルバに依存せず、Google/CloudflareのパブリックDNSを明示的に使用
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = random.sample(PUBLIC_DNS_SERVERS, 2) + random.sample(PUBLIC_DNS_V6_SERVERS, 1)
            resolver.timeout = 3
            resolver.lifetime = 3

            raw_lines.append(f";; Domain: {domain}")
            raw_lines.append(f";; Resolver: {resolver.nameservers}")

            # --- Aレコード (IPv4) 取得 ---
            try:
                answers_v4 = resolver.resolve(domain, 'A')
                for rdata in answers_v4:
                    ip = rdata.to_text()
                    if ip not in ips:
                        ips.append(ip)
                    raw_lines.append(f"{domain}. \tIN \tA \t{ip}")
            except dns.resolver.NoAnswer:
                raw_lines.append(f";; IPv4 (A) record not found for {domain}")
            except dns.resolver.NXDOMAIN:
                raw_lines.append(f";; Domain {domain} does not exist (NXDOMAIN)")
                return [], "\n".join(raw_lines) # ドメインがないなら終了
            except Exception as e:
                raw_lines.append(f";; IPv4 Query Failed: {str(e)}")

            # --- AAAAレコード (IPv6) 取得 ---
            try:
                answers_v6 = resolver.resolve(domain, 'AAAA')
                for rdata in answers_v6:
                    ip = rdata.to_text()
                    if ip not in ips:
                        ips.append(ip)
                    raw_lines.append(f"{domain}. \tIN \tAAAA \t{ip}")
            except dns.resolver.NoAnswer:
                pass # IPv6がないのは一般的
            except Exception as e:
                raw_lines.append(f";; IPv6 Query Failed: {str(e)}")

            # --- MXレコード (Mail Exchange) 取得 ---
            try:
                # MXレコードは捨てアド特定の生命線であるため、専用の長いライフタイムを設定して取得を試みる
                resolver_mx = dns.resolver.Resolver(configure=False)
                resolver_mx.nameservers = random.sample(PUBLIC_DNS_SERVERS, 3)
                resolver_mx.timeout = 5
                resolver_mx.lifetime = 10
                
                answers_mx = resolver_mx.resolve(domain, 'MX')
                for rdata in answers_mx:
                    mx_target = rdata.exchange.to_text(omit_final_dot=True)
                    mx_pref = rdata.preference
                    raw_lines.append(f"{domain}. \tIN \tMX \t{mx_pref} {mx_target}")
            except dns.resolver.NoAnswer:
                raw_lines.append(f";; MX record not found for {domain}")
            except Exception as e:
                raw_lines.append(f";; MX Query Failed: {str(e)}")

        except Exception as e:
            raw_lines.append(f";; Critical DNS Error: {str(e)}")
    
        return ips, "\n".join(raw_lines)
    
    # フィルタリング用に元データをマップ化する（これを追加してください）
    orig_data_map = {}
    if st.session_state.get('original_df') is not None and st.session_state.get('ip_column_name'):
        ip_col = st.session_state['ip_column_name']
        for _, row in st.session_state['original_df'].iterrows():
            ip = str(row[ip_col]).strip()
            if ip not in orig_data_map:
                orig_data_map[ip] = []
            orig_data_map[ip].append(row.to_dict())

    for t in raw_targets:
        original_t = t
        is_ocr_error_likely = any(c in ocr_error_chars for c in original_t)
        if is_ocr_error_likely:
            cleaned_t = clean_ocr_error_chars(original_t)
            if is_valid_ip(cleaned_t):
                if is_bogon_ip(cleaned_t):
                    private_targets_skipped.append(cleaned_t)
                elif cleaned_t not in targets: 
                    targets.append(cleaned_t)
                continue
            t = original_t
        
        invalid_ip_chars = set('ghijklmnopqrstuvwxyz')
        has_hyphen = '-' in t
        has_strictly_domain_char = any(c in invalid_ip_chars for c in t.lower())
        is_likely_domain_or_host = has_hyphen or has_strictly_domain_char
    
        if is_valid_ip(t):
            if is_bogon_ip(t):
                private_targets_skipped.append(t)
            elif t not in targets: 
                targets.append(t)
        elif is_likely_domain_or_host:
            # ドメイン形式の厳格チェック
            if is_valid_domain(t):
                # DNS解決を入力時から削除し、単にドメインとしてキューに入れる
                if t not in targets: targets.append(t)
            else:
                invalid_targets_skipped.append(t) # 不正なドメインとして除外
        else:
            cleaned_t_final = clean_ocr_error_chars(t)
            if is_valid_ip(cleaned_t_final):
                if is_bogon_ip(cleaned_t_final):
                    private_targets_skipped.append(cleaned_t_final)
                elif cleaned_t_final not in targets: 
                    targets.append(cleaned_t_final)
            else:
                # クリーンアップ後もドメイン形式の厳格チェック
                if is_valid_domain(cleaned_t_final):
                    if cleaned_t_final not in targets: targets.append(cleaned_t_final)
                else:
                    invalid_targets_skipped.append(t) # 不正なドメインとして除外

    # スキップされたターゲットがあれば警告を表示
    if invalid_targets_skipped:
        st.warning(f"⚠️ 以下の入力は「IPアドレス」または「有効なドメイン形式 (例: example.com)」を満たしていないため、検索対象から除外されました: **{', '.join(list(set(invalid_targets_skipped)))}**")
        
    if private_targets_skipped:
        st.info(f"🛡️ 以下の入力は「ローカルIP / プライベートIP / 予約IP」のため、無駄なAPI通信を防止する目的で自動除外されました: **{', '.join(list(set(private_targets_skipped)))}**")

    # --- プレビュー表に判定結果を反映させる (NEW) ---
    if 'preview_container' in locals() and df_orig is not None and ip_col:
        preview_df = df_orig.copy()
        # 除外対象がある場合のみ判定列を追加する
        if invalid_targets_skipped or private_targets_skipped:
            invalid_set = set(invalid_targets_skipped)
            private_set = set(private_targets_skipped)
            def check_status(val):
                if pd.isna(val): return "➖ 空欄"
                val_str = str(val).strip()
                
                if val_str in invalid_set:
                    return "除外 (形式エラー)"
                if val_str in private_set:
                    return "除外 (ローカルIP)"
                    
                # クリーンアップされたIPがマッチするかも判定
                cleaned_val = clean_ocr_error_chars(val_str)
                if cleaned_val in private_set:
                    return "除外 (ローカルIP)"
                    
                return "✅ 検索対象"
            
            # データフレームの一番左 (インデックス0) に判定列を挿入
            preview_df.insert(0, '📝 判定結果', preview_df[ip_col].apply(check_status))
            
        # プレースホルダーにデータフレームを描画
        preview_container.dataframe(preview_df, width="stretch")

    has_new_targets = (targets != st.session_state.targets_cache)
    
    if has_new_targets or 'target_freq_map' not in st.session_state:
        st.session_state['target_freq_map'] = target_freq_counts
        st.session_state['original_input_list'] = cleaned_raw_targets_list
        if has_new_targets:
            st.session_state['resolved_dns_map'] = {} # 新規入力時はマップをリセットする

    # --- エンジン処理用の振り分け（ドメイン(IP)はIPとして処理させる） ---
    ip_targets = [t for t in targets if is_valid_ip(t)]
    domain_targets = [t for t in targets if not is_valid_ip(t)]

    # --- UI表示用の厳密なカウント & カテゴリ分け ---
    # 1. ドメインから解決されたIP (例: "domain.com (1.2.3.4)")
    count_resolved_ip = sum(1 for t in ip_targets if "(" in t and ")" in t)
    
    # 2. 直接入力されたIPv6
    count_direct_ipv6 = sum(1 for t in ip_targets if not is_ipv4(t) and "(" not in t)
    
    # 3. 直接入力されたIPv4 (全IPターゲット - 解決分 - IPv6)
    count_direct_ipv4 = len(ip_targets) - count_direct_ipv6 - count_resolved_ip
    
    # 4. 純粋なドメインターゲット
    count_domain = len(domain_targets)

    # 合計待機数
    count_pending = len(st.session_state.deferred_ips)

    # 設定エリアをExpanderに格納し、デフォルトで閉じておく
    with st.expander("⚙️ 検索表示・解析オプション (クリックして展開)", expanded=False):
        col_set1, col_set2 = st.columns(2)
        
        # UIの評価順序を制御するため、先に右カラム(col_set2)のチェックボックスを定義する
        with col_set2:
            st.markdown("**解析モード:** (追加の解析オプションを選択)")
            # InternetDBオプション
            use_internetdb_option = st.checkbox("IoTリスク検知 (InternetDBを利用)", value=False, help="Shodan InternetDBを利用して、対象IPの開放ポートや踏み台リスクを検知します。")
            # RDAPオプション
            use_rdap_option = st.checkbox("公式レジストリ情報 (RDAP公式台帳の併用 - 5秒待機)", value=False, help="RDAP(公式台帳)から最新のネットワーク名を取得します。アクセス制限を避けるため処理速度が強制的に低下します。")
            # 逆引き(rDNS)オプション
            use_rdns_option = st.checkbox("IP逆引き (Reverse DNS - dnspython)", value=False, help="対象IPアドレスに対してdnspythonを実行し、ホスト名(PTRレコード)を取得して詳細レポートに追加します。")
            # SecurityTrails Reverse IPオプション
            # Reverse IP (Passive DNS) オプション
            use_st_reverse_ip = st.checkbox(
                "Reverse IP (Passive DNS)", 
                value=False, 
                disabled=not (bool(st_api_key) or bool(otx_api_key)), 
                help="対象IPに紐づくドメイン群を逆検索します。AlienVault OTXのAPIキーがある場合は優先利用され、バルク制限を回避できます。"
            )

            skip_whois = False
            if use_st_reverse_ip:
                skip_whois = st.checkbox(
                    "IP属性検索(ISP/国等)をスキップ", 
                    value=False, 
                    help="オンにすると処理時間は短縮されますが、APIの連続アクセス制限にかかりやすくなります。オフのままWhois検索等の自然な通信ラグをクッションとして利用することを推奨します。"
                )

        with col_set1:
            display_mode = st.radio(
                "**表示モード:** (検索結果の表示形式とAPI使用有無を設定)",
                ("標準モード", "集約モード (IPv4 Group)", "簡易モード (APIなし)"),
                key="display_mode_radio",
                horizontal=False
            )
            st.markdown("---") 
            
            # RDAPまたはrDNSがオンの場合は、ユーザーに設定させずUI上で固定値を明示する
            if use_rdap_option:
                st.info("ℹ️ **RDAP有効時の制限**\n公式台帳のアクセス制限を回避するため、自動的に「単一スレッド / 5秒待機」に固定されます。速度を優先する場合は右側のチェックを外してください。")
                max_workers = 1
                delay_between_requests = 5.0
            elif use_rdns_option:
                st.info("ℹ️ **逆引き(rDNS)有効時の制限**\nDNSクエリの競合を防ぐため、自動的に「単一スレッド / 2秒待機」に固定されます。速度を優先する場合は右側のチェックを外してください。")
                max_workers = 1
                delay_between_requests = 2.0
            else:
                # 1. API 処理モードの選択
                api_mode_options = list(MODE_SETTINGS.keys()) + ["カスタム設定 (任意調整)"]
                api_mode_selection = st.radio(
                    "**API 処理モード:** (速度と安定性のトレードオフ)",
                    api_mode_options,
                    key="api_mode_radio",
                    horizontal=False
                )
                # 2. 変数の確定ロジック (KeyError 回避策)
                if api_mode_selection == "カスタム設定 (任意調整)":
                    st.markdown("---")
                    max_workers = st.slider("並列スレッド数 (同時処理数)", 1, 5, 2, help="数を増やすと速くなりますが、API制限にかかりやすくなります。")
                    delay_between_requests = st.slider("リクエスト間待機時間 (秒)", 0.1, 5.0, 1.5, 0.1, help="値を増やすほど安全ですが、検索に時間がかかります。")
                else:
                    selected_settings = MODE_SETTINGS[api_mode_selection]
                    max_workers = selected_settings["MAX_WORKERS"]
                    delay_between_requests = selected_settings["DELAY_BETWEEN_REQUESTS"]
            
            # 3. 共通定数の設定
            rate_limit_wait_seconds = RATE_LIMIT_WAIT_SECONDS

    mode_mapping = {
        "標準モード": "標準モード (1ターゲット = 1行)",
        "集約モード (IPv4 Group)": "集約モード (IPv4アドレスをISP/国別でグループ化)",
        "簡易モード (APIなし)": "簡易モード (APIなし - セキュリティリンクのみ)"
    }
    current_mode_full_text = mode_mapping[display_mode]

    is_currently_searching = st.session_state.is_searching and not st.session_state.cancel_search
    
    st.markdown("### 📋 実行前ステータス・確認事項")
    
    # --- 公開モード時のみセキュリティ警告を表示 ---
    if IS_PUBLIC_MODE:
        st.warning("""
        **🛡️ セキュリティ上の注意**
        * **テキスト入力推奨**: ファイルアップロードよりも、左側のテキストエリアへの**コピー＆ペースト**の方が、メタデータ（作成者情報など）が含まれないため安全です。
        * **ファイル名に注意**: アップロードする場合は、ファイル名に機密情報（例: `ClientA_Log.txt`）を含めず、`list.txt` などの無機質な名前を使用してください。
        """)

    status_msg = (
        f"**検索対象:** IPアドレス: {count_direct_ipv4}件(v4)・{count_direct_ipv6}件(v6) / "
        f"ドメイン: {count_domain} 件 (正引きIP: {count_resolved_ip}件) / "
        f"待機中: {count_pending}件 / **キャッシュ:** {len(st.session_state.cidr_cache)}件"
    )
    st.info(status_msg)
      
    # 3. 各種APIの精度・制限に関する警告文
    if not pro_api_key:
        st.warning("⚠️ **IPinfo Inactive:** 通常版API(ip-api)を使用するため、ISP判定結果が正確ではない可能性があります。")
    else:
        st.success("🔑 **IPinfo Pro Active:** 高精度なISP情報・地理位置を取得します。")

    if not vpnapi_key:
        st.warning("⚠️ **VPNAPI.io Inactive:** 未設定時はTorノードのみを検知し、それ以外のプロキシ/VPN判定は空欄となります。高精度な判定が必要な場合はAPIキーを設定してください。")
    else:
        st.success("🕵️ **VPNAPI.io Evidence Active:** 不審判定時に自動で匿名通信判定結果を取得します。")

    if not use_internetdb_option:
        st.caption("※ **IoT Check Inactive:** IoT/脆弱性リスク検知はスキップされます。")

    st.markdown("<br>", unsafe_allow_html=True) # ボタンとの間に少し余白を作る

    # 4. 実行ボタン
    is_currently_searching = st.session_state.is_searching and not st.session_state.cancel_search
    total_ip_targets_for_display = len(ip_targets) + len(st.session_state.deferred_ips)

    if is_currently_searching:
        if st.button("❌ 検索を中止する", type="secondary", width="stretch"):
            st.session_state.cancel_search = True
            st.session_state.is_searching = False
            st.session_state.deferred_ips = {}
            st.rerun()
    else:
        # ボタンのテキストを変更し、警告を読んだことを意識させる
        execute_search = st.button(
        "🚀 上記の確認事項を了承して検索を開始する",
        type="primary",
        width="stretch",
        disabled=(len(targets) == 0 and len(st.session_state.deferred_ips) == 0)
    )

    if ('execute_search' in locals() and execute_search and (has_new_targets or len(st.session_state.deferred_ips) > 0)) or is_currently_searching:
        
        if ('execute_search' in locals() and execute_search and has_new_targets and len(targets) > 0):
            # 新規検索時に古い巨大なデータを明示的に解放し、状態をリセットする
            reset_search_state()
            st.session_state.targets_cache = targets
            st.rerun() 
            
        elif is_currently_searching:
            targets = st.session_state.targets_cache
            domain_targets = [t for t in targets if not is_valid_ip(t)]

            st.subheader("⏳ 処理中...")
            
            # メインスレッドを占有しないよう、検索開始直後に専用スレッドで並列DNS解決を一括実行する
            unresolved_domains = [d for d in domain_targets if d not in st.session_state.get('resolved_dns_map', {})]
            if unresolved_domains:
                with st.spinner(f"⏳ {len(unresolved_domains)}件のドメインを並列で名前解決中... (並列数: {max_workers})"):
                    def resolve_and_map(domain):
                        ips, raw = resolve_domain_nslookup(domain)
                        return domain, ips, raw
                    
                    # DNSクエリ(UDP)によるルーターのNAT溢れを防ぐため、ユーザー設定のmax_workersに同期させる
                    with ThreadPoolExecutor(max_workers=max_workers) as dns_executor:
                        dns_results = list(dns_executor.map(resolve_and_map, unresolved_domains))
                        
                    for domain, ips, raw in dns_results:
                        st.session_state.resolved_dns_map[domain] = {'ips': ips, 'raw': raw}
                        for resolved_ip in ips:
                            combined_t = f"{domain} ({resolved_ip})"
                            if combined_t not in targets: 
                                targets.append(combined_t)
                    
                    # DNS解決済みのターゲットリストでキャッシュを最新状態に上書き
                    st.session_state.targets_cache = targets

            # DNS並列解決が完了した後、改めて全体のIPターゲットを抽出してキューに流す
            ip_targets = [t for t in targets if is_valid_ip(t)]
            total_targets = len(targets)
            total_ip_api_targets = len(ip_targets)
            
            ip_targets_to_process = [ip for ip in ip_targets if ip not in st.session_state.finished_ips]
            
            current_time = time.time()
            ready_to_retry_ips = []
            deferred_ips_new = {}
            for ip, defer_time in st.session_state.deferred_ips.items():
                if current_time >= defer_time:
                    ready_to_retry_ips.append(ip)
                else:
                    deferred_ips_new[ip] = defer_time
            
            st.session_state.deferred_ips = deferred_ips_new
            
            immediate_ip_queue_unique = []
            for ip in ip_targets_to_process:
                if ip not in st.session_state.deferred_ips and ip not in immediate_ip_queue_unique:
                    immediate_ip_queue_unique.append(ip)

            immediate_ip_queue = immediate_ip_queue_unique
            immediate_ip_queue.extend(ready_to_retry_ips)
            
            is_single_input = (len(cleaned_raw_targets_list) == 1)
            if "簡易" in current_mode_full_text:
                if not st.session_state.raw_results:
                    results_list = []
                    for t in targets:
                        results_list.append(get_simple_mode_details(t))
                    st.session_state.raw_results = results_list
                    st.session_state.finished_ips.update(targets)
                    st.session_state.is_searching = False
                    st.rerun()

            else:
                if not any(res['ISP'] == 'Domain/Host' for res in st.session_state.raw_results) and domain_targets:
                    for d in domain_targets:
                        dns_data = st.session_state.get('resolved_dns_map', {}).get(d, {})
                        ns_raw = dns_data.get('raw', '') if isinstance(dns_data, dict) else str(dns_data)
                        res_domain = get_domain_details(d, ns_raw, st_api_key, st_start_date, st_end_date, is_single_target=is_single_input, skip_whois=skip_whois)
                        
                        heavy_keys = ['RDAP_JSON', 'VPNAPI_JSON', 'IPINFO_JSON', 'DOMAIN_RDAP_JSON', 'ST_JSON', 'RDNS_DATA', 'ST_REVERSE_IP_JSON', 'DOMAIN_WHOIS_TEXT', 'IP_WHOIS_TEXT']
                        ip_val = res_domain['Target_IP']
                        st.session_state.detailed_data[ip_val] = {k: res_domain.pop(k) for k in heavy_keys if k in res_domain}
                        
                        st.session_state.raw_results.append(res_domain)
                    st.session_state.finished_ips.update(domain_targets)

                prog_bar_container = st.empty()
                status_text_container = st.empty()
                summary_container = st.empty() 

                if immediate_ip_queue:
                    cidr_cache_snapshot = st.session_state.cidr_cache.copy() 
                    learned_isps_snapshot = st.session_state.learned_proxy_isps.copy()
                    
                    # --- IPinfo バルク一括取得の実行 ---
                    bulk_ipinfo_cache_snapshot = {}
                    if pro_api_key and not skip_whois:
                        # 有効な実IPのみを抽出して重複排除
                        actual_ips_to_fetch = list(set([extract_actual_ip(ip) for ip in immediate_ip_queue if is_valid_ip(extract_actual_ip(ip))]))
                        if actual_ips_to_fetch:
                            with st.spinner(f"⏳ IPinfo Bulk APIで {len(actual_ips_to_fetch)} 件の基本情報を一括取得中..."):
                                bulk_ipinfo_cache_snapshot = fetch_ipinfo_bulk(actual_ips_to_fetch, pro_api_key)
                                
                    # --- 各種オプション有効時の動的負荷調整 (安全装置) ---
                    current_max_workers = max_workers
                    current_delay = delay_between_requests
                    
                    if use_rdap_option:
                        # RDAPエンドポイントの厳格なアクセス制限(429エラー)を回避するため強制保護
                        current_max_workers = 1
                        if current_delay < 5.0:
                            current_delay = 5.0
                        st.info("ℹ️ RDAP公式台帳のアクセス制限を回避するため、安全モード（シングルスレッド/最低5秒待機）で実行中...")
                    elif use_rdns_option:
                        # DNSクエリの競合とタイムアウトを防ぐため強制的にシングルスレッド化
                        current_max_workers = 1 
                        if current_delay < 2.0:
                            current_delay = 2.0
                        st.info("ℹ️ 逆引き精度向上のため、負荷調整モード（シングルスレッド/最低2秒待機）で実行中...")
                    elif use_st_reverse_ip:
                        # Reverse IP (OTX/ST) の過負荷による接続拒否・データ欠損を防ぐ
                        current_max_workers = 1
                        if current_delay < 5.0:
                            current_delay = 5.0
                        st.info("ℹ️ Reverse IP (Passive DNS) の接続安定化のため、負荷調整モード（シングルスレッド/最低5秒待機）で実行中...")

                    # --- asyncio / aiohttp を用いた非同期実行ラッパー関数 ---
                    import asyncio
                    import aiohttp

                    async def process_targets_async():
                        # 同時接続数の上限をセマフォで厳格に制御 (APIレートリミット対策)
                        sem = asyncio.Semaphore(current_max_workers)
                        connector = aiohttp.TCPConnector(limit=current_max_workers)
                        
                        # 【修正】WAF（Cloudflare等）によるボット判定・切断を防ぐための標準的なブラウザヘッダーを設定
                        headers = {
                            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                            "Accept": "application/json"
                        }
                        
                        # 非同期セッションの構築 (TCPコネクションの使い回しで高速化)
                        async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
                            tasks = []
                            for ip in immediate_ip_queue:
                                # 次のステップで作成する非同期関数をタスクとして登録
                                task = asyncio.create_task(
                                    get_ip_details_from_api_async(
                                        sem,
                                        session,
                                        ip, 
                                        cidr_cache_snapshot, 
                                        learned_isps_snapshot, 
                                        current_delay,
                                        rate_limit_wait_seconds,
                                        tor_nodes,
                                        cloud_ip_data,
                                        use_rdap_option,
                                        use_internetdb_option,
                                        use_rdns_option,
                                        use_st_reverse_ip,
                                        skip_whois,
                                        pro_api_key,
                                        vpnapi_key,
                                        st_api_key,
                                        otx_api_key,
                                        st_start_date,
                                        st_end_date,
                                        use_st_rev_fetchall,
                                        is_single_input,
                                        bulk_ipinfo_cache_snapshot,
                                        threat_intel_list=threat_intel_list,
                                        proxy_intel_list=proxy_intel_list
                                    )
                                )
                                tasks.append(task)

                            # UI更新用のタイマーと進捗カウンター初期化
                            last_ui_update_time = time.time()
                            last_backup_time = time.time()
                            completed_tasks_count = 0
                            total_tasks = len(tasks)

                            # 完了したタスクから順次結果を取得し、UIを更新する (as_completed)
                            for coro in asyncio.as_completed(tasks):
                                if st.session_state.cancel_search:
                                    # ユーザーによる中止フラグ検知時は、残りのタスクをキャンセルしてループを抜ける
                                    for t in tasks:
                                        if not t.done():
                                            t.cancel()
                                    break

                                try:
                                    res_tuple = await coro
                                    completed_tasks_count += 1
                                    
                                    res = res_tuple[0]
                                    new_cache_entry = res_tuple[1] if len(res_tuple) > 1 else None
                                    new_learned_isp = res_tuple[2] if len(res_tuple) > 2 else None
                                    ip = res['Target_IP']
                                    
                                    if new_cache_entry:
                                        st.session_state.cidr_cache.update(new_cache_entry)
                                    
                                    if new_learned_isp:
                                        st.session_state.learned_proxy_isps.update(new_learned_isp)
                                        
                                    if res.get('Status', '').startswith('Success'):
                                        heavy_keys = ['RDAP_JSON', 'VPNAPI_JSON', 'IPINFO_JSON', 'DOMAIN_RDAP_JSON', 'ST_JSON', 'RDNS_DATA', 'ST_REVERSE_IP_JSON', 'DOMAIN_WHOIS_TEXT', 'IP_WHOIS_TEXT']
                                        st.session_state.detailed_data[ip] = {k: res.pop(k) for k in heavy_keys if k in res}
                                        
                                        st.session_state.raw_results.append(res)
                                        st.session_state.finished_ips.add(ip)
                                    elif res.get('Defer_Until'):
                                        st.session_state.deferred_ips[ip] = res['Defer_Until']
                                    else:
                                        heavy_keys = ['RDAP_JSON', 'VPNAPI_JSON', 'IPINFO_JSON', 'DOMAIN_RDAP_JSON', 'ST_JSON', 'RDNS_DATA', 'ST_REVERSE_IP_JSON', 'DOMAIN_WHOIS_TEXT', 'IP_WHOIS_TEXT']
                                        st.session_state.detailed_data[ip] = {k: res.pop(k) for k in heavy_keys if k in res}
                                        
                                        st.session_state.raw_results.append(res)
                                        st.session_state.finished_ips.add(ip)

                                    current_time_for_ui = time.time()
                                    is_last_item = (completed_tasks_count == total_tasks) and not st.session_state.deferred_ips

                                    # 一定間隔、または最後のアイテムの処理時にUIを更新
                                    if total_ip_api_targets > 0 and (current_time_for_ui - last_ui_update_time > 1.5 or is_last_item):
                                        last_ui_update_time = current_time_for_ui
                                        
                                        processed_api_ips_count = len([i for i in st.session_state.finished_ips if is_valid_ip(i)])
                                        pct = int(processed_api_ips_count / total_ip_api_targets * 100)
                                        elapsed_time = time.time() - st.session_state.search_start_time
                                        eta_seconds = 0
                                        if processed_api_ips_count > 0:
                                            rate = processed_api_ips_count / elapsed_time
                                            remaining_count = total_ip_api_targets - processed_api_ips_count
                                            eta_seconds = math.ceil(remaining_count / rate)
                                        
                                        eta_display = "計算中..."
                                        if eta_seconds > 0:
                                            minutes = int(eta_seconds // 60)
                                            seconds = int(eta_seconds % 60)
                                            eta_display = f"{minutes:02d}分{seconds:02d}秒"
                                            
                                        prog_bar_container.progress(pct)
                                        status_text_container.info(f"**⏳ 処理中... ({pct}%)** | 完了: {processed_api_ips_count}/{total_ip_api_targets} | ⏸️ 保留: {len(st.session_state.deferred_ips)} | 📦 キャッシュ: {len(st.session_state.cidr_cache)} | ⏱️ 残り: {eta_display}")
                                        
                                        isp_df, country_df, freq_df, country_all_df, isp_full_df, country_full_df, freq_full_df, proxy_df = summarize_in_realtime(st.session_state.raw_results)
                                        
                                        with summary_container.container():
                                            draw_summary_content(isp_df, country_df, freq_df, country_all_df, proxy_df, "📊 リアルタイム分析") 
                                            
                                        # 10秒ごとにディスクへセッションをバックアップする
                                        if current_time_for_ui - last_backup_time > 10.0 or is_last_item:
                                            save_recovery_data()
                                            last_backup_time = current_time_for_ui

                                    # エラー/保留発生時に安全にループを抜ける処理
                                    if st.session_state.deferred_ips:
                                        for t in tasks:
                                            if not t.done():
                                                t.cancel()
                                        break
                                        
                                except Exception as e:
                                    import logging
                                    logging.error(f"Async loop error: {e}")

                    # Streamlitの同期ループ上で、非同期イベントループを起動して実行を待機
                    # (実行環境によって既にループが回っている場合のエラー回避ロジック)
                    try:
                        loop = asyncio.get_running_loop()
                    except RuntimeError:
                        loop = None

                    if loop and loop.is_running():
                        # 既にループが回っている場合は task として投入
                        future = asyncio.run_coroutine_threadsafe(process_targets_async(), loop)
                        future.result()
                    else:
                        # ループがない場合は標準のrun
                        asyncio.run(process_targets_async())
                    
                    # 完了時の最終UI更新
                    if total_ip_api_targets > 0 and not st.session_state.deferred_ips and not st.session_state.cancel_search:
                        processed_api_ips_count = len([ip for ip in st.session_state.finished_ips if is_valid_ip(ip)])
                        final_pct = int(processed_api_ips_count / total_ip_api_targets * 100)
                        with prog_bar_container:
                            st.progress(final_pct)
                        with status_text_container:
                            st.success(f"**✅ 処理完了 (100%)** | 完了: {processed_api_ips_count}/{total_ip_api_targets} | 📦 キャッシュ: {len(st.session_state.cidr_cache)}")
                        
                if len(st.session_state.finished_ips) == total_targets and not st.session_state.deferred_ips:
                    st.session_state.is_searching = False
                    clear_recovery_data() # 正常完了時はバックアップを消去
                    with status_text_container:
                        st.success("✅ 全ての検索タスクが完了しました。結果を展開します...")
                    time.sleep(1.0) # 高速処理時にUI描画(一覧ビュー等)の同期を安定化させるための待機時間
                    st.rerun()
                
                elif st.session_state.deferred_ips and not st.session_state.cancel_search:
                    next_retry_time = min(st.session_state.deferred_ips.values())
                    wait_time = max(1, int(next_retry_time - time.time()))
                    
                    prog_bar_container.empty()
                    status_text_container.empty()
                    st.warning(f"⚠️ **ネットワーク切断、またはAPI制限を検知しました。** 保留中の **{len(st.session_state.deferred_ips)}** 件のターゲットは通信回復を待ち、**{wait_time}** 秒後に自動で再試行されます。")
                    time.sleep(min(5, wait_time)) 
                    st.rerun()

                elif st.session_state.cancel_search:
                    prog_bar_container.empty()
                    status_text_container.empty()
                    st.warning("検索がユーザーによって中止されました。")
                    st.session_state.is_searching = False
                    st.rerun()


    # --- 結果表示 ---
    if st.session_state.raw_results or st.session_state.deferred_ips:
        res = st.session_state.raw_results
        
        if st.session_state.get('debug_summary'):
            with st.expander("🛠️ デバッグ情報 (集計データ確認用)", expanded=False):
                st.markdown("**API 処理モード設定**")
                st.write(f"MAX_WORKERS: {max_workers}")
                st.write(f"DELAY_BETWEEN_REQUESTS: {delay_between_requests}")
                st.markdown("---")
                st.json(st.session_state['debug_summary'].get('country_code_counts', {}))
                st.json(st.session_state['debug_summary'].get('country_all_df', []))
                st.markdown("---")
                st.json(st.session_state.get('cidr_cache', {}))

        
        successful_results = [r for r in res if r['Status'].startswith('Success') or r['Status'].startswith('Aggregated')]
        error_results = [r for r in res if not (r['Status'].startswith('Success') or r['Status'].startswith('Aggregated'))]
        
        for ip, defer_time in st.session_state.deferred_ips.items():
            status = f"Pending (Retry in {max(0, int(defer_time - time.time()))}s)"
            error_results.append({
                'Target_IP': ip, 'ISP': 'N/A', 'Country': 'N/A', 'CountryCode': 'N/A', 'RIR_Link': get_authoritative_rir_link(ip, 'N/A'),
                'Secondary_Security_Links': create_secondary_links(ip), 
                'Status': status
            })
        
        if "集約" in current_mode_full_text:
            display_res = group_results_by_isp(successful_results)
            display_res.extend(error_results)
        else:
            display_res = successful_results + error_results
            target_order = {ip: i for i, ip in enumerate(targets)}
            display_res.sort(key=lambda x: target_order.get(get_copy_target(x['Target_IP']), float('inf')))

        display_results(display_res, current_mode_full_text, display_mode, use_rdap_option, pro_api_key, vpnapi_key, st_api_key, use_rdns_option, use_st_reverse_ip)
        
        if not st.session_state.is_searching or st.session_state.cancel_search:
            isp_df, country_df, freq_df, country_all_df, isp_full_df, country_full_df, freq_full_df, proxy_df = summarize_in_realtime(st.session_state.raw_results)
            st.markdown("---")
            draw_summary_content(isp_df, country_df, freq_df, country_all_df, proxy_df, "✅ 集計結果")

            # --- 全入力順・全件ベースのデータフレーム構築 ---
            df_for_analysis = pd.DataFrame()
            
            # マッチング精度を高めるための多重キー辞書の構築
            result_lookup = {}
            for r in st.session_state.raw_results:
                target = r.get('Target_IP', '')
                actual = extract_actual_ip(target)
                result_lookup[target] = r
                if actual and actual != target:
                    result_lookup[actual] = r

            def get_result_info(raw_ip_str):
                if pd.isna(raw_ip_str): return {}
                val = str(raw_ip_str).strip()
                cleaned = clean_ocr_error_chars(val)
                actual = extract_actual_ip(cleaned)
                # 実IP、クリーンIP、生文字列の順で一致する結果を探す
                return result_lookup.get(actual) or result_lookup.get(cleaned) or result_lookup.get(val) or {}

            full_input_list = st.session_state.get('original_input_list', [])

            if full_input_list:
                if st.session_state.get('original_df') is not None:
                    # 元のアップロードデータ(CSV/Excel)が存在する場合、その行構造(時間など)を完全維持する
                    df_for_analysis = st.session_state['original_df'].copy()
                    ip_col = st.session_state['ip_column_name']
                    
                    df_for_analysis['Whois(元データ)'] = df_for_analysis[ip_col].map(lambda x: get_result_info(x).get('ISP_API_Raw', 'N/A'))
                    df_for_analysis['Whois(日本語名)'] = df_for_analysis[ip_col].map(lambda x: get_result_info(x).get('ISP_JP', 'N/A'))
                    df_for_analysis['RDAP(元データ)'] = df_for_analysis[ip_col].map(lambda x: get_result_info(x).get('RDAP_Name_Raw', 'N/A'))
                    df_for_analysis['RDAP(日本語名)'] = df_for_analysis[ip_col].map(lambda x: get_result_info(x).get('RDAP_JP', 'N/A'))
                    df_for_analysis['国名'] = df_for_analysis[ip_col].map(lambda x: get_result_info(x).get('Country_JP', 'N/A'))
                    df_for_analysis['プロキシ種別'] = df_for_analysis[ip_col].map(lambda x: get_result_info(x).get('Proxy_Type', ''))
                    df_for_analysis['IoTリスク'] = df_for_analysis[ip_col].map(lambda x: get_result_info(x).get('IoT_Risk', 'N/A'))
                    df_for_analysis['逆引き結果'] = df_for_analysis[ip_col].map(lambda x: get_result_info(x).get('RDNS_Hosts', ''))
                    df_for_analysis['Reverse IP'] = df_for_analysis[ip_col].map(lambda x: get_result_info(x).get('ST_Reverse_Hosts', ''))
                    df_for_analysis['ステータス'] = df_for_analysis[ip_col].map(lambda x: get_result_info(x).get('Status', 'N/A'))
                else:
                    # テキスト貼り付けの場合
                    temp_rows = []
                    for t in full_input_list:
                        info = get_result_info(t)
                        temp_rows.append({
                            '対象IP/Domain': t,
                            'Whois(元データ)': info.get('ISP_API_Raw', 'N/A'),
                            'Whois(日本語名)': info.get('ISP_JP', 'N/A'),
                            'RDAP(元データ)': info.get('RDAP_Name_Raw', 'N/A'),
                            'RDAP(日本語名)': info.get('RDAP_JP', 'N/A'),
                            '国名': info.get('Country_JP', 'N/A'),
                            'プロキシ種別': info.get('Proxy_Type', ''),
                            'IoTリスク': info.get('IoT_Risk', 'N/A'),
                            '逆引き結果': info.get('RDNS_Hosts', ''),
                            'Reverse IP': info.get('ST_Reverse_Hosts', ''),
                            'ステータス': info.get('Status', 'N/A')
                        })
                    df_for_analysis = pd.DataFrame(temp_rows)

            # マスターデータ（Excel/全件CSV用）から無効オプション列を削除
            if not df_for_analysis.empty:
                master_cols_to_drop = []
                if not use_rdap_option:
                    master_cols_to_drop.extend(['RDAP(元データ)', 'RDAP(日本語名)'])
                if not use_internetdb_option:
                    master_cols_to_drop.append('IoTリスク')
                if not use_rdns_option:
                    master_cols_to_drop.append('逆引き結果')
                if not use_st_reverse_ip:
                    master_cols_to_drop.append('Reverse IP')
                
                if master_cols_to_drop:
                    df_for_analysis = df_for_analysis.drop(columns=[c for c in master_cols_to_drop if c in df_for_analysis.columns], errors='ignore')

            # --- クロス分析 (画面表示) ---
            if not df_for_analysis.empty:
                st.markdown("---")
                # 出力用マスターデータを汚染しないよう、一時的なコピーを作成
                df_for_render = df_for_analysis.copy()
                if st.session_state.get('ip_column_name') and st.session_state['ip_column_name'] in df_for_render.columns:
                    df_for_render['Target_IP'] = df_for_render[st.session_state['ip_column_name']].astype(str)
                elif '対象IP/Domain' in df_for_render.columns:
                    df_for_render['Target_IP'] = df_for_render['対象IP/Domain'].astype(str)
                
                render_merged_analysis(df_for_render)

            # --- UI改善：ダウンロードセンター ---
            st.markdown("---")
            st.markdown("### 📥 レポート ＆ データ出力")
            
            base_fname = st.session_state.get('base_filename', 'WhoisSearchResult')
            ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            file_prefix = f"{base_fname}_{ts}"
            
            main_col1, main_col2 = st.columns(2)
            with main_col1:
                st.info("📊 **分析マスター (全入力順)**\n\nアップロードされた全行に基づき、ISP・RDAP・国別などの集計表とグラフを生成します。")
                if not df_for_analysis.empty:
                    time_cols = [c for c in df_for_analysis.columns if any(k in c.lower() for k in ['date', 'time', 'jst'])]
                    selected_time_col = None
                    if time_cols:
                        selected_time_col = st.selectbox("時間分析に使用する列:", df_for_analysis.columns, index=df_for_analysis.columns.get_loc(time_cols[0]), key="time_col_selector_final")
                    
                    with st.spinner("⏳ Excelレポートを生成中..."):
                        excel_advanced = create_advanced_excel(df_for_analysis, selected_time_col)
                    
                    excel_filename = f"{file_prefix}_MasterReport.xlsx"
                    if IS_PUBLIC_MODE:
                        st.download_button(
                            label="📥 Excelレポート (全入力順・グラフ付き) を保存",
                            data=excel_advanced,
                            file_name=excel_filename,
                            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                            width="stretch",
                            type="primary"
                        )
                    else:
                        render_local_save_ui(
                            "💾 Excelレポートをローカル保存 (容量無制限)", 
                            excel_filename, excel_advanced, "master_excel", "primary"
                        )
                else:
                    st.button("データなし", disabled=True, width="stretch")

            with main_col2:
                st.success("🌐 **全件グラフ HTMLレポート**\n\nブラウザで閲覧・印刷可能なグラフィカルな分析レポートです。")
                with st.spinner("⏳ HTMLレポートを生成中..."):
                    html_report = generate_full_report_html(isp_full_df, country_full_df, freq_full_df)
                
                html_summary_filename = f"{file_prefix}_Summary.html"
                if IS_PUBLIC_MODE:
                    st.download_button(
                        label="📥 HTMLレポート (閲覧・印刷用) を表示",
                        data=html_report,
                        file_name=html_summary_filename,
                        mime="text/html",
                        width="stretch"
                    )
                else:
                    render_local_save_ui(
                        "💾 HTMLレポートをローカル保存", 
                        html_summary_filename, html_report, "master_html", "secondary"
                    )

            with st.expander("🛠️ システム連携用・RAWデータ ＆ 脅威インテリジェンス出力"):
                st.caption("SIEM（セキュリティログ監視）への取り込みや、データベース連携に利用してください。")
                sub_tab1, sub_tab2, sub_tab3 = st.tabs(["📄 検索結果リスト (CSV/Excel)", "📈 統計・カウントデータ", "🛡️ STIX 2.1 (SOC/MISP連携用)"])
                
                with sub_tab1:
                    use_defang = st.checkbox("🛡️ IoC（侵害指標）の無害化（Defang）を適用する", value=False, help="出力されるIPアドレスやドメインの「.」を「[.]」に置換し、レポート共有時の誤クリックによるセキュリティ事故を防ぎます（SOC・CSIRT向け）。")
                    
                    c1, c2 = st.columns(2)
                    csv_display = pd.DataFrame(display_res).astype(str)
                    
                    # --- CSV出力の列名と並び順をマスターレポートと完全に統一する ---
                    desired_cols_map = {
                        'Target_IP': 'IPアドレス',
                        'ISP_API_Raw': 'Whois(元データ)',
                        'ISP_JP': 'Whois(日本語名)',
                        'RDAP_Name_Raw': 'RDAP(元データ)',
                        'RDAP_JP': 'RDAP(日本語名)',
                        'Country_JP': '国名', 
                        'Proxy_Type': 'プロキシ種別',
                        'IoT_Risk': 'IoTリスク',
                        'RDNS_Hosts': '逆引き結果',
                        'ST_Reverse_Hosts': 'Reverse IP',
                        'Status': 'ステータス'
                    }
                    
                    available_cols = [c for c in desired_cols_map.keys() if c in csv_display.columns]
                    csv_display = csv_display[available_cols]
                    csv_display = csv_display.rename(columns=desired_cols_map)
                    
                    display_cols_to_drop = []
                    if not use_rdap_option:
                        display_cols_to_drop.extend(['RDAP(元データ)', 'RDAP(日本語名)'])
                    if not use_internetdb_option:
                        display_cols_to_drop.append('IoTリスク')
                    if not use_rdns_option:
                        display_cols_to_drop.append('逆引き結果')
                    if not use_st_reverse_ip:
                        display_cols_to_drop.append('Reverse IP')
                        
                    if display_cols_to_drop:
                        csv_display = csv_display.drop(columns=[c for c in display_cols_to_drop if c in csv_display.columns], errors='ignore')

                    # --- Defang処理 (画面表示順データ) ---
                    if use_defang:
                        defang_cols = ['IPアドレス', '逆引き結果', 'Reverse IP']
                        for c in defang_cols:
                            if c in csv_display.columns:
                                # 対象文字列のドットとhttpをエスケープ
                                csv_display[c] = csv_display[c].apply(
                                    lambda x: str(x).replace('.', '[.]').replace('hxxp', 'http')  # ← 逆順
                                    if str(x) not in ['nan', 'None', '', 'N/A']
                                    else x
                                )

                    with c1:
                        st.markdown("**画面表示順 (現在の並び)**")
                        st.download_button("CSV形式", csv_display.to_csv(index=False).encode('utf-8-sig'), f"{file_prefix}_Display.csv", "text/csv", key="csv_display_btn", width="stretch")
                        st.download_button("Excel形式", convert_df_to_excel(csv_display), f"{file_prefix}_Display.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", key="excel_display_btn", width="stretch")
                    
                   # 元のアップロードデータ(時間や他カラムを含む)を完全に維持している df_for_analysis をそのまま出力に使用する
                    if not df_for_analysis.empty:
                        csv_full = df_for_analysis.astype(str)
                        
                        # --- Defang処理 (全データ) ---
                        if use_defang:
                            orig_ip_col = st.session_state.get('ip_column_name')
                            defang_cols_full = ['対象IP/Domain', '逆引き結果', 'Reverse IP']
                            if orig_ip_col and orig_ip_col in csv_full.columns:
                                defang_cols_full.append(orig_ip_col)
                                
                            for c in defang_cols_full:
                                if c in csv_full.columns:
                                    csv_full[c] = csv_full[c].apply(
                                        lambda x: str(x).replace('.', '[.]').replace('http', 'hxxp') if str(x) not in ['nan', 'None', '', 'N/A'] else x
                                    )
                    else:
                        csv_full = pd.DataFrame() # 空の場合のフォールバック
                        
                    with c2:
                        st.markdown("**全データ (入力した順番)**")
                        st.download_button("CSV形式", csv_full.to_csv(index=False).encode('utf-8-sig'), f"{file_prefix}_Full.csv", "text/csv", key="csv_full_btn", width="stretch")
                        st.download_button("Excel形式", convert_df_to_excel(csv_full), f"{file_prefix}_Full.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", key="excel_full_btn", width="stretch")

                with sub_tab2:
                    sc1, sc2, sc3 = st.columns(3)
                    with sc1:
                        st.download_button("🎯 ターゲット別件数 (CSV)", freq_full_df.to_csv(index=False).encode('utf-8-sig'), f"{file_prefix}_Freq.csv", "text/csv", key="btn_freq_csv", width="stretch")
                    with sc2:
                        st.download_button("🏢 ISP別件数 (CSV)", isp_full_df.to_csv(index=False).encode('utf-8-sig'), f"{file_prefix}_ISP.csv", "text/csv", key="btn_isp_csv", width="stretch")
                    with sc3:
                        st.download_button("🌍 国別件数 (CSV)", country_full_df.to_csv(index=False).encode('utf-8-sig'), f"{file_prefix}_Country.csv", "text/csv", key="btn_country_csv", width="stretch")

                with sub_tab3:
                    st.info("**STIX (Structured Threat Information Expression) 2.1 形式**\n\n調査結果を、世界標準の脅威インテリジェンス・フォーマット (JSON形式) で出力します。SIEMへのIoC（侵害指標）の取り込みや、MISPへのインポートにそのまま使用できます。")
                    
                    stix_data = generate_stix2_bundle(display_res)
                    stix_filename = f"{file_prefix}_STIX.json"
                    
                    if IS_PUBLIC_MODE:
                        st.download_button(
                            label="STIX 2.1 Bundle (JSON) をダウンロード",
                            data=stix_data.encode('utf-8'),
                            file_name=stix_filename,
                            mime="application/json",
                            width="stretch",
                            type="primary"
                        )
                    else:
                        render_local_save_ui(
                            "STIX 2.1 Bundle をローカル保存", 
                            stix_filename, stix_data.encode('utf-8'), "stix_json", "primary"
                        )
                
if __name__ == "__main__":
    main()

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
import altair as alt # 新しいグラフ描画のためにaltairをインポート
import json # GeoJSONの読み込みに使用

# ページ設定（必ず先頭に記述）
st.set_page_config(layout="wide", page_title="Whois Search Tool", page_icon="🌐")

# --- 設定：API通信と並行処理 ---
# ユーザーが選択可能なモードの設定値を定義
MODE_SETTINGS = {
    "安定性重視 (1.5秒待機/単一スレッド)": {
        "MAX_WORKERS": 1, 
        "DELAY_BETWEEN_REQUESTS": 1.5 # 1.5秒 (レートリミット回避の確実性を高める)
    },
    "速度優先 (1.4秒待機/2スレッド)": {
        "MAX_WORKERS": 2, 
        "DELAY_BETWEEN_REQUESTS": 1.4 # 1.4秒 (わずかに高速化しつつ、2スレッドで並列処理)
    }
}
# IP-APIのベースURLと固定レートリミット待機時間は定数として維持
IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,isp,query,message"
RATE_LIMIT_WAIT_SECONDS = 120 # レートリミット発生時の強制待機時間 (秒)
  
# --- RIR/RegistryのURL定義 (変更なし) ---
RIR_LINKS = {
    'RIPE': 'https://apps.db.ripe.net/db-web-ui/#/query?searchtext={ip}',
    'ARIN': 'https://search.arin.net/rdap/?query={ip}',
    'APNIC': 'https://wq.apnic.net/static/search.html',
    'JPNIC': 'https://www.nic.ad.jp/ja/whois/ja-gateway.html',
    'AFRINIC': 'https://www.afrinic.net/whois',
    'ICANN Whois': 'https://lookup.icann.org/',
}
# --- セカンダリツールリンクのベースURL定義 (変更なし) ---
SECONDARY_TOOL_BASE_LINKS = {
    'VirusTotal': 'https://www.virustotal.com/',
    'Whois.com': 'https://www.whois.com/',
    'Who.is': 'https://who.is/',
    'DomainSearch.jp': 'https://www.domainsearch.jp/',
    'Aguse': 'https://www.aguse.jp/',
    'IP2Proxy': 'https://www.ip2proxy.com/',
    'DNS Checker': 'https://dnschecker.org/',
    'DNSlytics': 'https://dnslytics.com/',
    'IP Location': 'https://iplocation.io/',
    'CP-WHOIS': 'https://doco.cph.jp/whoisweb.php',
    }

# --- RIR割り当てマップ (変更なし) ---
COUNTRY_CODE_TO_RIR = {
    'JP': 'JPNIC', 'CN': 'APNIC', 'AU': 'APNIC', 'KR': 'APNIC', 'IN': 'APNIC',
    'ID': 'APNIC', 'MY': 'APNIC', 'NZ': 'APNIC', 'SG': 'APNIC',
    'TH': 'APNIC', 'VN': 'APNIC', 'PH': 'APNIC', 'PK': 'APNIC', 
    'BD': 'APNIC', 'HK': 'APNIC', 'TW': 'APNIC', 'NP': 'APNIC', 'LK': 'APNIC',
    'MO': 'APNIC', 
    'US': 'ARIN', 'CA': 'ARIN',
    'ZA': 'AFRINIC', 'EG': 'AFRINIC', 'NG': 'AFRINIC',
    'KE': 'AFRINIC', 'DZ': 'AFRINIC', 'MA': 'AFRINIC', 'GH': 'AFRINIC', 
    'CM': 'AFRINIC', 'TN': 'AFRINIC', 'ET': 'AFRINIC', 'TZ': 'AFRINIC',
    'DE': 'RIPE', 'FR': 'RIPE', 'GB': 'RIPE', 'RU': 'RIPE',
    'NL': 'RIPE', 'IT': 'RIPE', 'ES': 'RIPE', 'PL': 'RIPE', 
    'TR': 'RIPE', 'UA': 'RIPE', 'SA': 'RIPE', 'IR': 'RIPE', 
    'CH': 'RIPE', 'SE': 'RIPE', 'NO': 'RIPE', 'DK': 'RIPE', 
    'BE': 'RIPE', 'AT': 'RIPE', 'GR': 'RIPE', 'PT': 'RIPE',
    'IE': 'RIPE', 'FI': 'RIPE', 'CZ': 'RIPE', 'RO': 'RIPE',
    'HU': 'RIPE', 'IL': 'RIPE', 'KZ': 'RIPE', 'BG': 'RIPE',
    'HR': 'RIPE', 'RS': 'RIPE', 'AE': 'RIPE', 'QA': 'RIPE',
}

# --- 国コードから ISO 3166-1 Numeric Code へのマッピング (変更なし) ---
COUNTRY_CODE_TO_NUMERIC_ISO = {
    'AF': 4, 'AL': 8, 'DZ': 12, 'AS': 16, 'AD': 20, 'AO': 24, 'AI': 660, 'AQ': 10, 'AG': 28, 'AR': 32,
    'AM': 51, 'AW': 533, 'AU': 36, 'AT': 40, 'AZ': 31, 'BS': 44, 'BH': 48, 'BD': 50, 'BB': 52, 'BY': 112,
    'BE': 56, 'BZ': 84, 'BJ': 204, 'BM': 60, 'BT': 64, 'BO': 68, 'BA': 70, 'BW': 72, 'BV': 74, 'BR': 76,
    'VG': 92, 'IO': 86, 'BN': 96, 'BG': 100, 'BF': 854, 'BI': 108, 'KH': 116, 'CM': 120, 'CA': 124, 'CV': 132,
    'KY': 136, 'CF': 140, 'TD': 148, 'CL': 152, 'CN': 156, 'CX': 162, 'CC': 166, 'CO': 170, 'KM': 174, 'CG': 178,
    'CD': 180, 'CK': 184, 'CO': 170, 'CR': 188, 'HR': 191, 'CU': 192, 'CY': 196, 'CZ': 203, 'DK': 208, 'DJ': 262, 'DM': 212,
    'DO': 214, 'EC': 218, 'EG': 818, 'SV': 222, 'GQ': 226, 'ER': 232, 'EE': 233, 'ET': 231, 'FK': 238, 'FO': 234,
    'FJ': 242, 'FI': 246, 'FR': 250, 'GF': 254, 'PF': 258, 'TF': 260, 'GA': 266, 'GM': 270, 'GE': 268, 'DE': 276,
    'GH': 288, 'GI': 292, 'GR': 300, 'GL': 304, 'GD': 308, 'GP': 312, 'GU': 316, 'GT': 320, 'GN': 324, 'GW': 624,
    'GY': 328, 'HT': 332, 'HM': 334, 'VA': 336, 'HN': 340, 'HK': 344, 'HU': 348, 'IS': 352, 'IN': 356, 'ID': 360,
    'IR': 364, 'IQ': 368, 'IE': 372, 'IL': 376, 'IT': 380, 'CI': 384, 'JM': 388, 'JP': 392, 'JO': 400, 'KZ': 398,
    'KE': 404, 'KI': 296, 'KP': 408, 'KR': 410, 'KW': 414, 'KG': 417, 'LA': 418, 'LV': 428, 'LB': 422, 'LS': 426,
    'LR': 430, 'LY': 434, 'LI': 438, 'LT': 440, 'LU': 442, 'MO': 446, 'MK': 807, 'MG': 450, 'MW': 454, 'MY': 458,
    'MV': 462, 'ML': 466, 'MT': 470, 'MH': 584, 'MQ': 474, 'MR': 478, 'MU': 480, 'YT': 175, 'MX': 484, 'FM': 583,
    'MD': 498, 'MC': 492, 'MN': 496, 'MS': 500, 'MA': 504, 'MZ': 508, 'MM': 104, 'NA': 516, 'NR': 520, 'NP': 524,
    'NL': 528, 'AN': 530, 'NC': 540, 'NZ': 554, 'NI': 558, 'NE': 562, 'NG': 566, 'NU': 570, 'NF': 574, 'MP': 580,
    'NO': 578, 'OM': 512, 'PK': 586, 'PW': 585, 'PS': 275, 'PA': 591, 'PG': 598, 'PY': 600, 'PE': 604, 'PH': 608,
    'PN': 612, 'PL': 616, 'PT': 620, 'PR': 630, 'QA': 634, 'RE': 638, 'RO': 642, 'RU': 643, 'RW': 646, 'SH': 654,
    'KN': 659, 'LC': 662, 'PM': 666, 'VC': 670, 'WS': 882, 'SM': 674, 'ST': 678, 'SA': 682, 'SN': 686, 'RS': 688,
    'SC': 690, 'SL': 694, 'SG': 702, 'SK': 703, 'SI': 705, 'SB': 90, 'SO': 706, 'ZA': 710, 'GS': 239, 'ES': 724,
    'LK': 144, 'SD': 736, 'SR': 740, 'SJ': 744, 'SZ': 748, 'SE': 752, 'CH': 756, 'SY': 760, 'TW': 158, 'TJ': 762,
    'TZ': 834, 'TH': 764, 'TL': 626, 'TG': 768, 'TK': 772, 'TO': 776, 'TT': 780, 'TN': 788, 'TR': 792, 'TM': 795,
    'TC': 796, 'TV': 798, 'UG': 800, 'UA': 804, 'AE': 784, 'GB': 826, 'US': 840, 'UM': 581, 'UY': 858, 'UZ': 860,
    'VU': 548, 'VE': 862, 'VN': 704, 'VI': 850, 'WF': 876, 'EH': 732, 'YE': 887, 'ZM': 894, 'ZW': 716
}


@st.cache_resource
def get_session():
    session = requests.Session()
    session.headers.update({"User-Agent": "WhoisBatchTool/1.4 (+PythonStreamlitApp)"})
    return session

session = get_session()

@st.cache_data
def get_world_map_data():
    try:
        world_geojson = alt.topo_feature('https://cdn.jsdelivr.net/npm/vega-datasets@v1.29.0/data/world-110m.json', 'countries')
        return world_geojson
    except Exception as e:
        st.error(f"GeoJSONデータのロード中にエラーが発生しました: {e}")
        return None

WORLD_MAP_GEOJSON = get_world_map_data()


# --- ヘルパー関数群 (変更なし) ---
def clean_ocr_error_chars(target):
    cleaned_target = target
    cleaned_target = cleaned_target.replace('Ⅱ', '11')
    cleaned_target = cleaned_target.replace('I', '1')
    cleaned_target = cleaned_target.replace('l', '1')
    cleaned_target = cleaned_target.replace('|', '1')
    cleaned_target = cleaned_target.replace('O', '0')
    cleaned_target = cleaned_target.replace('o', '0')
    cleaned_target = cleaned_target.replace('S', '5')
    cleaned_target = cleaned_target.replace('s', '5')
    cleaned_target = cleaned_target.replace('A', '4')
    cleaned_target = cleaned_target.replace('a', '4')
    cleaned_target = cleaned_target.replace('B', '8')
    return cleaned_target

def is_valid_ip(target):
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False

def is_ipv4(target):
    try:
        ipaddress.IPv4Address(target)
        return True
    except ValueError:
        return False

def ip_to_int(ip):
    try:
        if is_ipv4(ip):
            return struct.unpack("!I", socket.inet_aton(ip))[0]
        return 0
    except OSError:
        return 0

def get_cidr_block(ip, netmask_range=(8, 24)):
    """
    IP Geolocation APIのキャッシュキーとして使用するCIDRブロックを返す。
    IPv4は/24に固定することで、ISP単位の精度の高いキャッシュを実現している。
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version == 4:
            netmask = netmask_range[1] # 24 を使用 (ISP情報に最適)
            network = ipaddress.ip_network(f'{ip}/{netmask}', strict=False)
            return str(network)
        elif ip_obj.version == 6:
            netmask = 48
            network = ipaddress.ip_network(f'{ip}/{netmask}', strict=False)
            return str(network)
        return None
    except ValueError:
        return None

def get_authoritative_rir_link(ip, country_code):
    rir_name = COUNTRY_CODE_TO_RIR.get(country_code)
    
    if rir_name and rir_name in RIR_LINKS:
        encoded_ip = quote(ip, safe='')
        
        if rir_name in ['RIPE', 'ARIN']:
            link_url = RIR_LINKS[rir_name].format(ip=encoded_ip)
            return f"[{rir_name}]({link_url})"
            
        elif rir_name in ['JPNIC', 'APNIC', 'LACNIC', 'AFRINIC']:
            link_url = RIR_LINKS[rir_name]  
            return f"[{rir_name} (手動検索)]({link_url})"

    return f"[Whois (汎用検索 - APNIC窓口)]({RIR_LINKS.get('APNIC', 'https://wq.apnic.net/static/search.html')})"

def create_secondary_links(target):
    encoded_target = quote(target, safe='')
    is_ip = is_valid_ip(target)
    is_ipv6 = is_ip and not is_ipv4(target)

    who_is_url = f'https://who.is/whois-ip/ip-address/{encoded_target}' if is_ip else f'https://who.is/whois/{encoded_target}'
    dns_checker_url = ''
    dns_checker_key = ''

    if is_ip:
        dns_checker_path = 'ipv6-whois-lookup.php' if is_ipv6 else 'ip-whois-lookup.php'
        dns_checker_url = f'https://dnschecker.org/{dns_checker_path}?query={encoded_target}'
        dns_checker_key = 'DNS Checker (手動 - IPv6)' if is_ipv6 else 'DNS Checker'
    else:
        dns_checker_url = f'https://dnschecker.org/whois-lookup.php?query={encoded_target}'
        dns_checker_key = 'DNS Checker (ドメイン)'

    all_links = {
        'VirusTotal': f'https://www.virustotal.com/gui/search/{encoded_target}',
        'Aguse': f'https://www.aguse.jp/?url={encoded_target}',
        'Whois.com': f'https://www.whois.com/whois/{encoded_target}',
        'DomainSearch.jp': f'https://www.domainsearch.jp/whois/?q={encoded_target}',
        'Who.is': who_is_url,
        'IP2Proxy': f'https://www.ip2proxy.com/{encoded_target}',
        'DNSlytics (手動)': 'https://dnslytics.com/whois-lookup/',
        'IP Location (手動)': 'https://iplocation.io/ip-whois-lookup',
        'CP-WHOIS (手動)': 'https://doco.cph.jp/whoisweb.php',
    }

    if dns_checker_url:
        all_links[dns_checker_key] = dns_checker_url

    if is_ipv6:
        links = {
            'VirusTotal': all_links['VirusTotal'],
            'DomainSearch.jp': all_links['DomainSearch.jp'],
            dns_checker_key: all_links[dns_checker_key],
            'IP2Proxy': all_links['IP2Proxy'],
            'DNSlytics (手動)': all_links['DNSlytics (手動)'],
            'IP Location (手動)': all_links['IP Location (手動)'],
            'CP-WHOIS (手動)': all_links['CP-WHOIS (手動)'],
        }
    else:
        links = all_links

    link_html = ""
    for name, url in links.items():
        link_html += f"[{name}]({url}) | "
    return link_html.rstrip(' | ')

# --- API通信関数の変更（API設定値を引数で受け取るように修正） ---
def get_ip_details_from_api(ip, cidr_cache_snapshot, delay_between_requests, rate_limit_wait_seconds):
    """
    IP-APIから詳細を取得する。CIDRキャッシュを優先的に使用する。
    
    Args:
        ip (str): ターゲットIPアドレス
        cidr_cache_snapshot (dict): メインスレッドから渡された現在のCIDRキャッシュのコピー
        delay_between_requests (float): APIコール前の待機時間 (レートリミット対策)
        rate_limit_wait_seconds (int): レートリミット発生時の強制待機時間

    Returns:
        tuple: (result_dict, new_cache_entry_or_None)
    """
    
    result = {
        'Target_IP': ip, 'ISP': 'N/A', 'Country': 'N/A', 'CountryCode': 'N/A', 'RIR_Link': 'N/A',
        'Secondary_Security_Links': 'N/A', 'Status': 'N/A'
    }
    new_cache_entry = None

    # 1. CIDRブロックを特定
    cidr_block = get_cidr_block(ip)
    
    # 2. CIDRキャッシュのチェック
    if cidr_block and cidr_block in cidr_cache_snapshot:
        cached_data = cidr_cache_snapshot[cidr_block]
        
        # キャッシュのTTLチェック (24時間 = 86400秒)
        if time.time() - cached_data['Timestamp'] < 86400:
            status_type = "IPv6 CIDR Cache" if not is_ipv4(ip) else "IPv4 CIDR Cache"
            
            result['ISP'] = cached_data['ISP']
            result['Country'] = cached_data['Country']
            result['CountryCode'] = cached_data['CountryCode']
            result['RIR_Link'] = get_authoritative_rir_link(ip, cached_data['CountryCode'])
            result['Status'] = f'Success ({status_type})'
            result['Secondary_Security_Links'] = create_secondary_links(ip)
            
            return result, new_cache_entry
        # キャッシュ期限切れの場合は、APIコールに進む

    
    # 3. APIコール（キャッシュがない、または期限切れの場合）
    try:
        # ユーザー選択に基づく遅延時間を使用
        time.sleep(delay_between_requests) 

        url = IP_API_URL.format(ip=ip)
        response = session.get(url, timeout=45)
        
        # 429エラー (レートリミット) 発生時の処理
        if response.status_code == 429:
            # ユーザー選択に基づく待機時間を使用
            defer_until = time.time() + rate_limit_wait_seconds
            result['Status'] = 'Error: Rate Limit (429)'
            result['Defer_Until'] = defer_until
            result['Secondary_Security_Links'] = create_secondary_links(ip)
            return result, new_cache_entry 
        
        response.raise_for_status()
        data = response.json()
        
        if data.get('status') == 'success':
            country = data.get('country', 'N/A')
            country_code = data.get('countryCode', 'N/A') 

            result['ISP'] = data.get('isp', 'N/A')
            result['Country'] = country
            result['CountryCode'] = country_code
            result['RIR_Link'] = get_authoritative_rir_link(ip, country_code)
            status_type = "IPv6 API" if not is_ipv4(ip) else "IPv4 API"
            result['Status'] = f'Success ({status_type})'
            
            # 4. CIDRキャッシュの書き込みデータを準備（成功時のみ）
            if cidr_block:
                new_cache_entry = {
                    cidr_block: {
                        'ISP': result['ISP'],
                        'Country': result['Country'],
                        'CountryCode': result['CountryCode'],
                        'Timestamp': time.time()
                    }
                }
            
        elif data.get('status') == 'fail':
            result['Status'] = f"API Fail: {data.get('message', 'Unknown Fail')}"
            result['RIR_Link'] = get_authoritative_rir_link(ip, 'N/A')
            
        else:
            result['Status'] = f"API Error: Unknown Response"
            result['RIR_Link'] = get_authoritative_rir_link(ip, 'N/A')
            
    except requests.exceptions.RequestException as e:
        result['Status'] = f'Error: Network/Timeout ({type(e).__name__})'
        
    result['Secondary_Security_Links'] = create_secondary_links(ip)
    return result, new_cache_entry

def get_domain_details(domain):
    icann_link = f"[ICANN Whois (手動検索)]({RIR_LINKS['ICANN Whois']})"
    return {
        'Target_IP': domain, 'ISP': 'Domain/Host', 'Country': 'N/A', 'CountryCode': 'N/A',
        'RIR_Link': icann_link,
        'Secondary_Security_Links': create_secondary_links(domain),
        'Status': 'Success (Domain)'
    }

def get_simple_mode_details(target):
    if is_valid_ip(target):
        rir_link_content = f"[Whois (汎用検索 - APNIC窓口)]({RIR_LINKS['APNIC']})"
    else:
        rir_link_content = f"[ICANN Whois (手動検索)]({RIR_LINKS['ICANN Whois']})"
        
    return {
        'Target_IP': target, 
        'ISP': 'N/A (簡易モード)', 
        'Country': 'N/A (簡易モード)',
        'CountryCode': 'N/A',
        'RIR_Link': rir_link_content,
        'Secondary_Security_Links': create_secondary_links(target),
        'Status': 'Success (簡易モード)' 
    }

# --- 後続のヘルパー関数群 (group_results_by_isp, summarize_in_realtime, draw_summary_content, display_results) は変更なし ---

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
                'Status': res['Status']
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
            'Target_IP': target_ip_display, 'Country': data['Country'], 'ISP': data['ISP'],
            'RIR_Link': data['RIR_Link'], 'Secondary_Security_Links': data['Secondary_Security_Links'],
            'Status': status_display
        })
    
    final_grouped_results.extend(non_aggregated_results)

    return final_grouped_results

# --- リアルタイム集計関数 (変更なし) ---
def summarize_in_realtime(raw_results):
    isp_counts = {}
    country_code_counts = {}

    target_frequency = st.session_state.get('target_freq_map', {})

    st.session_state['debug_summary'] = {} 

    country_all_df = pd.DataFrame({
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

        isp = r.get('ISP', 'N/A')
        cc = r.get('CountryCode', 'N/A')
        
        if isp and isp not in ['N/A', 'N/A (簡易モード)']:
            isp_counts[isp] = isp_counts.get(isp, 0) + frequency
        if cc and cc != 'N/A':
            country_code_counts[cc] = country_code_counts.get(cc, 0) + frequency

    isp_df = pd.DataFrame(list(isp_counts.items()), columns=['ISP', 'Count'])
    if not isp_df.empty:
        isp_df = isp_df.sort_values('Count', ascending=False).head(10)
        isp_df['ISP'] = isp_df['ISP'].str.wrap(25)
    else:
        isp_df = pd.DataFrame(columns=['ISP', 'Count'])

    if country_code_counts:
        code_to_name = {
            r['CountryCode']: r['Country'] 
            for r in raw_results 
            if r.get('CountryCode') and r['CountryCode'] != 'N/A'
        }
        code_to_name['JP'] = 'Japan'
        code_to_name['US'] = 'United States'

        map_data = []
        for cc, cnt in country_code_counts.items():
            num = COUNTRY_CODE_TO_NUMERIC_ISO.get(cc)
            if num is not None:
                map_data.append({
                    'NumericCode': int(num), 
                    'Count': int(cnt),
                    'Country': code_to_name.get(cc, cc)
                })

        country_all_df = pd.DataFrame(map_data).astype({
            'NumericCode': 'int64',
            'Count': 'int64'
        })

        top10 = sorted(country_code_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        country_df = pd.DataFrame([
            {'Country': code_to_name.get(c, c), 'Count': n} 
            for c, n in top10
        ])
        country_df['Country'] = country_df['Country'].str.wrap(25)
    else:
        country_df = pd.DataFrame(columns=['Country', 'Count'])
        
    st.session_state['debug_summary']['country_code_counts'] = country_code_counts
    st.session_state['debug_summary']['country_all_df'] = country_all_df.to_dict('records')


    freq_map = st.session_state.get('target_freq_map', {})
    finished = st.session_state.get('finished_ips', set())
    freq_list = [{'Target_IP': t, 'Count': c} for t, c in freq_map.items() if t in finished]
    freq_df = pd.DataFrame(freq_list)
    if not freq_df.empty:
        freq_df = freq_df.sort_values('Count', ascending=False).head(10)

    return isp_df, country_df, freq_df, country_all_df

# --- 集計結果描画ヘルパー関数 (変更なし) ---
def draw_summary_content(isp_summary_df, country_summary_df, target_frequency_df, country_all_df, title):
    st.subheader(title)
    
    st.markdown("#### 🌍 国別 IP カウントヒートマップ")
    if WORLD_MAP_GEOJSON and not country_all_df.empty:
        
        base = alt.Chart(WORLD_MAP_GEOJSON).mark_geoshape(
            stroke='black', 
            strokeWidth=0.1
        ).encode(
            color=alt.value("#f0f0f052"), 
        ).project(
            type='mercator',
            scale=80,
            translate=[500, 180]        
        ).properties(
            title='World Map IP Count Heatmap',
            width=2500, 
            height=400 
        )

        heatmap = alt.Chart(WORLD_MAP_GEOJSON).mark_geoshape(
            stroke='black', 
            strokeWidth=0.1
        ).encode(
            color=alt.Color('Count:Q',
                            scale=alt.Scale(
                                type='log', 
                                domainMin=1,
                                domainMax=alt.Undefined,
                                range=['#99f6e4', '#facc15', '#dc2626']
                            ),
                            legend=alt.Legend(title="IP Count")),
            tooltip=[
                alt.Tooltip('Country:N', title='Country'),
                alt.Tooltip('Count:Q', title='IP Count', format=',')
            ]
        ).transform_lookup(
            lookup='id',
            from_=alt.LookupData(
                country_all_df, 
                key='NumericCode',          
                fields=['Count', 'Country']
            )
        ).project(
            type='mercator',
            scale=80,
            translate=[500, 180]
            )

        chart = alt.layer(base, heatmap).resolve_scale(
            color='independent'
        ).configure_legend(
            orient='right'
        ).interactive()
        
        st.altair_chart(chart, use_container_width=True)
        
    else:
        st.info("ヒートマップデータまたはGeoJSONがロードされていないか、成功したIPv4データが存在しないため表示できません。")
    
    st.markdown("---")


    col_freq, col_isp, col_country = st.columns([1, 1, 1]) 

    with col_freq:
        st.markdown("#### 🎯 Target IP別カウント (トップ10)")
        if not target_frequency_df.empty:
            st.caption(f"**集計対象ターゲット数 (重複なし):** {len(target_frequency_df)} 件")
            
            chart = alt.Chart(target_frequency_df).mark_bar().encode(
                x=alt.X('Count', title='Count'),
                y=alt.Y('Target_IP', sort='-x', title='Target IP'), 
                tooltip=['Target_IP', 'Count']
            ).properties(title='Target IP Counts').interactive()
            st.altair_chart(chart, use_container_width=True)

            target_frequency_df_display = target_frequency_df.copy()
            target_frequency_df_display['Target_IP'] = target_frequency_df_display['Target_IP'].str.wrap(25)
            st.dataframe(target_frequency_df_display, hide_index=True, use_container_width=True)
        else:
            st.info("データがありません")
            
    with col_isp:
        st.markdown("#### 🏢 ISP別カウント (トップ10)")
        if not isp_summary_df.empty:
            chart = alt.Chart(isp_summary_df).mark_bar().encode(
                x=alt.X('Count', title='Count'),
                y=alt.Y('ISP', sort='-x', title='ISP'), 
                tooltip=['ISP', 'Count']
            ).properties(title='ISP Counts').interactive()
            st.altair_chart(chart, use_container_width=True)
            
            st.dataframe(isp_summary_df, hide_index=True, use_container_width=True)
        else:
            st.info("データがありません")
            
    with col_country:
        st.markdown("#### 🌍 国別カウント (トップ10)")
        if not country_summary_df.empty:
            chart = alt.Chart(country_summary_df).mark_bar().encode(
                x=alt.X('Count', title='Count'),
                y=alt.Y('Country', sort='-x', title='Country'),
                tooltip=['Country', 'Count']
            ).properties(title='Country Counts').interactive()
            st.altair_chart(chart, use_container_width=True)
            
            st.dataframe(country_summary_df, hide_index=True, use_container_width=True)
        else:
            st.info("データがありません")


def get_copy_target(ip_display):
    return ip_display.split(' - ')[0].split(' ')[0]

# --- 結果を表示する関数 (変更なし) ---
def display_results(results_to_display, display_mode):
    st.markdown("### 📝 検索結果")
    
    def get_copy_target(ip_display):
        return ip_display.split(' - ')[0].split(' ')[0]

    with st.container(height=600):
        
        if display_mode == "簡易モード (APIなし - セキュリティリンクのみ)":
            col_widths = [0.5, 1.5, 2.0, 3.5, 0.5] 
            header_names = ["No.", "Target IP", "RIR Links", "Secondary Links", "✅"]
        else:
            col_widths = [0.5, 1.0, 1.0, 1.0, 1.8, 2.2, 0.9, 0.5]
            header_names = ["No.", "Target IP", "Country", "ISP", "RIR Links", "Secondary Links", "**Status**", "✅"]
        
        cols = st.columns(col_widths)
        header_style = "font-weight: bold; background-color: #f0f2f6; padding: 10px; border-radius: 5px; color: #1e3a8a;"
        for i, name in enumerate(header_names):
            if name == "**Status**":
                cols[i].markdown(f'<div style="{header_style}">{name.replace("**", "")}</div>', unsafe_allow_html=True)
            else:
                cols[i].markdown(f'<div style="{header_style}">{name}</div>', unsafe_allow_html=True)
        st.markdown("---")
        
        for i, row in enumerate(results_to_display):
            row_cols = st.columns(col_widths)
            ip_display = row['Target_IP']
            rir_link = row['RIR_Link']
            sec_links = row['Secondary_Security_Links'].replace('\n', ' ')
            chk_key = f"chk_{i}_{ip_display}"
            
            target_to_copy = get_copy_target(ip_display)

            row_cols[0].write(f"**{i+1}**")
            row_cols[1].markdown(f"`{ip_display}`")
            
            if not display_mode.startswith("簡易"):
                row_cols[2].write(row.get('Country', ''))
                row_cols[3].write(row.get('ISP', ''))
                
            rir_col_index = 2 if display_mode.startswith("簡易") else 4
            with row_cols[rir_col_index]: 
                st.markdown(rir_link)
                st.code(target_to_copy, language=None)
            
            sec_col_index = 3 if display_mode.startswith("簡易") else 5
            row_cols[sec_col_index].markdown(sec_links)
            
            if not display_mode.startswith("簡易"):
                status = row.get('Status', '')
                status_text_style = ""
                
                if status.startswith("Success"):
                    if status.endswith("CIDR Cache)"):
                        status_text_style = f'<span style="color: #0d9488; font-weight: bold;">{status}</span>' 
                    else:
                        status_text_style = f'<span style="color: #16a34a; font-weight: bold;">{status}</span>' 
                elif status.startswith("Aggregated"):
                    status_text_style = f'<span style="color: #2563eb; font-weight: bold;">{status}</span>'
                elif status.startswith("Error"):
                    status_text_style = f'<span style="color: #dc2626; font-weight: bold;">{status}</span>'
                elif status.startswith("Pending"):
                    status_text_style = f'<span style="color: #f59e0b; font-weight: bold;">{status}</span>'
                else:
                    status_text_style = status

                if status_text_style:
                    row_cols[6].markdown(status_text_style, unsafe_allow_html=True)
                else:
                    row_cols[6].write(status)

                row_cols[7].checkbox("", key=chk_key, value=False)
                
            else:
                row_cols[4].checkbox("", key=chk_key, value=False)

                
            st.markdown('<hr style="margin: 5px 0; opacity: 0.2;">', unsafe_allow_html=True)


# --- メイン処理 ---
def main():
    # 【変更なし】セッションステートの定義
    if 'cancel_search' not in st.session_state: st.session_state['cancel_search'] = False
    if 'raw_results' not in st.session_state: st.session_state['raw_results'] = []
    if 'targets_cache' not in st.session_state: st.session_state['targets_cache'] = []
    if 'is_searching' not in st.session_state: st.session_state['is_searching'] = False
    if 'deferred_ips' not in st.session_state: st.session_state['deferred_ips'] = {} 
    if 'finished_ips' not in st.session_state: st.session_state['finished_ips'] = set() 
    if 'search_start_time' not in st.session_state: st.session_state['search_start_time'] = 0.0 
    if 'target_freq_map' not in st.session_state: st.session_state['target_freq_map'] = {} 
    if 'cidr_cache' not in st.session_state: st.session_state['cidr_cache'] = {} 
    if 'debug_summary' not in st.session_state: st.session_state['debug_summary'] = {} 
    
    # --- サイドバーデザイン ---
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
        if st.button("🔄 IPキャッシュクリア", help="キャッシュが古くなった場合にクリック"):
            st.session_state['cidr_cache'] = {} 
            st.info("IP/CIDRキャッシュをクリアしました。")
            st.rerun()

    # --- メインコンテンツ：仕様・解説タブ (省略) ---
    if selected_menu == "仕様・解説":
        st.title("📖 ツールの仕様と解説")
        st.markdown(f"""
        このツールは、IPアドレスまたはドメイン名に対して Whois および IP Geolocation 情報を一括で検索するためのアプリケーションです。
                    
        #### 1. データソース
        - **IP Geolocation / ISP 情報**: `ip-api.com` の API を使用しています。
        - **Whois リンク**: 各IPアドレスの国コードに基づいて、適切な地域インターネットレジストリ (RIR) の Whois 検索ページへのリンクを生成します。          

        #### 2. 主な機能
        - **一括Whois検索**: 
            - 複数行の IP/ドメインを一括で処理できます。
            - 処理はマルチスレッドで行われ、APIのレートリミットを自動で検知・待機します。
            - **CIDRキャッシュ**: **同じCIDRブロック内のIPアドレスはAPIリクエストをスキップ**し、検索速度を大幅に向上させます。（デフォルトでIPv4は/24、IPv6は/48のブロックでキャッシュします。）
            - **標準モード**: 各ターゲットを個別に表示します。
            - **集約モード**: 同じ ISP/国コードを持つ連続するIPv4アドレス群を「IPレンジ」として集約表示します。
            - **簡易モード**: APIコールを行わず、各種セキュリティ/Whois検索サイトへのリンクのみを提供します。
        - **集計結果**: 検索後、ISP別、国別、ターゲット別をグラフで表示し、国別のIPカウントヒートマップも表示します。
            - **キャッシュ対応**: キャッシュ機能によりAPIリクエストはユニークなIPに限定されますが、**集計機能は入力リストのIPの重複度（出現回数）を正確に反映**しています。
        - **セキュリティ/Whois検索サイトリンク**: VirusTotal, Aguseなどのセキュリティ関連リンクも併せて表示します。
                    
        #### 3. セキュリティ/Whois検索サイトの特性
        - **公式RIR**: 各地域のインターネットレジストリ (RIR) が提供する公式の Whois サービスです。最も正確な情報が得られますが、一部の RIR では手動での検索が必要です。
        - **[{'VirusTotal'}]({SECONDARY_TOOL_BASE_LINKS['VirusTotal']})**: セキュリティ評判、マルウェア、攻撃履歴の確認できます。
        - **[{'Whois.com'}]({SECONDARY_TOOL_BASE_LINKS['Whois.com']}) / [{'Who.is'}]({SECONDARY_TOOL_BASE_LINKS['Who.is']})**: 公式情報を見やすく表示します。ドメイン/IPの両方に対応しています。            
        - **[{'DomainSearch.jp'}]({SECONDARY_TOOL_BASE_LINKS['DomainSearch.jp']}) / [{'Aguse'}]({SECONDARY_TOOL_BASE_LINKS['Aguse']})**: IPアドレス、ドメイン名、ネームサーバ等の複合的な調査が可能です。
        - **[{'IP2Proxy'}]({SECONDARY_TOOL_BASE_LINKS['IP2Proxy']})**: プロキシ、VPN、Torなどの匿名化技術の使用判定が可能です。
        - **[{'DNS Checker'}]({SECONDARY_TOOL_BASE_LINKS['DNS Checker']})**: IPv6対応。DNSレコードやWhois情報の多機能ツールです。
        - **[{'DNSlytics'}]({SECONDARY_TOOL_BASE_LINKS['DNSlytics']}) / [{'IP Location'}]({SECONDARY_TOOL_BASE_LINKS['IP Location']})**: IPv6対応。地理情報、ホスティング情報等の調査が可能です。
        - **[{'CP-WHOIS'}]({SECONDARY_TOOL_BASE_LINKS['CP-WHOIS']})**: **信頼性**が高いWhois検索ツールです。利用者認証が必要です。

        #### 4. 技術的仕様
        - **Streamlit**: WebUIフレームワーク
        - **Requests/ThreadPoolExecutor**: HTTP通信とマルチスレッド並列処理
        - **IP Address/Socket/Struct**: IPアドレス操作およびCIDR対応
        - **Pandas/Altair/GeoJSON**: データ集計と可視化

        #### 5. API レートリミット対策
        `ip-api.com` の API は無料版で**毎分 45リクエスト**のレートリミットがあります。
        - **API 処理モード**で、安定性を優先するか、速度を優先するかを選択できます。
            - **安定性重視**: 単一スレッドで、APIコール間に {MODE_SETTINGS["安定性重視 (1.5秒待機/単一スレッド)"]["DELAY_BETWEEN_REQUESTS"]} 秒の遅延を設けます。
            - **速度優先**: 2スレッドで、APIコール間に {MODE_SETTINGS["速度優先 (1.4秒待機/2スレッド)"]["DELAY_BETWEEN_REQUESTS"]} 秒の遅延を設けます。
        - 検索処理中に 429 エラー (Too Many Requests) が発生した場合、ツールは自動的に {RATE_LIMIT_WAIT_SECONDS} 秒間処理を中断し、その後残りの処理を再開します。
        - **CIDRキャッシュ機能**により、一度検索したIPアドレスと同じCIDRブロック内のIPアドレスに対するAPIリクエストを回避し、レートリミット対策の効率を向上させています。
        
        #### 6. OCRエラー対策
        入力された文字列に対して、OCR誤認識で発生しやすい文字 (`Ⅱ` -> `11`,`I/l` -> `1`, `O/o` -> `0`, `S/s` -> `5` など) を自動で修正する処理を加えています。
        """) 
        return

    # --- メインコンテンツ：Whois検索タブ ---
    st.title("🌐 WhoisSearchTool")

    # 入力エリア
    col_input1, col_input2 = st.columns([1, 1])

    with col_input1:
        manual_input = st.text_area(
            "📋 テキスト入力 (IP/ドメイン)",
            height=150,
            placeholder="8.8.8.8\nexample.com\n2404:6800:..."
        )

    with col_input2:
        uploaded_file = st.file_uploader("📂 リストをアップロード (txt)", type=['txt'])
        st.caption("※ 1行に1つのターゲットを記載してください")

    # ターゲット解析 (変更なし)
    raw_targets = []
    if manual_input: raw_targets.extend(manual_input.splitlines())
    if uploaded_file: raw_targets.extend(uploaded_file.read().decode("utf-8").splitlines())
    raw_targets = [t.strip() for t in raw_targets if t.strip()]
    
    if raw_targets:
        cleaned_raw_targets_list = [clean_ocr_error_chars(t) for t in raw_targets]
        target_freq_counts = pd.Series(cleaned_raw_targets_list).value_counts().to_dict()
    else:
        target_freq_counts = {}

    targets = []
    ocr_error_chars = set('Iil|OoSsAaBⅡ')

    for t in raw_targets:
        original_t = t
        is_ocr_error_likely = any(c in ocr_error_chars for c in original_t)
        if is_ocr_error_likely:
            cleaned_t = clean_ocr_error_chars(original_t)
            if is_valid_ip(cleaned_t):
                if cleaned_t not in targets: targets.append(cleaned_t)
                continue
            t = original_t
        
        invalid_ip_chars = set('ghijklmnopqrstuvwxyz')
        has_hyphen = '-' in t
        has_strictly_domain_char = any(c in invalid_ip_chars for c in t.lower())
        is_likely_domain_or_host = has_hyphen or has_strictly_domain_char
    
        if is_valid_ip(t):
            if t not in targets: targets.append(t)
        elif is_likely_domain_or_host:
            if t not in targets: targets.append(t)
        else:
            cleaned_t_final = clean_ocr_error_chars(t)
            if cleaned_t_final not in targets: targets.append(cleaned_t_final)

    has_new_targets = (targets != st.session_state.targets_cache)
    
    if has_new_targets or 'target_freq_map' not in st.session_state:
        st.session_state['target_freq_map'] = target_freq_counts

    ip_targets = [t for t in targets if is_valid_ip(t)]
    domain_targets = [t for t in targets if not is_valid_ip(t)]
    ipv6_count = sum(1 for t in ip_targets if not is_ipv4(t))
    ipv4_count = len(ip_targets) - ipv6_count

    st.markdown("---")
    st.markdown("### ⚙️ 検索表示設定")
    
    # --- 表示モードの選択 (変更なし) ---
    display_mode = st.radio(
        "**表示モード:** (検索結果の表示形式とAPI使用有無を設定)",
        ("標準モード", "集約モード (IPv4 Group)", "簡易モード (APIなし)"),
        key="display_mode_radio",
        horizontal=True
    )
    
    # --- API処理モードの選択 (新規追加) ---
    api_mode_selection = st.radio(
        "**API 処理モード:** (速度と安定性のトレードオフ)",
        list(MODE_SETTINGS.keys()),
        key="api_mode_radio",
        horizontal=True
    )
    
    # 選択されたAPI設定の適用
    selected_settings = MODE_SETTINGS[api_mode_selection]
    max_workers = selected_settings["MAX_WORKERS"]
    delay_between_requests = selected_settings["DELAY_BETWEEN_REQUESTS"]
    
    # 固定値として定義されているレートリミット待機時間をローカル変数に格納
    rate_limit_wait_seconds = RATE_LIMIT_WAIT_SECONDS


    mode_mapping = {
        "標準モード": "標準モード (1ターゲット = 1行)",
        "集約モード (IPv4 Group)": "集約モード (IPv4アドレスをISP/国別でグループ化)",
        "簡易モード (APIなし)": "簡易モード (APIなし - セキュリティリンクのみ)"
    }
    current_mode_full_text = mode_mapping[display_mode]

    # --- アクションエリア ---
    st.markdown("---")
    col_act1, col_act2 = st.columns([3, 1])

    is_currently_searching = st.session_state.is_searching and not st.session_state.cancel_search
    
    total_ip_targets_for_display = len(ip_targets) + len(st.session_state.deferred_ips)

    with col_act1:
        st.success(f"**Target:** IPv4: {ipv4_count} / IPv6: {ipv6_count} / Domain: {len(domain_targets)} (Pending: {len(st.session_state.deferred_ips)}) / **CIDR Cache:** {len(st.session_state.cidr_cache)}")

    with col_act2:
        if is_currently_searching:
            if st.button("❌ 中止", type="secondary", use_container_width=True):
                st.session_state.cancel_search = True
                st.session_state.is_searching = False
                st.session_state.deferred_ips = {}
                st.rerun()
        else:
            execute_search = st.button(
            "🚀 検索開始",
            type="primary",
            use_container_width=True,
            disabled=(len(targets) == 0 and len(st.session_state.deferred_ips) == 0)
            )

    # 検索開始/継続アクション
    if ('execute_search' in locals() and execute_search and (has_new_targets or len(st.session_state.deferred_ips) > 0)) or is_currently_searching:
        
        if ('execute_search' in locals() and execute_search and has_new_targets and len(targets) > 0):
            st.session_state.is_searching = True
            st.session_state.cancel_search = False
            st.session_state.raw_results = []
            st.session_state.deferred_ips = {}
            st.session_state.finished_ips = set()
            st.session_state.targets_cache = targets
            st.session_state.search_start_time = time.time()
            
            st.rerun() 
            
        elif is_currently_searching:
            targets = st.session_state.targets_cache
            ip_targets = [t for t in targets if is_valid_ip(t)]
            domain_targets = [t for t in targets if not is_valid_ip(t)]

            st.subheader("⏳ 処理中...")
            
            total_targets = len(targets)
            total_ip_api_targets = len(ip_targets)
            
            ip_targets_to_process = [ip for ip in ip_targets if ip not in st.session_state.finished_ips]
            
            # 1. 遅延IPのチェックと復帰
            current_time = time.time()
            ready_to_retry_ips = []
            deferred_ips_new = {}
            for ip, defer_time in st.session_state.deferred_ips.items():
                if current_time >= defer_time:
                    ready_to_retry_ips.append(ip)
                else:
                    deferred_ips_new[ip] = defer_time
            
            st.session_state.deferred_ips = deferred_ips_new
            
            # APIコールが必要なIPと、CIDRキャッシュチェックが必要なIPを抽出
            immediate_ip_queue_unique = []
            for ip in ip_targets_to_process:
                if ip not in st.session_state.deferred_ips and ip not in immediate_ip_queue_unique:
                    immediate_ip_queue_unique.append(ip)

            immediate_ip_queue = immediate_ip_queue_unique
            immediate_ip_queue.extend(ready_to_retry_ips)
            
            # 簡易モードの場合はAPI処理をスキップ
            if "簡易" in current_mode_full_text:
                if not st.session_state.raw_results:
                    results_list = []
                    for t in targets:
                        results_list.append(get_simple_mode_details(t))
                    st.session_state.raw_results = results_list
                    st.session_state.finished_ips.update(targets)
                    st.session_state.is_searching = False
                    st.rerun()

            # 標準/集約モード
            else:
                
                if not any(res['ISP'] == 'Domain/Host' for res in st.session_state.raw_results) and domain_targets:
                    st.session_state.raw_results.extend([get_domain_details(d) for d in domain_targets])
                    st.session_state.finished_ips.update(domain_targets)
                    
                prog_bar_container = st.empty()
                status_text_container = st.empty()
                summary_container = st.empty() 

                if immediate_ip_queue:
                    
                    # キャッシュスナップショットの取得
                    cidr_cache_snapshot = st.session_state.cidr_cache.copy() 
                    
                    # ユーザー設定に基づく MAX_WORKERS を使用
                    with ThreadPoolExecutor(max_workers=max_workers) as executor:
                        
                        # ワーカ関数への引数に API設定値を渡す
                        future_to_ip = {
                            executor.submit(
                                get_ip_details_from_api, 
                                ip, 
                                cidr_cache_snapshot, 
                                delay_between_requests, 
                                rate_limit_wait_seconds # RATE_LIMIT_WAIT_SECONDSは固定
                            ): ip for ip in immediate_ip_queue
                        }
                        remaining = set(future_to_ip.keys())
                        
                        while remaining and not st.session_state.cancel_search:
                            
                            done, remaining = wait(remaining, timeout=0.1, return_when=FIRST_COMPLETED)
                            
                            for f in done:
                                # ワーカ関数の戻り値 (res, new_cache_entry) を受け取る
                                res_tuple = f.result()
                                res = res_tuple[0]
                                new_cache_entry = res_tuple[1]
                                ip = res['Target_IP']
                                
                                # メインスレッドで st.session_state.cidr_cache を安全に更新
                                if new_cache_entry:
                                    st.session_state.cidr_cache.update(new_cache_entry)
                                
                                # 結果の処理 (変更なし)
                                if res.get('Status', '').startswith('Success'):
                                    st.session_state.raw_results.append(res)
                                    st.session_state.finished_ips.add(ip)
                                
                                elif res.get('Defer_Until'):
                                    st.session_state.deferred_ips[ip] = res['Defer_Until']
                                    
                                else:
                                    st.session_state.raw_results.append(res)
                                    st.session_state.finished_ips.add(ip)

                            
                            # 進捗状況の更新 (変更なし)
                            if total_ip_api_targets > 0:
                                processed_api_ips_count = len([ip for ip in st.session_state.finished_ips if is_valid_ip(ip)])
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
                                    eta_display = f"{minutes:02d}:{seconds:02d}"
                                    
                                with prog_bar_container:
                                    st.progress(pct)
                                with status_text_container:
                                    st.caption(f"**Progress:** {processed_api_ips_count}/{total_ip_api_targets} | **Deferred:** {len(st.session_state.deferred_ips)} | **CIDR Cache:** {len(st.session_state.cidr_cache)} | **Remaining Time:** {eta_display}")
                                
                                isp_summary_df, country_summary_df, target_frequency_df, country_all_df = summarize_in_realtime(st.session_state.raw_results)
                                with summary_container.container():
                                    st.markdown("---")
                                    draw_summary_content(isp_summary_df, country_summary_df, target_frequency_df, country_all_df, "📊 Real-time analysis")
                                st.markdown("---")


                            if not remaining and not st.session_state.deferred_ips:
                                break
                            
                            if st.session_state.deferred_ips:
                                st.rerun()  
                            
                            time.sleep(0.5) 
                            
                        if total_ip_api_targets > 0 and not st.session_state.deferred_ips:
                            processed_api_ips_count = len([ip for ip in st.session_state.finished_ips if is_valid_ip(ip)])
                            final_pct = int(processed_api_ips_count / total_ip_api_targets * 100)
                            with prog_bar_container:
                                st.progress(final_pct)
                            with status_text_container:
                                st.caption(f"**Progress:** {processed_api_ips_count}/{total_ip_api_targets} | **Deferred:** {len(st.session_state.deferred_ips)} | **CIDR Cache:** {len(st.session_state.cidr_cache)} | **Remaining Time:** 完了")
                        
                if len(st.session_state.finished_ips) == total_targets and not st.session_state.deferred_ips:
                    st.session_state.is_searching = False
                    st.info("✅ 全ての検索が完了しました。")
                    
                    summary_container.empty()
                    
                    st.rerun()
                
                elif st.session_state.deferred_ips and not st.session_state.cancel_search:
                    next_retry_time = min(st.session_state.deferred_ips.values())
                    wait_time = max(1, int(next_retry_time - time.time()))
                    
                    prog_bar_container.empty()
                    status_text_container.empty()
                    summary_container.empty()
                    st.warning(f"⚠️ **APIレートリミットに達しました。** 隔離中の **{len(st.session_state.deferred_ips)}** 件のIPアドレスは **{wait_time}** 秒後に再試行されます。")
                    
                    time.sleep(min(5, wait_time)) 
                    st.rerun()

                elif st.session_state.cancel_search:
                    prog_bar_container.empty()
                    status_text_container.empty()
                    summary_container.empty()
                    st.warning("検索がユーザーによって中止されました。")
                    st.session_state.is_searching = False
                    st.rerun()


    # --- 結果表示 ---
    if st.session_state.raw_results or st.session_state.deferred_ips:
        res = st.session_state.raw_results
        
        # 🔔 デバッグ情報の表示 🔔
        if st.session_state.get('debug_summary'):
            with st.expander("🛠️ デバッグ情報 (集計データ確認用)", expanded=False):
                st.markdown("**API 処理モード設定**")
                st.write(f"MAX_WORKERS: {max_workers}")
                st.write(f"DELAY_BETWEEN_REQUESTS: {delay_between_requests}")
                st.markdown("---")
                st.markdown("**country_code_counts (Alpha-2とカウント)** - **重複度を反映**")
                st.json(st.session_state['debug_summary'].get('country_code_counts', {}))
                
                st.markdown("**country_all_df (Numeric ISO Codeとカウント - 整数型であるべき)** - **重複度を反映**")
                st.json(st.session_state['debug_summary'].get('country_all_df', []))
                
                st.markdown("---")
                if 'cidr_cache' in st.session_state:
                    st.markdown("**CIDR Cache**")
                    st.json(st.session_state.get('cidr_cache', {}))
                else:
                    st.markdown("**CIDR Cache**：初期化されていません")

        
        successful_results = [r for r in res if r['Status'].startswith('Success') or r['Status'].startswith('Aggregated')]
        error_results = [r for r in res if not (r['Status'].startswith('Success') or r['Status'].startswith('Aggregated'))]
        
        # 遅延中のIPをエラー結果として追加
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

        
        display_results(display_res, current_mode_full_text)
        
        if not st.session_state.is_searching or st.session_state.cancel_search:
            isp_summary_df, country_summary_df, target_frequency_df, country_all_df = summarize_in_realtime(st.session_state.raw_results)
            st.markdown("---")
            draw_summary_content(isp_summary_df, country_summary_df, target_frequency_df, country_all_df, "✅ 集計結果")

        
        csv_df = pd.DataFrame(display_res).astype(str)
        if 'Defer_Until' in csv_df.columns:
            csv_df = csv_df.drop(columns=['Defer_Until'])
            
        csv = csv_df.to_csv(index=False).encode('utf-8')
        st.download_button("⬇️ CSVダウンロード", csv, "whois_results.csv", "text/csv")

if __name__ == "__main__":
    main()

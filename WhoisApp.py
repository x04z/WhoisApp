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
import altair as alt 
import json 
import io 
import re 

# --- Excelグラフ生成用ライブラリ ---
from openpyxl import Workbook
from openpyxl.utils.dataframe import dataframe_to_rows
from openpyxl.chart import BarChart, Reference, Series
from openpyxl.chart.label import DataLabelList
from openpyxl.chart.axis import ChartLines
from openpyxl.chart.layout import Layout, ManualLayout
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side

# ページ設定
st.set_page_config(layout="wide", page_title="検索大臣", page_icon="🌐")

# ==========================================
# 🛠️ 自動モード判定ロジック (st.secrets利用)
# ==========================================
IS_PUBLIC_MODE = False
try:
    if "ENV_MODE" in st.secrets and st.secrets["ENV_MODE"] == "public":
        IS_PUBLIC_MODE = True
except FileNotFoundError:
    IS_PUBLIC_MODE = False
# ==========================================

# --- 設定 ---
MODE_SETTINGS = {
    "安定性重視 (2.5秒待機/単一スレッド)": {
        "MAX_WORKERS": 1, 
        "DELAY_BETWEEN_REQUESTS": 2.5 
    },
    "速度優先 (1.4秒待機/2スレッド)": {
        "MAX_WORKERS": 2, 
        "DELAY_BETWEEN_REQUESTS": 1.4 
    }
}
IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,isp,org,query,message"
IPINFO_API_URL = "https://ipinfo.io/{ip}" 
RDAP_BOOTSTRAP_URL = "https://rdap.apnic.net/ip/{ip}" 

RATE_LIMIT_WAIT_SECONDS = 120 
  
RIR_LINKS = {
    'RIPE': 'https://apps.db.ripe.net/db-web-ui/#/query?searchtext={ip}',
    'ARIN': 'https://search.arin.net/rdap/?query={ip}',
    'APNIC': 'https://wq.apnic.net/static/search.html',
    'JPNIC': 'https://www.nic.ad.jp/ja/whois/ja-gateway.html',
    'AFRINIC': 'https://www.afrinic.net/whois',
    'ICANN Whois': 'https://lookup.icann.org/',
}

# 🔗 リンク集
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

COUNTRY_JP_NAME = {
    "AF": "アフガニスタン","AL": "アルバニア","DZ": "アルジェリア","AS": "アメリカ領サモア","AD": "アンドラ","AO": "アンゴラ",
    "AI": "アンギラ","AQ": "南極","AG": "アンティグア・バーブーダ","AR": "アルゼンチン","AM": "アルメニア","AW": "アルバ","AU": "オーストラリア",
    "AT": "オーストリア","AZ": "アゼルバイジャン","BS": "バハマ","BH": "バーレーン","BD": "バングラデシュ","BB": "バルバドス","BY": "ベラルーシ",
    "BE": "ベルギー","BZ": "ベリーズ","BJ": "ベナン","BM": "バミューダ","BT": "ブータン","BO": "ボリビア","BA": "ボスニア・ヘルツェゴビナ",
    "BW": "ボツワナ","BR": "ブラジル","BN": "ブルネイ","BG": "ブルガリア","BF": "ブルキナファソ","BI": "ブルンジ","KH": "カンボジア","CM": "カメルーン",
    "CA": "カナダ","CV": "カーボベルデ","CF": "中央アフリカ共和国","TD": "チャド","CL": "チリ","CN": "中国","CO": "コロンビア","CR": "コスタリカ",
    "HR": "クロアチア","CU": "キューバ","CY": "キプロス","CZ": "チェコ","DK": "デンマーク","DJ": "ジブチ","DM": "ドミニカ国","DO": "ドミニカ共和国",
    "EC": "エクアドル","EG": "エジプト","SV": "エルサルバドル","EE": "エストニア","ET": "エチオピア","FI": "フィンランド","FR": "フランス","DE": "ドイツ",
    "GR": "ギリシャ","GL": "グリーンランド","GT": "グアテマラ","GY": "ガイアナ","HK": "香港","HU": "ハンガリー","IN": "インド","ID": "インドネシア",
    "IR": "イラン","IQ": "イラク","IE": "アイルランド","IL": "イスラエル","IT": "イタリア","JP": "日本","KR": "韓国","TW": "台湾","MY": "マレーシア",
    "MX": "メキシコ","NL": "オランダ","NZ": "ニュージーランド","NO": "ノルウェー","PK": "パキスタン","PA": "パナマ","PE": "ペルー","PH": "フィリピン",
    "PL": "ポーランド","PT": "ポルトガル","QA": "カタール","RO": "ルーマニア","RU": "ロシア","SA": "サウジアラビア","SG": "シンガポール","ZA": "南アフリカ",
    "ES": "スペイン","SE": "スウェーデン","CH": "スイス","TH": "タイ","TR": "トルコ","UA": "ウクライナ","AE": "アラブ首長国連邦","GB": "イギリス",
    "US": "アメリカ","VN": "ベトナム","YE": "イエメン","ZM": "ザンビア","ZW": "ジンバブエ"
}

# --- ISP名称の日本語マッピング (企業名統一版) ---
ISP_JP_NAME = {
    # --- NTT Group ---
    'NTT Communications Corporation': 'NTTドコモビジネス', 
    'NTT COMMUNICATIONS CORPORATION': 'NTTドコモビジネス',
    'NTT DOCOMO BUSINESS,Inc.': 'NTTドコモビジネス',
    'NTT DOCOMO, INC.': 'NTTドコモ',
    'NTT PC Communications, Inc.': 'NTTPCコミュニケーションズ',
    
    # --- KDDI Group ---
    'Kddi Corporation': 'KDDI',
    'KDDI CORPORATION': 'KDDI',
    'Chubu Telecommunications Co., Inc.': '中部テレコミュニケーション',
    'Chubu Telecommunications Company, Inc.': '中部テレコミュニケーション',
    'Hokkaido Telecommunication Network Co., Inc.': 'HOTnet',
    'Energia Communications, Inc.': 'エネコム',
    'STNet, Inc.': 'STNet',
    'QTNet, Inc.': 'QTNet',
    'BIGLOBE Inc.': 'ビッグローブ',
    
    # --- SoftBank Group ---
    'SoftBank Corp.': 'ソフトバンク',
    'Yahoo Japan Corporation': 'LINEヤフー',
    'LY Corporation': 'LINEヤフー',
    'LINE Corporation': 'LINEヤフー',
    
    # --- Rakuten Group ---
    'Rakuten Group, Inc.': '楽天グループ',
    'Rakuten Mobile, Inc.': '楽天モバイル',
    'Rakuten Communications Corp.': '楽天コミュニケーションズ',
    
    # --- Sony Group ---
    'Sony Network Communications Inc.': 'ソニーネットワークコミュニケーションズ',
    'So-net Entertainment Corporation': 'ソニーネットワークコミュニケーションズ', 
    'So-net Corporation': 'ソニーネットワークコミュニケーションズ',
    
    # --- Major ISPs / VNEs ---
    'Internet Initiative Japan Inc.': 'IIJ',
    'NIFTY Corporation': 'ニフティ',
    'FreeBit Co., Ltd.': 'フリービット',
    'TOKAI Communications Corporation': 'TOKAIコミュニケーションズ',
    'DREAM TRAIN INTERNET INC.': 'ドリーム・トレイン・インターネット (DTI)',
    'ASAHI Net, Inc.': '朝日ネット',
    'Asahi Net': '朝日ネット',
    'Optage Inc.': 'オプテージ',
    'Jupiter Telecommunications Co., Ltd.': 'J:COM', 
    'JCOM Co., Ltd.': 'J:COM',
    'JCN': 'J:COM', 
    'SAKURA Internet Inc.': 'さくらインターネット',
    'GMO Internet, Inc.': 'GMOインターネット',
    'INTERNET MULTIFEED CO.': 'インターネットマルチフィード',
    'IDC Frontier Inc.': 'IDCフロンティア',
    
    # --- Others ---
    'ARTERIA Networks Corporation': 'アルテリア・ネットワークス',
    'UCOM Corporation': 'アルテリア・ネットワークス',
    'VECTANT Ltd.': 'アルテリア・ネットワークス',
    'KIBI Cable Television Co., Ltd.': '吉備ケーブルテレビ',
}

# 🆕 強力な名寄せルール (部分一致検索)
ISP_REMAP_RULES = [
    ('jcn', 'J:COM'), ('jupiter', 'J:COM'), ('cablenet', 'J:COM'),
    ('dion', 'KDDI'), ('au one', 'KDDI'), ('kddi', 'KDDI'),
    ('k-opti', 'オプテージ'), ('ctc', '中部テレコミュニケーション'),
    ('vectant', 'アルテリア・ネットワークス'), ('arteria', 'アルテリア・ネットワークス'),
    ('softbank', 'ソフトバンク'), ('bbtec', 'ソフトバンク'),
    ('ocn', 'OCN'),
    ('so-net', 'ソニーネットワークコミュニケーションズ'), ('nuro', 'ソニー (NURO)'),
    ('biglobe', 'ビッグローブ'), ('iij', 'IIJ'),
    ('transix', 'インターネットマルチフィード (transix)'),
    ('v6plus', 'JPNE (v6プラス)'),
    ('rakuten', '楽天グループ'),
]

def normalize_isp_key(text):
    if not text: return ""
    return text.lower().replace(',', '').replace('.', '').strip()

ISP_JP_NAME_NORMALIZED = {normalize_isp_key(k): v for k, v in ISP_JP_NAME.items()}

# --- 匿名化・プロキシ判定用データ ---

@st.cache_data(ttl=86400, show_spinner=False)
def fetch_tor_exit_nodes():
    try:
        url = "https://check.torproject.org/exit-addresses"
        response = requests.get(url, timeout=10)
        return set([line.split()[1] for line in response.text.splitlines() if line.startswith("ExitAddress")])
    except:
        return set()

HOSTING_VPN_KEYWORDS = [
    "hosting", "datacenter", "vps", "cloud", "server", "vpn", "proxy", "dedi",
    "amazon", "google", "microsoft", "azure", "oracle", "alibaba", "digitalocean", 
    "linode", "vultr", "ovh", "hetzner", "akamai", "cloudflare", "fastly",
    "expressvpn", "nordvpn", "proton", "mullvad", "cyberghost"
]

def detect_proxy_vpn_tor(ip, isp_name, tor_nodes):
    isp_lower = isp_name.lower()
    if ip in tor_nodes: return "Tor Node"
    if "icloud" in isp_lower or "private relay" in isp_lower: return "iCloud Private Relay"
    if any(kw in isp_lower for kw in ["vpn", "proxy"]): return "VPN/Proxy (Named)"
    if any(kw in isp_lower for kw in HOSTING_VPN_KEYWORDS): return "Hosting/DataCenter"
    return "Standard Connection"

def get_jp_names(english_isp, country_code):
    if not english_isp:
        return "N/A", COUNTRY_JP_NAME.get(country_code, country_code)

    normalized_input = normalize_isp_key(english_isp)
    jp_isp = english_isp 

    if english_isp in ISP_JP_NAME:
        jp_isp = ISP_JP_NAME[english_isp]
    elif normalized_input in ISP_JP_NAME_NORMALIZED:
        jp_isp = ISP_JP_NAME_NORMALIZED[normalized_input]
    else:
        for keyword, mapped_name in ISP_REMAP_RULES:
            if keyword in normalized_input:
                jp_isp = mapped_name
                break
        
    jp_country = COUNTRY_JP_NAME.get(country_code, country_code)
    return jp_isp, jp_country

@st.cache_resource
def get_session():
    session = requests.Session()
    session.headers.update({"User-Agent": "WhoisBatchTool/2.4 (+RDAP)"})
    return session

session = get_session()

@st.cache_data
def get_world_map_data():
    try:
        world_geojson = alt.topo_feature('https://cdn.jsdelivr.net/npm/vega-datasets@v1.29.0/data/world-110m.json', 'countries')
        return world_geojson
    except:
        return None

WORLD_MAP_GEOJSON = get_world_map_data()


# --- ヘルパー関数群 ---
def clean_ocr_error_chars(target):
    cleaned_target = target.replace('Ⅱ', '11').replace('I', '1').replace('l', '1').replace('|', '1').replace('O', '0').replace('o', '0')
    if ':' not in cleaned_target:
        cleaned_target = cleaned_target.replace('S', '5').replace('s', '5')
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
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version == 4:
            netmask = netmask_range[1] 
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
    return f"[Whois (汎用検索)]({RIR_LINKS.get('APNIC', 'https://wq.apnic.net/static/search.html')})"

def get_copy_target(ip_display):
    if not ip_display: return ""
    return str(ip_display).split(' - ')[0].split(' ')[0]

def create_secondary_links(target):
    encoded_target = quote(target, safe='')
    is_ip = is_valid_ip(target)
    
    # 🔗 リンク定義用辞書
    links = {}

    if is_ip:
        if is_ipv4(target):
            # --- IPv4用 厳選リンク ---
            # VirusTotal: 総合的なセキュリティ評価
            links['VirusTotal'] = f'https://www.virustotal.com/gui/search/{encoded_target}'
            # Aguse: 日本国内からのアクセス解析・ブラックリストチェックに強力
            links['Aguse'] = f'https://www.aguse.jp/?url={encoded_target}'
            # ipinfo.io: 地理位置情報やホスティング判定の詳細確認
            links['ipinfo.io'] = f'https://ipinfo.io/{encoded_target}'
            # IP2Proxy: プロキシ・VPN判定に特化
            links['IP2Proxy'] = f'https://www.ip2proxy.com/{encoded_target}'
            # IP Location: 地図表示と基本的な位置情報
            links['IP Location'] = f'https://iplocation.io/ip/{encoded_target}'
        else:
            # --- IPv6用 厳選リンク ---
            # VirusTotal: IPv6対応
            links['VirusTotal'] = f'https://www.virustotal.com/gui/search/{encoded_target}'
            # ipinfo.io: IPv6完全対応
            links['ipinfo.io'] = f'https://ipinfo.io/{encoded_target}'
            # IP2Proxy: IPv6対応 (プロキシ判定)
            links['IP2Proxy'] = f'https://www.ip2proxy.com/{encoded_target}'
            # IP Location: IPv6対応 (位置情報)
            links['IP Location'] = f'https://iplocation.io/ip/{encoded_target}'
            # DNS Checker: IPv6のWhois伝播確認用
            links['DNS Checker'] = f'https://dnschecker.org/ipv6-whois-lookup.php?query={encoded_target}'
    else:
        # --- ドメイン用 厳選リンク ---
        links['VirusTotal'] = f'https://www.virustotal.com/gui/search/{encoded_target}'
        # Aguse: サーバー証明書やマルウェアチェック
        links['Aguse'] = f'https://www.aguse.jp/?url={encoded_target}'
        # Whois.com: 汎用的なドメイン登録情報確認
        links['Whois.com'] = f'https://www.whois.com/whois/{encoded_target}'

    # 1. 【共通・必須】CP-WHOIS (手動検索用)
    links['CP-WHOIS (手動)'] = 'https://doco.cph.jp/whoisweb.php'


    # HTML生成
    link_html = ""
    for name, url in links.items():
        if url: 
            link_html += f"[{name}]({url}) | "
    
    return link_html.rstrip(' | ')

# 🆕 RDAPデータ取得関数 (公式台帳への照会)
def fetch_rdap_data(ip):
    try:
        url = RDAP_BOOTSTRAP_URL.format(ip=ip)
        # RDAPはリダイレクトされることが多いため allow_redirects=True, Timeoutは短めに
        response = session.get(url, timeout=4, allow_redirects=True)
        if response.status_code == 200:
            data = response.json()
            # 汎用的なRDAPレスポンスから名前を探す (name, handle, remarks)
            network_name = data.get('name', '')
            if not network_name and 'handle' in data:
                network_name = data['handle']
            return network_name
    except:
        pass
    return None

# 🆕 Proモード用 API取得関数 (ipinfo.io)
def get_ip_details_pro(ip, token, tor_nodes):
    result = {
        'Target_IP': ip, 'ISP': 'N/A', 'ISP_JP': 'N/A', 'Country': 'N/A', 'Country_JP': 'N/A', 
        'CountryCode': 'N/A', 'RIR_Link': 'N/A', 'Secondary_Security_Links': 'N/A', 'Status': 'N/A',
        'RDAP': '' # RDAP列用
    }
    try:
        url = IPINFO_API_URL.format(ip=ip)
        headers = {"Authorization": f"Bearer {token}"}
        response = session.get(url, headers=headers, timeout=10)
        
        if response.status_code == 429:
             result['Status'] = 'Error: Rate Limit (Pro)'
             return result
        
        if response.status_code == 403 or response.status_code == 401:
             result['Status'] = 'Error: Invalid API Key'
             return result

        response.raise_for_status()
        data = response.json()
        
        org_raw = data.get('org', '')
        isp_name = re.sub(r'^AS\d+\s+', '', org_raw) if org_raw else 'N/A'
        
        result['ISP'] = isp_name
        result['CountryCode'] = data.get('country', 'N/A')
        result['Country'] = result['CountryCode']
        result['RIR_Link'] = get_authoritative_rir_link(ip, result['CountryCode'])
        result['Status'] = 'Success (Pro)'
        
        jp_isp, jp_country = get_jp_names(result['ISP'], result['CountryCode'])
        result['ISP_JP'] = jp_isp
        result['Country_JP'] = jp_country

        # ipinfoのprivacyデータがあれば使用
        privacy_data = data.get('privacy', {})
        if privacy_data:
            detected = []
            if privacy_data.get('vpn'): detected.append("VPN")
            if privacy_data.get('proxy'): detected.append("Proxy")
            if privacy_data.get('tor'): detected.append("Tor Node")
            if privacy_data.get('hosting'): detected.append("Hosting")
            result['Proxy_Type'] = ", ".join(detected) if detected else ""
        else:
            proxy_type = detect_proxy_vpn_tor(ip, result['ISP'], tor_nodes)
            is_anonymous = (proxy_type != "Standard Connection")
            result['Proxy_Type'] = f"{proxy_type}" if is_anonymous else ""

    except Exception as e:
        result['Status'] = f'Error: Pro API ({type(e).__name__})'
    
    result['Secondary_Security_Links'] = create_secondary_links(ip)
    return result

# --- API通信関数 (Main) ---
def get_ip_details_from_api(ip, cidr_cache_snapshot, delay_between_requests, rate_limit_wait_seconds, tor_nodes, use_rdap, api_key=None):
    
    # 1. Proモード (APIキーあり)
    if api_key:
        result = get_ip_details_pro(ip, api_key, tor_nodes)
        # RDAPオプション有効時
        if use_rdap:
            rdap_res = fetch_rdap_data(ip)
            if rdap_res:
                result['ISP'] += f" [RDAP: {rdap_res}]"
                result['RDAP'] = rdap_res # 🆕 RDAP列に値をセット
        return result, None

    # 2. 通常モード (ip-api.com)
    result = {
        'Target_IP': ip, 'ISP': 'N/A', 'ISP_JP': 'N/A', 'Country': 'N/A', 'Country_JP': 'N/A', 
        'CountryCode': 'N/A', 'RIR_Link': 'N/A', 'Secondary_Security_Links': 'N/A', 'Status': 'N/A',
        'RDAP': '' # RDAP列用
    }
    new_cache_entry = None

    cidr_block = get_cidr_block(ip)
    
    if cidr_block and cidr_block in cidr_cache_snapshot:
        cached_data = cidr_cache_snapshot[cidr_block]
        if time.time() - cached_data['Timestamp'] < 86400:
            result['ISP'] = cached_data['ISP']
            result['Country'] = cached_data['Country']
            result['CountryCode'] = cached_data['CountryCode']
            result['Status'] = "Success (Cache)" 
            jp_isp, jp_country = get_jp_names(result['ISP'], result['CountryCode'])
            proxy_type = detect_proxy_vpn_tor(ip, result['ISP'], tor_nodes)
            is_anonymous = (proxy_type != "Standard Connection")
            result['ISP_JP'] = jp_isp
            result['Proxy_Type'] = f"{proxy_type}" if is_anonymous else ""
            result['Country_JP'] = jp_country
            # キャッシュヒット時はRDAP再取得しない（遅くなるため）か、必要ならここで取得
            return result, None 

    try:
        time.sleep(delay_between_requests) 

        url = IP_API_URL.format(ip=ip)
        response = session.get(url, timeout=45)
        
        if response.status_code == 429:
            defer_until = time.time() + rate_limit_wait_seconds
            result['Status'] = 'Error: Rate Limit (429)'
            result['Defer_Until'] = defer_until
            result['Secondary_Security_Links'] = create_secondary_links(ip)
            return result, new_cache_entry 
        
        response.raise_for_status()
        data = response.json()
        
        if data.get('status') == 'success':
            country_code = data.get('countryCode', 'N/A') 
            
            raw_isp = data.get('isp', 'N/A')
            raw_org = data.get('org', '')
            combined_name = raw_isp if raw_org == raw_isp else f"{raw_isp} / {raw_org}"
            
            result['ISP'] = combined_name
            result['Country'] = data.get('country', 'N/A')
            result['CountryCode'] = country_code
            result['RIR_Link'] = get_authoritative_rir_link(ip, country_code)
            
            # 🆕 RDAP取得ロジック
            if use_rdap:
                rdap_res = fetch_rdap_data(ip)
                if rdap_res:
                    result['ISP'] += f" [RDAP: {rdap_res}]"
                    result['RDAP'] = rdap_res # 🆕 RDAP列に値をセット

            result['Status'] = 'Success (API)'
            
            jp_isp, jp_country = get_jp_names(result['ISP'], country_code)
            proxy_type = detect_proxy_vpn_tor(ip, result['ISP'], tor_nodes)
            is_anonymous = (proxy_type != "Standard Connection")
            result['ISP_JP'] = jp_isp
            result['Proxy_Type'] = f"{proxy_type}" if is_anonymous else ""
            result['Country_JP'] = jp_country
            
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
        'Status': 'Success (Domain)',
        'RDAP': ''
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
        'Status': 'Success (簡易モード)',
        'RDAP': ''
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
            'Status': status_display
        })
    
    final_grouped_results.extend(non_aggregated_results)

    return final_grouped_results

# --- リアルタイム集計関数 ---
def summarize_in_realtime(raw_results):
    isp_counts = {}
    country_counts = {}
    country_code_counts = {}

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
        country_name = r.get('Country_JP', r.get('Country', 'N/A'))
        cc = r.get('CountryCode', 'N/A')
        
        if isp_name and isp_name not in ['N/A', 'N/A (簡易モード)']:
            isp_counts[isp_name] = isp_counts.get(isp_name, 0) + frequency
        
        if country_name and country_name != 'N/A':
            country_counts[country_name] = country_counts.get(country_name, 0) + frequency
            
        if cc and cc != 'N/A':
            country_code_counts[cc] = country_code_counts.get(cc, 0) + frequency

    # --- ISP集計 ---
    isp_full_df = pd.DataFrame(list(isp_counts.items()), columns=['ISP', 'Count'])
    isp_full_df = isp_full_df.sort_values('Count', ascending=False)
    
    if not isp_full_df.empty:
        isp_df = isp_full_df.head(10).copy()
        isp_df['ISP'] = isp_df['ISP'].str.wrap(25)
    else:
        isp_df = pd.DataFrame(columns=['ISP', 'Count'])

    # --- 国集計 ---
    country_full_df = pd.DataFrame(list(country_counts.items()), columns=['Country', 'Count'])
    country_full_df = country_full_df.sort_values('Count', ascending=False)

    if not country_full_df.empty:
        country_df = country_full_df.head(10).copy()
        country_df['Country'] = country_df['Country'].str.wrap(25)
    else:
        country_df = pd.DataFrame(columns=['Country', 'Count'])

    # ヒートマップ用
    if country_code_counts:
        map_data = []
        for cc, cnt in country_code_counts.items():
            num = COUNTRY_CODE_TO_NUMERIC_ISO.get(cc)
            if num is not None:
                name_for_map = COUNTRY_JP_NAME.get(cc, cc)
                map_data.append({
                    'NumericCode': int(num), 
                    'Count': int(cnt),
                    'Country': name_for_map
                })

        country_all_df_raw = pd.DataFrame(map_data).astype({
            'NumericCode': 'int64',
            'Count': 'int64'
        })
        
    st.session_state['debug_summary']['country_code_counts'] = country_code_counts
    st.session_state['debug_summary']['country_all_df'] = country_all_df_raw.to_dict('records')

    # --- ターゲット頻度集計 ---
    freq_map = st.session_state.get('target_freq_map', {})
    finished = st.session_state.get('finished_ips', set())
    freq_list = [{'Target_IP': t, 'Count': c} for t, c in freq_map.items() if t in finished]
    
    if freq_list:
        freq_full_df = pd.DataFrame(freq_list).sort_values('Count', ascending=False)
    else:
        freq_full_df = pd.DataFrame(columns=['Target_IP', 'Count'])
    
    if not freq_full_df.empty:
        freq_df = freq_full_df.head(10).copy()
    else:
        freq_df = pd.DataFrame(columns=['Target_IP', 'Count'])

    return isp_df, country_df, freq_df, country_all_df_raw, isp_full_df, country_full_df, freq_full_df

# --- 集計結果描画ヘルパー関数 ---
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

    # 共通チャート生成関数
    def create_labeled_bar_chart(df, x_field, y_field, title):
        base = alt.Chart(df).encode(
            x=alt.X(x_field, title='Count'),
            y=alt.Y(y_field, sort='-x', title=y_field),
            tooltip=[y_field, x_field]
        )
        bars = base.mark_bar()
        text = base.mark_text(
            align='left',
            baseline='middle',
            dx=3 
        ).encode(
            text=x_field
        )
        return (bars + text).properties(title=title).interactive()

    with col_freq:
        st.markdown("#### 🎯 対象IP別カウント (トップ10)")
        if not target_frequency_df.empty:
            st.caption(f"**集計対象ターゲット数 (重複なし):** {len(target_frequency_df)} 件")
            chart = create_labeled_bar_chart(target_frequency_df, 'Count', 'Target_IP', 'Target IP Counts')
            st.altair_chart(chart, use_container_width=True)

            target_frequency_df_display = target_frequency_df.copy()
            target_frequency_df_display['Target_IP'] = target_frequency_df_display['Target_IP'].str.wrap(25)
            st.dataframe(target_frequency_df_display, hide_index=True, use_container_width=True)
        else:
            st.info("データがありません")
            
    with col_isp:
        st.markdown("#### 🏢 ISP別カウント (トップ10)")
        if not isp_summary_df.empty:
            chart = create_labeled_bar_chart(isp_summary_df, 'Count', 'ISP', 'ISP Counts')
            st.altair_chart(chart, use_container_width=True)
            
            st.dataframe(isp_summary_df, hide_index=True, use_container_width=True)
        else:
            st.info("データがありません")
            
    with col_country:
        st.markdown("#### 🌍 国別カウント (トップ10)")
        if not country_summary_df.empty:
            chart = create_labeled_bar_chart(country_summary_df, 'Count', 'Country', 'Country Counts')
            st.altair_chart(chart, use_container_width=True)
            
            st.dataframe(country_summary_df, hide_index=True, use_container_width=True)
        else:
            st.info("データがありません")

# 💡 HTMLレポート生成関数
def generate_full_report_html(isp_full_df, country_full_df, freq_full_df):
    
    def create_chunked_chart_specs(df, x_col, y_col, title_base, chunk_size=50):
        specs = []
        # データ全体での最大値を取得 (ページまたぎのスケール統一のため)
        global_max = df[x_col].max() if not df.empty else 0

        # データフレームを分割
        chunks = [df[i:i + chunk_size] for i in range(0, df.shape[0], chunk_size)]
        
        for i, chunk in enumerate(chunks):
            chart_title = f"{title_base} ({i+1}/{len(chunks)})" if len(chunks) > 1 else title_base
            
            # 数値ラベル付きチャート
            # 💡 x軸のスケールを全体最大値で固定する
            base = alt.Chart(chunk).encode(
                x=alt.X(x_col, title='Count', scale=alt.Scale(domain=[0, global_max])),
                y=alt.Y(y_col, sort='-x', title=y_col),
                tooltip=[y_col, x_col]
            )
            bars = base.mark_bar()
            text = base.mark_text(
                align='left',
                baseline='middle',
                dx=5, 
                fontSize=11,
                fontWeight='bold'
            ).encode(
                text=x_col
            )
            chart = (bars + text).properties(
                title=chart_title,
                width=700,
                height=alt.Step(20) 
            )
            specs.append(chart.to_dict())
        return specs

    # 各カテゴリのチャートスペックを生成
    target_specs = create_chunked_chart_specs(freq_full_df, 'Count', 'Target_IP', 'Target IP Counts (All)')
    isp_specs = create_chunked_chart_specs(isp_full_df, 'Count', 'ISP', 'ISP Counts (All)')
    country_specs = create_chunked_chart_specs(country_full_df, 'Count', 'Country', 'Country Counts (All)')

    # HTMLテンプレート
    html_template = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <title>Whois Search Full Report</title>
      <script src="https://cdn.jsdelivr.net/npm/vega@5"></script>
      <script src="https://cdn.jsdelivr.net/npm/vega-lite@5"></script>
      <script src="https://cdn.jsdelivr.net/npm/vega-embed@6"></script>
      <style>
        body {{ font-family: "Helvetica Neue", Arial, sans-serif; padding: 40px; background-color: #fff; color: #333; }}
        h1 {{ text-align: center; border-bottom: 2px solid #333; padding-bottom: 10px; margin-bottom: 30px; }}
        h2 {{ 
            color: #1e3a8a; 
            margin-top: 50px; 
            border-left: 5px solid #1e3a8a; 
            padding-left: 15px; 
            page-break-before: always; 
        }}
        h2:first-of-type {{ page-break-before: auto; }} 
        
        .chart-container {{ 
            margin-bottom: 40px; 
            padding: 10px; 
            page-break-inside: avoid; 
        }}
        
        @media print {{
            body {{ padding: 0; background-color: #fff; }}
            .no-print {{ display: none; }}
            h2 {{ margin-top: 20px; }}
        }}
      </style>
    </head>
    <body>
      <h1>Whois検索結果分析レポート</h1>
      <p style="text-align: center; color: #666;">Generated by Whois Search Tool</p>

      <h2>対象IPアドレス カウント (全 {len(freq_full_df)} 件)</h2>
      <div id="target_charts"></div>

      <h2>ISP別 カウント (全 {len(isp_full_df)} 件)</h2>
      <div id="isp_charts"></div>

      <h2>国別 カウント (全 {len(country_full_df)} 件)</h2>
      <div id="country_charts"></div>

      <script type="text/javascript">
        // Embed charts function
        function embedCharts(containerId, specs) {{
            const container = document.getElementById(containerId);
            specs.forEach((spec, index) => {{
                const div = document.createElement('div');
                div.id = containerId + '_' + index;
                div.className = 'chart-container';
                container.appendChild(div);
                vegaEmbed('#' + div.id, spec, {{actions: false}});
            }});
        }}

        // Data from Python (Serialized to JSON)
        const targetSpecs = {json.dumps(target_specs)};
        const ispSpecs = {json.dumps(isp_specs)};
        const countrySpecs = {json.dumps(country_specs)};

        // Render
        if (targetSpecs.length > 0) embedCharts('target_charts', targetSpecs);
        else document.getElementById('target_charts').innerHTML = '<p>データなし</p>';

        if (ispSpecs.length > 0) embedCharts('isp_charts', ispSpecs);
        else document.getElementById('isp_charts').innerHTML = '<p>データなし</p>';

        if (countrySpecs.length > 0) embedCharts('country_charts', countrySpecs);
        else document.getElementById('country_charts').innerHTML = '<p>データなし</p>';
      </script>
    </body>
    </html>
    """
    return html_template

# 📈 クロス分析用HTMLレポート生成関数
def generate_cross_analysis_html(chart_spec, x_col, group_col):
    html_template = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <title>Whois Cross Analysis Report</title>
      <script src="https://cdn.jsdelivr.net/npm/vega@5"></script>
      <script src="https://cdn.jsdelivr.net/npm/vega-lite@5"></script>
      <script src="https://cdn.jsdelivr.net/npm/vega-embed@6"></script>
      <style>
        body {{ font-family: "Helvetica Neue", Arial, sans-serif; padding: 40px; background-color: #fff; color: #333; }}
        h1 {{ text-align: center; border-bottom: 2px solid #333; padding-bottom: 10px; margin-bottom: 30px; }}
        .info {{ text-align: center; color: #666; margin-bottom: 20px; }}
        .chart-container {{ 
            width: 100%; 
            display: flex; 
            justify-content: center; 
            margin-bottom: 40px; 
            padding: 10px; 
        }}
      </style>
    </head>
    <body>
      <h1>クロス分析レポート: {x_col} vs {group_col}</h1>
      <p class="info">Generated by Whois Search Tool</p>

      <div id="chart" class="chart-container"></div>

      <script type="text/javascript">
        const spec = {json.dumps(chart_spec)};
        vegaEmbed('#chart', spec, {{actions: true}});
      </script>
    </body>
    </html>
    """
    return html_template

# --- Excel生成ヘルパー関数 ---
def convert_df_to_excel(df):
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Sheet1')
    return output.getvalue()

# --- Advanced Excel Generator (Pivot & Chart) ---
def create_advanced_excel(df, time_col_name=None):
    """
    1. Raw Data
    2. Report_ISP_Volume: ISP Ranking (Bar Chart)
    3. Report_ISP_Risk: ISP x ProxyType (Stacked Bar)
    4. Report_Time_Volume: Hour Trend (Bar/Line) [if time_col available]
    5. Report_Time_Risk: Hour x ProxyType (Stacked Bar) [if time_col available]
    """
    output = io.BytesIO()
    
    # 1. データ前処理
    if 'Proxy Type' in df.columns:
        df['Proxy Type'] = df['Proxy Type'].fillna('Standard Connection')
        df['Proxy Type'] = df['Proxy Type'].replace('', 'Standard Connection')
        # 古い用語が残っている場合の念の為の置換
        df['Proxy Type'] = df['Proxy Type'].replace('Residential/Normal', 'Standard Connection')
        df['Proxy Type'] = df['Proxy Type'].replace('Residential/General', 'Standard Connection')
        df['Proxy Type'] = df['Proxy Type'].replace('Residential/Business', 'Standard Connection')
        df['Proxy Type'] = df['Proxy Type'].replace('nan', 'Standard Connection')
    else:
        df['Proxy Type'] = 'Standard Connection'
    
    # 時間帯列の作成
    has_time_analysis = False
    if time_col_name and time_col_name in df.columns:
        try:
            df['Hour'] = pd.to_datetime(df[time_col_name], errors='coerce').dt.hour
            has_time_analysis = True
        except Exception:
            pass

    # カウント用の列（最初の列を使う）
    count_col = df.columns[0]

    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        # Sheet 1: Raw Data
        df.to_excel(writer, index=False, sheet_name='Raw Data')
        wb = writer.book
        
        # --- 共通チャート作成関数 (解説文付き) ---
        def add_chart_sheet(pivot_df, sheet_name, chart_title, x_title, y_title, description, chart_type="col", stacked=False):
            if pivot_df.empty: return

            # Sheet作成とデータ書き込み (ヘッダー用に少し下げる)
            pivot_df.to_excel(writer, sheet_name=sheet_name, startrow=4)
            ws = wb[sheet_name]
            
            # --- 解説文の挿入 ---
            ws['A1'] = chart_title
            ws['A1'].font = Font(size=14, bold=True, color="1E3A8A")
            
            ws['A2'] = description
            ws['A2'].font = Font(size=11, color="555555", italic=True)
            ws['A2'].alignment = Alignment(wrap_text=True, vertical="top")
            
            # セル結合 (説明文エリア)
            ws.merge_cells('A2:H3')
            
            # 印刷設定（横向き）
            ws.page_setup.orientation = ws.ORIENTATION_LANDSCAPE
            ws.page_setup.fitToWidth = 1
            ws.print_options.horizontalCentered = True
            
            # --- グラフ作成  ---
            chart = BarChart()
            chart.type = chart_type
            chart.style = 10 # カラフルなスタイル
            chart.title = chart_title
            chart.height = 15 # 高さを確保
            chart.width = 25  # 幅を確保

            # 凡例を下に配置
            chart.legend.position = 'b'

            if stacked:
                chart.grouping = "stacked"
                chart.overlap = 100
            else:
                # 積み上げでない場合は、単一系列でも色を変えて見やすくする
                chart.varyColors = True

            # データラベルの設定 (値を表示 + 位置を外側上 'outEnd' に)
            # ※ 積み上げの場合は内側、それ以外は外側が見やすい
            chart.dataLabels = DataLabelList()
            chart.dataLabels.showVal = True
            chart.dataLabels.showCatName = False
            chart.dataLabels.showSerName = False
            chart.dataLabels.showPercent = False
            if not stacked:
                chart.dataLabels.position = 'outEnd'
            
            # 軸と目盛り線の設定
            chart.x_axis.title = x_title
            chart.y_axis.title = y_title
            chart.y_axis.majorGridlines = ChartLines() # 目盛り線を表示
            
            # 縦軸の目盛ラベル（数値）を確実に表示・整形する設定
            chart.y_axis.delete = False        
            chart.y_axis.numFmt = '0'          # 整数表示
            chart.y_axis.majorTickMark = 'out' # 目盛りを外側に出す
            chart.y_axis.tickLblPos = 'nextTo' # 数値を軸の隣に配置

            # レイアウトを手動設定して余白を作る (重なり防止 + スカスカ解消)
            # x=0.03 (左寄せ), y=0.05 (上余白), h=0.75 (高さ確保), w=0.85 (右余白確保)
            chart.layout = Layout(
                manualLayout=ManualLayout(
                    x=0.03, y=0.05, 
                    h=0.75, w=0.85, 
                )
            )

            # データ範囲設定
            data_start_row = 5 
            data_end_row = data_start_row + len(pivot_df)
            
            data = Reference(ws, min_col=2, min_row=data_start_row, max_row=data_end_row, max_col=len(pivot_df.columns)+1)
            cats = Reference(ws, min_col=1, min_row=data_start_row+1, max_row=data_end_row)
            
            chart.add_data(data, titles_from_data=True)
            chart.set_categories(cats)
            
            # グラフ配置 (データの下ではなく横に配置して見やすく)
            ws.add_chart(chart, "E5")

        # ---------------------------------------------------------
        # 2. Report_ISP_Volume: [ISP_JP] x [Count]
        # ---------------------------------------------------------
        top_isps = df['ISP_JP'].value_counts().head(20).index
        df_isp = df[df['ISP_JP'].isin(top_isps)]
        pivot_isp_vol = df_isp.pivot_table(
            index='ISP_JP', 
            values=count_col, 
            aggfunc='count'
        ).sort_values(count_col, ascending=False)
        
        desc_isp_vol = "どのプロバイダからのアクセスが最も多いかを可視化しています。特定のISPからのアクセス集中は、そのサービスの利用者層または特定のキャンペーンの影響を示唆します。"
        add_chart_sheet(pivot_isp_vol, 'Report_ISP_Volume', 'ISP Access Volume Ranking (Top 20)', 'Internet Service Provider', 'Access Count (件数)', desc_isp_vol)

        # ---------------------------------------------------------
        # 3. Report_ISP_Risk: [ISP_JP] x [Proxy Type]
        # ---------------------------------------------------------
        pivot_isp_risk = df_isp.pivot_table(
            index='ISP_JP', 
            columns='Proxy Type', 
            values=count_col, 
            aggfunc='count', 
            fill_value=0
        )
        desc_isp_risk = "そのISPが安全な一般回線か、注意が必要なサーバー/VPN経由かを判定しています。「Standard Connection」は一般的な安全な接続です。「Hosting」や「VPN」が多い場合は機械的なアクセスの可能性があります。"
        add_chart_sheet(pivot_isp_risk, 'Report_ISP_Risk', 'Risk Analysis by ISP (Top 20)', 'Internet Service Provider', 'Access Count (件数)', desc_isp_risk, stacked=True)
        
        # ---------------------------------------------------------
        # 4. Report_Country: [Country_JP] x [Count] (Bonus)
        # ---------------------------------------------------------
        pivot_country = df.pivot_table(
            index='Country_JP',
            values=count_col,
            aggfunc='count'
        ).sort_values(count_col, ascending=False).head(15)
        desc_country = "国ごとのアクセス数をランキング化しています。サービス提供エリア外からの予期せぬアクセス検知や、海外からの攻撃予兆の発見に役立ちます。"
        add_chart_sheet(pivot_country, 'Report_Country', 'Country Access Volume (Top 15)', 'Country Name', 'Access Count (件数)', desc_country)

        # ---------------------------------------------------------
        # 5. Time Analysis (if available)
        # ---------------------------------------------------------
        if has_time_analysis:
            # Report_Time_Volume: [Hour] x [Count]
            pivot_time_vol = df.pivot_table(
                index='Hour',
                values=count_col,
                aggfunc='count',
                fill_value=0
            ).reindex(range(24), fill_value=0)
            desc_time_vol = "何時にアクセスが集中しているかを可視化しています。一般的なユーザーは活動時間帯に、Botなどは深夜早朝や24時間一定のアクセスを行う傾向があります。"
            add_chart_sheet(pivot_time_vol, 'Report_Time_Volume', 'Hourly Access Trend', 'Time of Day (0-23h)', 'Access Count (件数)', desc_time_vol)

            # Report_Time_Risk: [Hour] x [Proxy Type]
            pivot_time_risk = df.pivot_table(
                index='Hour',
                columns='Proxy Type',
                values=count_col,
                aggfunc='count',
                fill_value=0
            ).reindex(range(24), fill_value=0)
            desc_time_risk = "深夜帯などに怪しいアクセス（Hosting/VPN等）が増えていないかを確認できます。夜間にHosting判定が増加する場合、Botによる自動巡回の可能性があります。"
            add_chart_sheet(pivot_time_risk, 'Report_Time_Risk', 'Hourly Risk Trend', 'Time of Day (0-23h)', 'Access Count (件数)', desc_time_risk, stacked=True)
            
    return output.getvalue()

def display_results(results, current_mode_full_text, display_mode):
    st.markdown("### 📝 検索結果")

    # --- ⬇️ ツール解説ガイド (Expander) ---
    with st.expander("ℹ️ リンク集の活用ガイド (表示条件と特徴)"):
        st.markdown("""
        ターゲットの種類（IPv4 / IPv6 / ドメイン）に応じて、最適なツールのみが自動で表示されます。
        
        | 目的 | 推奨ツール | 表示条件 | 特徴 |
        | :--- | :--- | :--- | :--- |
        | 🛡️ **安全性を診断** | **VirusTotal** | `v4` `v6` `Dom` | 世界中のウイルス対策エンジンで一括スキャン。危険なIPか即座に判別。 |
        | 🇯🇵 **国内調査・詳細** | **Aguse** | `v4` `Dom` | 日本語表示。ブラックリスト判定や、サーバー証明書情報が見やすい。 |
        | 📍 **場所・回線特定** | **ipinfo.io** | `v4` `v6` | 地図上の位置、ホスティング(クラウド)かどうかの詳細判定に強い。 |
        | 🕵️ **VPN/Proxy判定** | **IP2Proxy** | `v4` `v6` | 匿名プロキシやVPNからのアクセスかどうかを専門的に判定。 |
        | 🗺️ **地図表示** | **IP Location** | `v4` `v6` | IPアドレスの地理的位置をGoogleマップ等で視覚的に表示。 |
        | 📝 **登録者情報** | **Whois.com** | `Dom` | ドメインの所有者情報（英語）を確認するのに最適。IP検索時は非表示。 |
        | 📡 **伝播確認** | **DNS Checker** | `v6` | IPv6のWhois情報が世界中でどう見えているかを確認。 |
        | 📚 **公式情報** | **CP-WHOIS** | `ALL` | 利用者認証が必要な検索ツール。ここでの検索結果はデータとして信頼性が高い。 |
        
        <small>※ `v4`: IPv4アドレス, `v6`: IPv6アドレス, `Dom`: ドメイン名, `ALL`: 全て</small>
        """, unsafe_allow_html=True)
    # ----------------------------------------------------

    with st.expander("⚠️ 判定アイコンと表示ルールについて"):
        st.info("""
        ### 🔍 判定ロジックの概要
        本ツールは、IPアドレスに紐付けられた**ASN（Autonomous System Number）およびISP（インターネットサービスプロバイダ）の名称・属性**を解析し、通信主体のネットワーク種別を自動的に分類しています。
        
        インターネット上の通信は、その用途に応じて「個人宅・法人拠点からの直接接続」と「非対面的な中継・ホスティング経由の接続」に大別されます。本機能は後者を検知し、調査の優先順位判断を支援することを目的としています。
        
        ---
        
        ### 📌 判定種別の定義と技術的背景
        
        - **⚠️ [Tor Node]**
            - **定義**: Tor（The Onion Router）ネットワークにおける「Exit Node（出口ノード）」を指します。
            - **背景**: 起動時にTor Project公式サイトより最新のノードリストを取得し、照合を行っています。高い匿名性を維持した通信であるため、セキュリティリスクの検討が必要です。
            
        - **⚠️ [VPN/Proxy]**
            - **定義**: 商用VPNサービス、公開プロキシ、またはプライバシー保護を目的とした中継団体に属するIPです。
            - **背景**: ISP名称に含まれる特定のキーワード（VPN, Proxy等）および既知の匿名化サービス運営組織名に基づき判別します。
            
        - **⚠️ [Hosting/Infra]**
            - **定義**: クラウドサービス（AWS, Azure, GCP等）や、データセンター、ホスティング事業者のインフラストラクチャです。
            - **背景**: 一般的なコンシューマ回線とは異なり、サーバー間通信やBot、クローラー、あるいは攻撃用インフラとして利用されるケースが多いノードです。
            
        ---
        
        ※ 本判定はISP名称等に基づく推論であるため、実際の利用状況と異なる場合があります。
        """)
    
    col_widths = [0.5, 1.5, 1.2, 2.0, 1.5, 1.5, 1.0, 1.2, 0.5] 
    h_cols = st.columns(col_widths)
    headers = ["No.", "Target IP", "国名","ISP(日本語)", "RIR Link", "Security Links", "Proxy Type",  "Status", "✅"]
    for col, name in zip(h_cols, headers):
        col.markdown(f"**{name}**")
    st.markdown("<hr style='margin: 0px 0px 10px 0px;'>", unsafe_allow_html=True)

    with st.container(height=800):
        if not results:
            st.info("検索結果がここに表示されます。")
            return

        for idx, res in enumerate(results):
                row_cols = st.columns(col_widths)
                row_cols[0].write(f"**{idx+1}**")
                
                target_ip = res.get('Target_IP', 'N/A')
                row_cols[1].markdown(f"`{target_ip}`")
                
                c_jp = res.get('Country_JP', 'N/A')
                c_en = res.get('Country', 'N/A')
                row_cols[2].write(f"{c_jp}\n({c_en})")
                
                isp_display = res.get('ISP_JP', res.get('ISP', 'N/A'))
                row_cols[3].write(isp_display)
                
                rir_link = res.get('RIR_Link', 'N/A')
                with row_cols[4]:
                    st.write(rir_link)
                    clean_ip = get_copy_target(target_ip)
                    st.code(clean_ip, language=None)
                
                row_cols[5].write(res.get('Secondary_Security_Links', 'N/A'))
                hosting_val = res.get('Proxy_Type', '')
                row_cols[6].write(hosting_val)          
                
                status_val = res.get('Status', 'N/A')
                if "Success" in status_val:
                    row_cols[7].markdown(f"<span style='color:green;'>{status_val}</span>", unsafe_allow_html=True)
                else:
                    row_cols[7].write(status_val)
                    
                row_cols[8].checkbox("選択", key=f"chk_{get_copy_target(target_ip)}_{idx}", label_visibility="collapsed")

# 📊 元データ結合分析機能
def render_merged_analysis(df_merged):
    st.markdown("### 📈 元データ x 検索結果 クロス分析")
    st.info("アップロードされたファイルの元の列と、検索で得られたWhois情報を組み合わせて可視化します。印刷用にグラフ単体のダウンロードも可能です。")
    
    # グラフ設定用カラム
    # 元データのカラム（Statusなど後付けのカラムを除く）
    original_cols = [c for c in df_merged.columns if c not in ['ISP', 'ISP_JP', 'Country', 'Country_JP', 'Proxy Type', 'Status']]
    # Whois結果のカラム
    whois_cols = ['Country_JP', 'ISP_JP', 'Proxy Type', 'Status']
    
    col_x, col_grp, col_chart_type = st.columns(3)
    
    with col_x:
        x_col = st.selectbox("X軸 (カテゴリ/元の列)", original_cols + whois_cols, index=0)
    
    with col_grp:
        group_col = st.selectbox("積み上げ/色分け (Whois情報など)", ['(なし)'] + whois_cols + original_cols, index=1)
        
    with col_chart_type:
        chart_type = st.radio("グラフタイプ", ["バーチャート (集計)", "ヒートマップ"], horizontal=True)

    if not df_merged.empty:
        chart = None
        
        # データ前処理: NaNを文字列に置換してAltairのエラー回避
        chart_df = df_merged.fillna("N/A").astype(str)

        if chart_type == "バーチャート (集計)":
            if group_col != '(なし)':
                chart = alt.Chart(chart_df).mark_bar().encode(
                    x=alt.X(x_col, title=x_col),
                    y=alt.Y('count()', title='件数'),
                    color=alt.Color(group_col, title=group_col),
                    tooltip=[x_col, group_col, 'count()']
                ).properties(height=400)
            else:
                chart = alt.Chart(chart_df).mark_bar().encode(
                    x=alt.X(x_col, title=x_col),
                    y=alt.Y('count()', title='件数'),
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
            st.altair_chart(chart, use_container_width=True)
            
            # HTMLダウンロード用
            chart_json = chart.to_dict()
            html_content = generate_cross_analysis_html(chart_json, x_col, group_col if group_col != '(なし)' else 'Count')
            
            st.download_button(
                label="⬇️ クロス分析レポート(HTML)をダウンロード",
                data=html_content,
                file_name=f"cross_analysis_{x_col}_vs_{group_col}.html",
                mime="text/html",
                help="グラフをブラウザで全画面表示し、印刷するのに適しています。"
            )


# --- メイン処理 ---
def main():
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

    tor_nodes = fetch_tor_exit_nodes()
    
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
        # 🆕 Proモード設定 (APIキー入力)
        st.markdown("#### 🔑 Pro Mode (Optional)")
        pro_api_key = st.text_input("ipinfo.io API Key", type="password", help="入力するとipinfo.ioの高精度データベースを使用します。空欄の場合はip-api.com(無料)を使用します。").strip()
        
        st.markdown("---")
        if st.button("🔄 IPキャッシュクリア", help="キャッシュが古くなった場合にクリック"):
            st.session_state['cidr_cache'] = {} 
            st.info("IP/CIDRキャッシュをクリアしました。")
            st.rerun()

    if selected_menu == "仕様・解説":
        st.title("📖 マニュアル & ガイド")
        
        # 🆕 タブで情報を整理して見やすくする
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
            - **🔍 高精度モード (RDAP)**
                - `ip-api.com` (無料版) の情報に加え、各地域の**公式レジストリ(RDAP)** にも問い合わせを行います。
                - **メリット**: 「運用者(ISP)」だけでなく「法的な保有組織(Org)」まで特定できる確率が上がります。
                - **デメリット**: 通信回数が増えるため、検索スピードが大幅に低下します。徹底的に裏取りをしたい場合のみONにしてください。
            
            - **🔑 Pro Mode (API Key)**
                - サイドバーに `ipinfo.io` のAPIキーを入力すると自動で有効になります。
                - **メリット**: VPN/Proxy/Hostingの判定精度が劇的に向上し、企業名の特定精度も高まります。
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
            pip install streamlit pandas requests streamlit-option-menu altair openpyxl
            ```
            
            **3. アプリの起動**
            コマンドプロンプトまたはターミナルで以下を実行します。
            ```bash
            streamlit run WhoisAppxxxx.py
            ```
            これでブラウザが立ち上がり、**「🏠 Local Private Edition」** としてExcelアップロード機能などが解放された状態で起動します。
            """)
 
        with tab2:
            st.markdown("""
            #### 1. データソース
            - **IP Geolocation / ISP 情報**: 
                - 無料版: `ip-api.com` (毎分45リクエスト制限)
                - Pro版: `ipinfo.io` (APIキーに基づく制限)
            - **Whois (RDAP)**: APNIC等の各地域レジストリ公式サーバー
            - **Tor出口ノード**: Tor Project公式サイトより起動時に最新リストを取得

            #### 2. ハイブリッド検索の仕組み (API vs RDAP)
            - **API (ip-api/ipinfo)**: 
                - **役割**: 「今、誰がそのIPを運用しているか？」(Service Provider) を答えます。
                - **特徴**: 高速で、CloudflareやAmazonなどのサービス名が表示されやすいです。
            - **RDAP (公式台帳)**: 
                - **役割**: 「そのIPアドレス(土地)の法的な持ち主は誰か？」(Registry Owner) を答えます。
                - **特徴**: 正確ですが、APNIC-LABSなどの組織名が表示されることがあります。
            - **メリット**: この2つを見比べることで、「運用の委託関係」や「インフラの裏側」が見えてきます。

            #### 3. 技術的仕様
            - **並列処理**: マルチスレッドによる高速検索（APIレートリミット自動調整機能付き）
            - **CIDRキャッシュ**: 同一ネットワーク帯域（/24など）への重複リクエストを回避し、高速化
            """)
            
            st.markdown("#### 4. 判定ステータスの意味")
            st.warning("⚠️ **Hosting/VPN/Proxy**")
            st.markdown("データセンター、VPNサービス、プロキシサーバー経由の通信です。一般家庭からのアクセスではなく、ボットや匿名化ツールを使用している可能性があります。")
            st.error("⚠️ **Tor Node**")
            st.markdown("Tor匿名化ネットワークの出口ノードです。攻撃の前兆や、高い匿名性を必要とする通信の可能性があります。")

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
            A. APIの制限（レートリミット）にかかった可能性があります。ツールは自動的に待機して再開しますが、大量（数千件）の検索を行う場合は時間がかかります。「待機中」の表示が出ている場合はそのままお待ちください。

            **Q. ipinfoのAPIキーはどこで手に入りますか？**\n
            A. [ipinfo.io](https://ipinfo.io/signup) から無料で登録・取得できます（無料枠あり）。

            **Q. ISP名と [RDAP: 〇〇] の名前が違うのですが？**\n
            A. **それは「運用者」と「持ち主」の違いです。** 例えば `1.1.1.1` というIPアドレスの場合：
            * **ISP (API)**: `Cloudflare, Inc.` (DNSサービスを提供している運用者)
            * **RDAP (台帳)**: `APNIC-LABS` (IPアドレスブロックを保有している研究組織)
            このように表示されるのはバグではなく、このツールの「高精度モード」が、**IPアドレスの「表の運用者」と「裏の所有者」の両方を正しく表している証拠**です。
            
            **Q. ISP名とRDAPの名前が異なる場合、発信者情報開示をどちらに請求すればいいでしょうか？**\n
            A. 個人（契約者）の情報を持っているのは**表の運用者である「ISP / プロバイダ」**の方です。RDAPの情報はあくまで「そのIPアドレスブロックを管理している組織」の情報であり、実際の利用者情報は持っていないことが多いです。発信者情報開示請求を行う場合は、**ISP名を使って手続きを行ってください**。
            """)
        return

    # --- メインコンテンツ：Whois検索タブ ---   
    # 🆕 モード表示ロジック
    if IS_PUBLIC_MODE:
        mode_title = "☁️ Public Cloud Edition (機能制限あり)"
        mode_color = "gray"
    else:
        mode_title = "🏠 Local Private Edition (フル機能版)"
        mode_color = "green"

    st.title("🌐 検索大臣 - Whois & IP Intelligence -")
    st.markdown(f"**Current Mode:** <span style='color:{mode_color}; font-weight:bold;'>{mode_title}</span>", unsafe_allow_html=True)
    col_input1, col_input2 = st.columns([1, 1])

    with col_input1:
        manual_input = st.text_area(
            "📋 テキスト入力 (IP/ドメイン)",
            height=150,
            placeholder="8.8.8.8\nexample.com\n2404:6800:..."
        )

    with col_input2:
        # --- モードによるアップロード制限の切り替え ---
        if IS_PUBLIC_MODE:
            # 公開モード (st版の挙動): txtのみ許可、警告あり
            allowed_types = ['txt']
            label_text = "📂 IPリストをアップロード (.txtのみ)"
            help_text = "※ 1行に1つのターゲットを記載"
        else:
            # ローカルモード (my版の挙動): csv/excel許可
            allowed_types = ['txt', 'csv', 'xlsx', 'xls']
            label_text = "📂 リストをアップロード (txt/csv/xlsx)"
            help_text = "※ 1行に1つのターゲットを記載、またはCSV/ExcelのIP列を自動検出します"

        uploaded_file = st.file_uploader(label_text, type=allowed_types)
        st.caption(help_text)
        
        raw_targets = []
        df_orig = None # 初期化

        if manual_input:
            raw_targets.extend(manual_input.splitlines())
        
        if uploaded_file:
            # --- 公開モードの場合の読み込み処理 (st版ロジック) ---
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
            
            # --- ローカルモードの場合の読み込み処理 (my版ロジック) ---
            else:
                ip_col = None
                try:
                    if uploaded_file.name.endswith('.csv'):
                        df_orig = pd.read_csv(uploaded_file)
                    elif uploaded_file.name.endswith(('.xlsx', '.xls')):
                        df_orig = pd.read_excel(uploaded_file)
                    else:
                        # TXTファイル
                        raw_targets.extend(uploaded_file.read().decode("utf-8").splitlines())
                        st.session_state['original_df'] = None
                        st.session_state['ip_column_name'] = None

                    if df_orig is not None:
                        st.session_state['original_df'] = df_orig
                        for col in df_orig.columns:
                            sample = df_orig[col].dropna().head(10).astype(str)
                            if any(is_valid_ip(val.strip()) for val in sample):
                                ip_col = col
                                break
                        
                        if ip_col:
                            st.session_state['ip_column_name'] = ip_col
                            raw_targets.extend(df_orig[ip_col].dropna().astype(str).tolist())
                            
                            # --- 新機能：アップロードデータのプレビュー ---
                            st.info(f"📄 ファイル読み込み完了: {len(df_orig)} 行 / IP列: `{ip_col}`")
                            with st.expander("👀 アップロードデータ・プレビュー", expanded=False):
                                st.dataframe(df_orig)
                            # ---------------------------------------------
                        else:
                            st.error("ファイル内にIPアドレスの列が見つかりませんでした。")

                except Exception as e:
                    st.error(f"ファイル読み込みエラー: {e}")

    # --- 公開モード時のみセキュリティ警告を表示 ---
    if IS_PUBLIC_MODE:
        st.warning("""
        **🛡️ セキュリティ上の注意**
        * **テキスト入力推奨**: ファイルアップロードよりも、左側のテキストエリアへの**コピー＆ペースト**の方が、メタデータ（作成者情報など）が含まれないため安全です。
        * **ファイル名に注意**: アップロードする場合は、ファイル名に機密情報（例: `ClientA_Log.txt`）を含めず、`list.txt` などの無機質な名前を使用してください。
        """)
    
    cleaned_raw_targets_list = []
    target_freq_counts = {}

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
        st.session_state['original_input_list'] = cleaned_raw_targets_list
    ip_targets = [t for t in targets if is_valid_ip(t)]
    domain_targets = [t for t in targets if not is_valid_ip(t)]
    ipv6_count = sum(1 for t in ip_targets if not is_ipv4(t))
    ipv4_count = len(ip_targets) - ipv6_count

    st.markdown("---")
    st.markdown("### ⚙️ 検索表示設定")
    
    col_set1, col_set2 = st.columns(2)
    with col_set1:
        display_mode = st.radio(
            "**表示モード:** (検索結果の表示形式とAPI使用有無を設定)",
            ("標準モード", "集約モード (IPv4 Group)", "簡易モード (APIなし)"),
            key="display_mode_radio",
            horizontal=False
        )
    
    with col_set2:
        api_mode_selection = st.radio(
            "**API 処理モード:** (速度と安定性のトレードオフ)",
            list(MODE_SETTINGS.keys()),
            key="api_mode_radio",
            horizontal=False
        )
        # RDAPオプション
        use_rdap_option = st.checkbox("🔍 高精度モード (RDAP公式台帳の併用 - 低速)", value=False, help="無料APIのISP情報に加え、RDAP(公式台帳)から最新のネットワーク名を取得します。通信が増えるため処理が遅くなります。")
    
    selected_settings = MODE_SETTINGS[api_mode_selection]
    max_workers = selected_settings["MAX_WORKERS"]
    delay_between_requests = selected_settings["DELAY_BETWEEN_REQUESTS"]
    rate_limit_wait_seconds = RATE_LIMIT_WAIT_SECONDS

    mode_mapping = {
        "標準モード": "標準モード (1ターゲット = 1行)",
        "集約モード (IPv4 Group)": "集約モード (IPv4アドレスをISP/国別でグループ化)",
        "簡易モード (APIなし)": "簡易モード (APIなし - セキュリティリンクのみ)"
    }
    current_mode_full_text = mode_mapping[display_mode]

    st.markdown("---")
    col_act1, col_act2 = st.columns([3, 1])

    is_currently_searching = st.session_state.is_searching and not st.session_state.cancel_search
    
    total_ip_targets_for_display = len(ip_targets) + len(st.session_state.deferred_ips)

    with col_act1:
        st.success(f"**Target:** IPv4: {ipv4_count} / IPv6: {ipv6_count} / Domain: {len(domain_targets)} (Pending: {len(st.session_state.deferred_ips)}) / **CIDR Cache:** {len(st.session_state.cidr_cache)}")
        if pro_api_key:
            st.info("🔑 **Pro Mode Active:** ipinfo.io データベースを使用します")

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
                    st.session_state.raw_results.extend([get_domain_details(d) for d in domain_targets])
                    st.session_state.finished_ips.update(domain_targets)
                    
                prog_bar_container = st.empty()
                status_text_container = st.empty()
                summary_container = st.empty() 

                if immediate_ip_queue:
                    cidr_cache_snapshot = st.session_state.cidr_cache.copy() 
                    
                    with ThreadPoolExecutor(max_workers=max_workers) as executor:
                        future_to_ip = {
                            executor.submit(
                                get_ip_details_from_api, 
                                ip, 
                                cidr_cache_snapshot, 
                                delay_between_requests, 
                                rate_limit_wait_seconds,
                                tor_nodes,
                                use_rdap_option, # RDAPオプションを渡す
                                pro_api_key # APIキーを渡す
                            ): ip for ip in immediate_ip_queue
                        }
                        remaining = set(future_to_ip.keys())
                        
                        while remaining and not st.session_state.cancel_search:
                            done, remaining = wait(remaining, timeout=0.1, return_when=FIRST_COMPLETED)
                            
                            for f in done:
                                res_tuple = f.result()
                                res = res_tuple[0]
                                new_cache_entry = res_tuple[1]
                                ip = res['Target_IP']
                                
                                if new_cache_entry:
                                    st.session_state.cidr_cache.update(new_cache_entry)
                                
                                if res.get('Status', '').startswith('Success'):
                                    st.session_state.raw_results.append(res)
                                    st.session_state.finished_ips.add(ip)
                                elif res.get('Defer_Until'):
                                    st.session_state.deferred_ips[ip] = res['Defer_Until']
                                else:
                                    st.session_state.raw_results.append(res)
                                    st.session_state.finished_ips.add(ip)

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
                                
                                isp_df, country_df, freq_df, country_all_df, isp_full_df, country_full_df, freq_full_df = summarize_in_realtime(st.session_state.raw_results)
                                with summary_container.container():
                                    st.markdown("---")
                                    draw_summary_content(isp_df, country_df, freq_df, country_all_df, "📊 Real-time analysis")
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

        display_results(display_res, current_mode_full_text, display_mode)
        
        if not st.session_state.is_searching or st.session_state.cancel_search:
            isp_df, country_df, freq_df, country_all_df, isp_full_df, country_full_df, freq_full_df = summarize_in_realtime(st.session_state.raw_results)
            
            st.markdown("---")
            draw_summary_content(isp_df, country_df, freq_df, country_all_df, "✅ 集計結果")

            # --- 元データ結合処理（画面表示 & ダウンロード共通） ---
            df_with_res = pd.DataFrame() # 初期化
            
            # 1. CSV/Excelアップロードがある場合（元データと結合）
            if st.session_state.get('original_df') is not None and st.session_state.get('ip_column_name'):
                df_with_res = st.session_state['original_df'].copy()
                ip_col = st.session_state['ip_column_name']
                results = st.session_state.get('raw_results', []) 
                
                if results:
                    res_dict = {r['Target_IP']: r for r in results}

                    # 各行のIPに基づいて結果をマッピング
                    isps, isps_jp, countries, countries_jp, proxy_type, statuses, rdaps = [], [], [], [], [], [], []
                    for ip_val in df_with_res[ip_col]:
                        ip_val_str = str(ip_val).strip()
                        info = res_dict.get(ip_val_str, {})
                        isps.append(info.get('ISP', 'N/A'))
                        isps_jp.append(info.get('ISP_JP', 'N/A')) 
                        countries.append(info.get('Country', 'N/A'))
                        countries_jp.append(info.get('Country_JP', 'N/A'))
                        proxy_type.append(info.get('Proxy_Type', ''))
                        statuses.append(info.get('Status', 'N/A'))
                        rdaps.append(info.get('RDAP', ''))
                    
                    # 結合 (列の挿入)
                    insert_idx = df_with_res.columns.get_loc(ip_col) + 1
                    df_with_res.insert(insert_idx, 'Status', statuses)
                    df_with_res.insert(insert_idx, 'Proxy Type', proxy_type)
                    df_with_res.insert(insert_idx, 'RDAP', rdaps) # RDAP列
                    df_with_res.insert(insert_idx, 'Country_JP', countries_jp)
                    df_with_res.insert(insert_idx, 'Country', countries)
                    df_with_res.insert(insert_idx, 'ISP_JP', isps_jp)
                    df_with_res.insert(insert_idx, 'ISP', isps)

            # 2. アップロードがない場合（検索結果のみから分析データを作成）🆕
            elif st.session_state.raw_results:
                # 検索結果リストをベースにDataFrame化
                temp_data = []
                for res in st.session_state.raw_results:
                    # 必要なカラムのみ抽出・リネーム
                    row = {
                        'Target_IP': res.get('Target_IP'),
                        'ISP': res.get('ISP'),
                        'ISP_JP': res.get('ISP_JP'),
                        'Country': res.get('Country'),
                        'Country_JP': res.get('Country_JP'),
                        'RDAP': res.get('RDAP', ''),
                        'Proxy Type': res.get('Proxy_Type', ''), # キー名を統一
                        'Status': res.get('Status')
                    }
                    temp_data.append(row)
                df_with_res = pd.DataFrame(temp_data)

            # --- 新機能：元データ x 検索結果 クロス分析表示 ---
            if not df_with_res.empty:
                st.markdown("---")
                render_merged_analysis(df_with_res)
            # ------------------------------------------------

            # --- 全件集計データのダウンロードセクション ---
            st.markdown("### 📊 集計データの完全版ダウンロード")
            # (中略: csvダウンロードボタン部分はそのまま)
            col_full_dl1, col_full_dl2, col_full_dl3, col_full_dl4 = st.columns(4)
            
            with col_full_dl1:
                st.download_button(
                    "⬇️ 対象IP カウント (全件)",
                    freq_full_df.to_csv(index=False).encode('utf-8-sig'),
                    "target_ip_frequency_all.csv",
                    "text/csv",
                    use_container_width=True
                )
            with col_full_dl2:
                st.download_button(
                    "⬇️ ISP別 カウント (全件)",
                    isp_full_df.to_csv(index=False).encode('utf-8-sig'),
                    "isp_counts_all.csv",
                    "text/csv",
                    use_container_width=True
                )
            with col_full_dl3:
                st.download_button(
                    "⬇️ 国別 カウント (全件)",
                    country_full_df.to_csv(index=False).encode('utf-8-sig'),
                    "country_counts_all.csv",
                    "text/csv",
                    use_container_width=True
                )
            
            with col_full_dl4:
                # 全件グラフHTMLレポートの生成
                html_report = generate_full_report_html(isp_full_df, country_full_df, freq_full_df)
                st.download_button(
                    "⬇️ 全件グラフHTMLレポート",
                    html_report,
                    "whois_analysis_report.html",
                    "text/html",
                    use_container_width=True
                )

        
        st.markdown("### ⬇️ 検索結果リストのダウンロード")
        col_dl1, col_dl2, col_dl3 = st.columns(3)
        # 1. 画面表示順データ
        csv_display = pd.DataFrame(display_res).drop(columns=['CountryCode', 'Secondary_Security_Links', 'RIR_Link'], errors='ignore').astype(str)
        with col_dl1:
            st.download_button("⬇️ CSV (画面表示順)", csv_display.to_csv(index=False).encode('utf-8-sig'), "whois_results_display.csv", "text/csv", use_container_width=True)
            # Excel (Display)
            excel_display = convert_df_to_excel(csv_display)
            st.download_button("⬇️ Excel (画面表示順)", excel_display, "whois_results_display.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", use_container_width=True)

        # 2. 全入力データ（入力順）
        result_lookup = {r['Target_IP']: r for r in st.session_state.raw_results}
        full_output_data = []
        for original_t in st.session_state.get('original_input_list', []):
            if original_t in result_lookup:
                full_output_data.append(result_lookup[original_t])
            else:
                full_output_data.append({'Target_IP': original_t, 'ISP': 'N/A', 'ISP_JP': 'N/A', 'Country': 'N/A', 'Country_JP': 'N/A', 'Status': 'Pending/Error'})
        
        csv_full = pd.DataFrame(full_output_data).drop(columns=['CountryCode', 'Secondary_Security_Links', 'RIR_Link'], errors='ignore').astype(str)
        with col_dl2:
            st.download_button("⬇️ CSV (全入力データ順)", csv_full.to_csv(index=False).encode('utf-8-sig'), "whois_results_full.csv", "text/csv", use_container_width=True)
            # Excel (Full)
            excel_full = convert_df_to_excel(csv_full)
            st.download_button("⬇️ Excel (全入力データ順)", excel_full, "whois_results_full.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", use_container_width=True)

        with col_dl3:
            # 3. 分析付きExcel (全モードで有効化) 🆕
            if not df_with_res.empty:
                st.markdown("**🔍 分析付きExcel (Pivot/Graph)**")
                
                # 時間帯分析用の列選択ボックス (存在する場合のみ)
                time_cols = [c for c in df_with_res.columns if 'date' in c.lower() or 'time' in c.lower() or 'jst' in c.lower()]
                default_idx = df_with_res.columns.get_loc(time_cols[0]) if time_cols else 0
                
                selected_time_col = None
                if time_cols:
                    selected_time_col = st.selectbox(
                        "時間帯分析(Hour列)に使う日時列を選択:", 
                        df_with_res.columns, 
                        index=default_idx,
                        key="time_col_selector"
                    )
                else:
                    st.caption("※ 日時列がないため時間帯分析はスキップされます")

                # Advanced Excel生成 (v5.0)
                excel_advanced = create_advanced_excel(df_with_res, selected_time_col)
                
                st.download_button(
                    "⬇️ Excel (分析・グラフ付き)", 
                    excel_advanced, 
                    "whois_analysis_master.xlsx", 
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", 
                    use_container_width=True,
                    help="生データに加え、ISP別・時間帯別の集計表とグラフ（ピボット）が別シートに含まれます。"
                )
            else:
                st.button("⬇️ Excel (データなし)", disabled=True, use_container_width=True)

if __name__ == "__main__":
    main()


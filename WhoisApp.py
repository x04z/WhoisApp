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
import subprocess
import dns.resolver
import dns.reversename
import dns

# --- Excelグラフ生成用ライブラリ ---
from openpyxl import Workbook
from openpyxl.utils.dataframe import dataframe_to_rows
from openpyxl.chart import BarChart, Reference, Series
from openpyxl.chart.label import DataLabelList
from openpyxl.chart.axis import ChartLines
from openpyxl.chart.layout import Layout, ManualLayout
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side

# ページ設定
st.set_page_config(layout="wide", page_title="検索大臣", page_icon="🔎")

# ==========================================
#  [Local User Config] API Key Hardcoding
# ==========================================
# ローカルで利用する場合、ここにAPIキーを記述するとGUIでの入力を省略できます。
# 記述例: HARDCODED_IPINFO_KEY = "your_token_here"
HARDCODED_IPINFO_KEY = "" 
HARDCODED_IP2PROXY_KEY = ""
HARDCODED_SECURITYTRAILS_KEY = ""
# ==========================================

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
IP2PROXY_API_URL = "https://api.ip2location.io/?key={key}&ip={ip}&format=json"
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

# リンク集
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

# --- COUNTRY_JP_NAME 全体 ---
COUNTRY_JP_NAME = {
    "AF": "アフガニスタン・イスラム首長国","AL": "アルバニア共和国","DZ": "アルジェリア民主人民共和国","AS": "アメリカ領サモア","AD": "アンドラ公国","AO": "アンゴラ共和国",
    "AI": "アンギラ","AQ": "南極","AG": "アンティグア・バーブーダ","AR": "アルゼンチン共和国","AM": "アルメニア共和国","AW": "アルバ","AU": "オーストラリア連邦",
    "AT": "オーストリア共和国","AZ": "アゼルバイジャン共和国","BS": "バハマ国","BH": "バーレーン王国","BD": "バングラデシュ人民共和国","BB": "バルバドス","BY": "ベラルーシ共和国",
    "BE": "ベルギー王国","BZ": "ベリーズ","BJ": "ベナン共和国","BM": "バミューダ","BT": "ブータン王国","BO": "ボリビア多民族国","BA": "ボスニア・ヘルツェゴビナ",
    "BW": "ボツワナ共和国","BR": "ブラジル連邦共和国","BN": "ブルネイ・ダルサラーム国","BG": "ブルガリア共和国","BF": "ブルキナファソ","BI": "ブルンジ共和国","KH": "カンボジア王国","CM": "カメルーン共和国",
    "CA": "カナダ","CV": "カーボベルデ共和国","CF": "中央アフリカ共和国","TD": "チャド共和国","CL": "チリ共和国","CN": "中華人民共和国","CO": "コロンビア共和国","CR": "コスタリカ共和国",
    "HR": "クロアチア共和国","CU": "キューバ共和国","CY": "キプロス共和国","CZ": "チェコ共和国","DK": "デンマーク王国","DJ": "ジブチ共和国","DM": "ドミニカ国","DO": "ドミニカ共和国",
    "EC": "エクアドル共和国","EG": "エジプト・アラブ共和国","SV": "エルサルバドル共和国","EE": "エストニア共和国","ET": "エチオピア連邦民主共和国","FI": "フィンランド共和国","FR": "フランス共和国","DE": "ドイツ連邦共和国",
    "GR": "ギリシャ共和国","GL": "グリーンランド","GT": "グアテマラ共和国","GY": "ガイアナ共和国","HK": "中華人民共和国香港特別行政区","HU": "ハンガリー","IN": "インド共和国","ID": "インドネシア共和国",
    "IR": "イラン・イスラム共和国","IQ": "イラク共和国","IE": "アイルランド","IL": "イスラエル国","IT": "イタリア共和国","JP": "日本国","KR": "大韓民国","TW": "台湾","MY": "マレーシア",
    "MX": "メキシコ合衆国","NL": "オランダ王国","NZ": "ニュージーランド","NO": "ノルウェー王国","PK": "パキスタン・イスラム共和国","PA": "パナマ共和国","PE": "ペルー共和国","PH": "フィリピン共和国",
    "PL": "ポーランド共和国","PT": "ポルトガル共和国","QA": "カタール国","RO": "ルーマニア","RU": "ロシア連邦","SA": "サウジアラビア王国","SG": "シンガポール共和国","ZA": "南アフリカ共和国",
    "ES": "スペイン王国","SE": "スウェーデン王国","CH": "スイス連邦","TH": "タイ王国","TR": "トルコ共和国","UA": "ウクライナ","AE": "アラブ首長国連邦","GB": "グレートブリテン及び北アイルランド連合王国",
    "US": "アメリカ合衆国","VN": "ベトナム社会主義共和国","YE": "イエメン共和国","ZM": "ザンビア共和国","ZW": "ジンバブエ共和国"
}

# --- ISP名称の日本語マッピング (企業名統一版) ---
ISP_JP_NAME = {
    # --- NTT Group ---
    'NTT Communications Corporation': 'NTTドコモビジネス株式会社', 
    'NTT COMMUNICATIONS CORPORATION': 'NTTドコモビジネス株式会社',
    'NTT DOCOMO BUSINESS,Inc.': 'NTTドコモビジネス株式会社',
    'NTT DOCOMO, INC.': '株式会社NTTドコモ',
    'NTT PC Communications, Inc.': '株式会社エヌ・ティ・ティ・ピー・シーコミュニケーションズ',
    
    # --- KDDI Group ---
    'Kddi Corporation': 'KDDI株式会社',
    'KDDI CORPORATION': 'KDDI株式会社',
    'Chubu Telecommunications Co., Inc.': '中部テレコミュニケーション株式会社',
    'Chubu Telecommunications Company, Inc.': '中部テレコミュニケーション株式会社',
    'Hokkaido Telecommunication Network Co., Inc.': '北海道総合通信網株式会社',
    'Energia Communications, Inc.': '株式会社エネルギア・コミュニケーションズ',
    'STNet, Inc.': '株式会社STNet',
    'QTNet, Inc.': '株式会社QTnet',
    'BIGLOBE Inc.': 'ビッグローブ株式会社',
    
    # --- SoftBank Group ---
    'SoftBank Corp.': 'ソフトバンク株式会社',
    'Yahoo Japan Corporation': 'LINEヤフー株式会社',
    'LY Corporation': 'LINEヤフー株式会社',
    'LINE Corporation': 'LINEヤフー株式会社',
    
    # --- Rakuten Group ---
    'Rakuten Group, Inc.': '楽天グループ株式会社',
    'Rakuten Mobile, Inc.': '楽天モバイル株式会社',
    'Rakuten Communications Corp.': '楽天コミュニケーションズ株式会社',
    
    # --- Sony Group ---
    'Sony Network Communications Inc.': 'ソニーネットワークコミュニケーションズ株式会社',
    'So-net Entertainment Corporation': 'ソニーネットワークコミュニケーションズ株式会社', 
    'So-net Corporation': 'ソニーネットワークコミュニケーションズ株式会社',
    
    # --- Major ISPs / VNEs ---
    'Internet Initiative Japan Inc.': '株式会社インターネットイニシアティブ',
    'NIFTY Corporation': 'ニフティ株式会社',
    'FreeBit Co., Ltd.': 'フリービット株式会社',
    'TOKAI Communications Corporation': '株式会社TOKAIコミュニケーションズ',
    'DREAM TRAIN INTERNET INC.': '株式会社ドリーム・トレイン・インターネット',
    'ASAHI Net, Inc.': '株式会社朝日ネット',
    'Asahi Net': '株式会社朝日ネット',
    'Optage Inc.': '株式会社オプテージ',
    'Jupiter Telecommunications Co., Ltd.': 'JCOM株式会社', 
    'JCOM Co., Ltd.': 'JCOM株式会社',
    'JCN': 'JCOM株式会社', 
    'SAKURA Internet Inc.': 'さくらインターネット株式会社',
    'GMO Internet, Inc.': 'GMOインターネットグループ株式会社',
    'INTERNET MULTIFEED CO.': 'インターネットマルチフィード株式会社',
    'IDC Frontier Inc.': '株式会社アイディーシーフロンティア',
    
    # --- Others ---
    'ARTERIA Networks Corporation': 'アルテリア・ネットワークス株式会社',
    'UCOM Corporation': 'アルテリア・ネットワークス株式会社',
    'VECTANT Ltd.': 'アルテリア・ネットワークス株式会社',
    'KIBI Cable Television Co., Ltd.': '株式会社吉備ケーブルテレビ',
}

# 強力な名寄せルール (部分一致検索)
ISP_REMAP_RULES = [
    ('jcn', 'JCOM株式会社'), ('jupiter', 'JCOM株式会社'), ('cablenet', 'JCOM株式会社'),
    ('dion', 'KDDI株式会社'), ('au one', 'KDDI株式会社'), ('kddi', 'KDDI株式会社'),
    ('k-opti', 'オプテージ株式会社'), ('ctc', '中部テレコミュニケーションズ株式会社'),
    ('vectant', 'アルテリア・ネットワークス株式会社'), ('arteria', 'アルテリア・ネットワークス株式会社'),
    ('softbank', 'ソフトバンク株式会社'), ('bbtec', 'ソフトバンク株式会社'),
    ('ocn', 'OCN株式会社'),
    ('so-net', 'ソニーネットワークコミュニケーションズ株式会社'), ('nuro', 'ソニー (NURO)'),
    ('biglobe', 'ビッグローブ株式会社'), ('iij', 'IIJ'),
    ('transix', 'インターネットマルチフィード株式会社 (transix)'),
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

def extract_actual_ip(target):
    """ 'ドメイン (IP)' の形式からIPアドレスだけを抽出する関数 """
    if not isinstance(target, str): return target
    if "(" in target and ")" in target:
        possible_ip = target.split("(")[-1].replace(")", "").strip()
        try:
            ipaddress.ip_address(possible_ip)
            return possible_ip
        except ValueError:
            pass
    return target

def clean_ocr_error_chars(target):
    cleaned_target = target.replace('Ⅱ', '11').replace('I', '1').replace('l', '1').replace('|', '1').replace('O', '0').replace('o', '0').replace(';', '.').replace(',', '.')
    if ':' not in cleaned_target:
        cleaned_target = cleaned_target.replace('S', '5').replace('s', '5')
    return cleaned_target

def is_valid_ip(target):
    try:
        ipaddress.ip_address(extract_actual_ip(target))
        return True
    except ValueError:
        return False

def is_valid_domain(target):
    """ 入力された文字列が有効なFQDN（ドメイン名）の形式を満たしているか判定する """
    if not isinstance(target, str): return False
    if is_valid_ip(target): return False
    if '.' not in target or target.startswith('.') or target.endswith('.'): return False
    if re.search(r'\s', target): return False
    parts = target.split('.')
    if len(parts) < 2 or not parts[-1].isalpha() or len(parts[-1]) < 2: return False
    return True

def is_ipv4(target):
    try:
        ipaddress.IPv4Address(extract_actual_ip(target))
        return True
    except ValueError:
        return False

def ip_to_int(ip):
    actual_ip = extract_actual_ip(ip)
    try:
        if is_ipv4(actual_ip):
            return struct.unpack("!I", socket.inet_aton(actual_ip))[0]
        return 0
    except OSError:
        return 0

def get_cidr_block(ip, netmask_range=(8, 24)):
    actual_ip = extract_actual_ip(ip)
    try:
        ip_obj = ipaddress.ip_address(actual_ip)
        if ip_obj.version == 4:
            netmask = netmask_range[1] 
            network = ipaddress.ip_network(f'{actual_ip}/{netmask}', strict=False)
            return str(network)
        elif ip_obj.version == 6:
            netmask = 48
            network = ipaddress.ip_network(f'{actual_ip}/{netmask}', strict=False)
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
    actual_ip = extract_actual_ip(target)
    is_composite = (actual_ip != target and "(" in target) # ドメインとIPの複合型か判定
    is_ip = is_valid_ip(target) and not is_composite
    
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
            links['IP Location'] = f'https://iplocation.io/ip/{encoded_target}'
        else:
            links['VirusTotal'] = f'https://www.virustotal.com/gui/search/{encoded_target}'
            links['ipinfo.io'] = f'https://ipinfo.io/{encoded_target}'
            links['IP2Proxy'] = f'https://www.ip2proxy.com/{encoded_target}'
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
            link_html += f"[{name}]({url}) | "
    
    return link_html.rstrip(' | ')

# RDAPデータ取得関数 (公式台帳への照会)
def fetch_rdap_data(ip):
    try:
        url = RDAP_BOOTSTRAP_URL.format(ip=ip)
        # 海外レジストリ(AFRINIC等)の遅延を考慮し、タイムアウトを8秒に設定
        response = session.get(url, timeout=8, allow_redirects=True)
        if response.status_code == 200:
            data = response.json()
            # 汎用的なRDAPレスポンスから名前を探す (name, handle, remarks)
            network_name = data.get('name', '')
            if not network_name and 'handle' in data:
                network_name = data['handle']
            return {'name': network_name, 'json': data, 'url': url}
    except:
        pass
    return None

# ドメイン専用RDAP取得関数
def fetch_domain_rdap_data(domain):
    """ ドメイン専用のRDAP情報を取得する関数 (rdap.org リゾルバを利用) """
    try:
        url = f"https://rdap.org/domain/{domain}"
        response = session.get(url, timeout=8, allow_redirects=True)
        if response.status_code == 200:
            data = response.json()
            return {'json': data, 'url': response.url}
    except:
        pass
    return None

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
        if res_a.status_code == 200:
            data_a = res_a.json()
            if "records" in data_a:
                combined_records.extend(data_a["records"])
    except Exception:
        pass

    # AAAAレコード (IPv6) 取得
    try:
        url_aaaa = f"https://api.securitytrails.com/v1/history/{domain}/dns/aaaa"
        res_aaaa = session.get(url_aaaa, headers=headers, timeout=10)
        if res_aaaa.status_code == 200:
            data_aaaa = res_aaaa.json()
            if "records" in data_aaaa:
                combined_records.extend(data_aaaa["records"])
    except Exception:
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
            return {
                "records": filtered_records,
                "is_date_filtered": is_date_filtered
            }

    return None

# Shodan InternetDB API Logic (No API Key Required)
def check_internetdb_risk(ip, max_retries=3):
    """
    Shodan InternetDB APIを使用して、ポートスキャン結果と脆弱性をチェックする。
    タイムアウトによるデータ欠損を防ぐため、リトライ機構とバックオフを実装。
    """
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
            # タイムアウトを5秒に延長し、猶予を持たせる
            response = requests.get(url, timeout=5)
            
            if response.status_code == 404:
                return "[No Data]"
            elif response.status_code == 429:
                return "Error: Rate Limit (Shodan)"
            elif 500 <= response.status_code < 600:
                return f"Error: Shodan Server ({response.status_code})"
            elif response.status_code != 200:
                return f"Error: HTTP {response.status_code}"
                
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
            
        except requests.exceptions.Timeout:
            # 最終試行でもタイムアウトした場合のみエラーを返す
            if attempt == max_retries - 1:
                return "Error:Timeout"
            time.sleep(1.5) # リトライ前に1.5秒の待機を挟む（バックオフ）
        except Exception:
            return "Error:Connection"
        
# IP2Proxy API取得関数
def get_ip2proxy_data(ip, api_key):
    """
    IP2Proxy Web Service APIを使用してプロキシ判定の詳細データを取得する。
    """
    if not api_key:
        return None
    try:
        url = IP2PROXY_API_URL.format(ip=ip, key=api_key)
        response = session.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            # ip2location.io の仕様：is_proxy キーが存在するかで判定
            if "is_proxy" in data:
                return data
    except Exception:
        pass
    return None


# IP逆引き関数 (PTRレコード取得 - dnspython使用/高信頼設定)
def resolve_ip_nslookup(ip):
    """ dnspythonを使用して、外部DNSサーバーを直接指定し、逆引き(PTR)ホスト名を取得する """
    hostnames = []
    raw_output = ""
    try:
        import dns.resolver
        import dns.reversename
        
        rev_name = dns.reversename.from_address(ip)
        
        # システムの不安定なDNS設定を回避し、信頼できる公開DNS（Google/Cloudflare）を明示的に指定
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ['8.8.8.8', '1.1.1.1', '2001:4860:4860::8888']
        resolver.timeout = 3 # 高速応答を期待し、タイムアウトを3秒に最適化
        resolver.lifetime = 3
        
        # PTRレコードをクエリ
        answers = resolver.resolve(rev_name, 'PTR')       
       
        # 取得したレコードを処理
        raw_lines = []
        for rdata in answers:
            # 末尾のドットを削除してクリーンなホスト名を取得
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

# --- API通信関数 (Main) ---
def get_ip_details_from_api(ip, cidr_cache_snapshot, learned_isps_snapshot, delay_between_requests, rate_limit_wait_seconds, tor_nodes, use_rdap, use_internetdb, use_rdns, api_key=None, ip2proxy_api_key=None, ip2proxy_mode="自動節約 (不審なIPのみ)", st_api_key=None, st_start_date=None, st_end_date=None):

    actual_ip = extract_actual_ip(ip)
    
    # 1. 拡張されたデータ構造 (RawとAggregatedを分離)
    result = {
        'Target_IP': ip, 
        'ISP_API_Raw': 'N/A', 'ISP_JP': 'N/A', # Whois(API)用
        'RDAP_Name_Raw': '', 'RDAP_JP': '',    # RDAP用
        'ISP': 'N/A', # 表示互換用（メインのISP表示）
        'Country': 'N/A', 'Country_JP': 'N/A', 'CountryCode': 'N/A', 
        'RIR_Link': 'N/A', 'Secondary_Security_Links': 'N/A', 'Status': 'N/A',
        'RDAP_JSON': None, 'IP2PROXY_JSON': None, 'RDAP_URL': '', 'IPINFO_JSON': None, 'IoT_Risk': '',
        'DOMAIN_RDAP_JSON': None, 'DOMAIN_RDAP_URL': '', 'ST_JSON': None, 'RDNS_DATA': None,
        'Proxy_Type': ''
    }
    new_cache_entry = None
    new_learned_isp = None
    cidr_block = get_cidr_block(actual_ip)
    
    # --- 【共通】CIDRキャッシュ取得 (省略可だが構造合わせのため記載) ---
    if cidr_block and cidr_block in cidr_cache_snapshot:
        cached_data = cidr_cache_snapshot[cidr_block]
        if time.time() - cached_data['Timestamp'] < 86400:
            result.update(cached_data) # キャッシュから復元
            result['Status'] = "Success (Cache)" 
            result['Secondary_Security_Links'] = create_secondary_links(ip)
            return result, None, None

    # --- API通信実行 ---
    try:
        time.sleep(delay_between_requests) 
        
        # Proモード (IPinfo)
        if api_key:
            url = IPINFO_API_URL.format(ip=actual_ip) 
            headers = {"Authorization": f"Bearer {api_key}"}
            response = session.get(url, headers=headers, timeout=10)
            
            if response.status_code == 429:
                result['Status'] = 'Error: Rate Limit (Pro)'
                result['Defer_Until'] = time.time() + rate_limit_wait_seconds
                return result, None, None
                
            response.raise_for_status()
            data = response.json()
            result['IPINFO_JSON'] = data 
            
            # 生データ取得
            org_raw = data.get('org', '')
            raw_isp = re.sub(r'^AS\d+\s+', '', org_raw) if org_raw else 'N/A'
            result['ISP_API_Raw'] = raw_isp
            
            result['CountryCode'] = data.get('country', 'N/A')
            result['Country'] = result['CountryCode']
            
            # Privacy判定 (省略) ...
            base_proxy_type = detect_proxy_vpn_tor(actual_ip, raw_isp, tor_nodes) # 簡易判定
            status_api = 'Success (Pro)'

        # 通常モード (ip-api)
        else:
            url = IP_API_URL.format(ip=actual_ip)
            response = session.get(url, timeout=45)
            
            if response.status_code == 429:
                result['Status'] = 'Error: Rate Limit (429)'
                result['Defer_Until'] = time.time() + rate_limit_wait_seconds
                return result, None, None
            
            response.raise_for_status()
            data = response.json()
            
            if data.get('status') == 'success':
                result['CountryCode'] = data.get('countryCode', 'N/A')
                result['Country'] = data.get('country', 'N/A')
                
                # 生データ取得
                raw_isp_val = data.get('isp', 'N/A')
                raw_org_val = data.get('org', '')
                result['ISP_API_Raw'] = raw_isp_val if raw_org_val == raw_isp_val else f"{raw_isp_val} / {raw_org_val}"
                
                base_proxy_type = detect_proxy_vpn_tor(actual_ip, result['ISP_API_Raw'], tor_nodes)
                status_api = 'Success (API)'
            else:
                result['Status'] = f"API Fail: {data.get('message', 'Unknown Fail')}"
                return result, None, None

        # --- RDAP取得 (重要) ---
        if use_rdap:
            rdap_res = fetch_rdap_data(actual_ip) 
            if rdap_res:
                raw_rdap_name = rdap_res['name']
                result['RDAP_Name_Raw'] = raw_rdap_name # 生のRDAP名
                result['RDAP_JSON'] = rdap_res['json']
                result['RDAP_URL'] = rdap_res['url']
                
                rdap_jp, _ = get_jp_names(raw_rdap_name, result['CountryCode'])
                result['RDAP_JP'] = rdap_jp

            # ドメイン版RDAP (省略) ...
            is_composite = (actual_ip != ip and "(" in ip)
            if is_composite:
                domain_part = ip.split("(")[0].strip()
                res_d = fetch_domain_rdap_data(domain_part)
                if res_d:
                    result['DOMAIN_RDAP_JSON'] = res_d['json']
                    result['DOMAIN_RDAP_URL'] = res_d['url']

        # --- その他のデータ取得 (SecurityTrails, rDNS, InternetDB) ---
        # (既存ロジックと同じため省略なしで実装してください。ここではスペースの都合で省略表記しますが、元のコードを維持します)
        is_composite = (actual_ip != ip and "(" in ip)
        if is_composite and st_api_key:
            st_res = get_securitytrails_data(ip.split("(")[0].strip(), st_api_key, st_start_date, st_end_date)
            if st_res: result['ST_JSON'] = st_res

        if use_rdns:
            rdns_hosts, rdns_raw = resolve_ip_nslookup(actual_ip)
            if rdns_raw: result['RDNS_DATA'] = {'hosts': rdns_hosts, 'raw': rdns_raw}

        if use_internetdb:
            result['IoT_Risk'] = check_internetdb_risk(actual_ip)
        else:
            result['IoT_Risk'] = "[Not Checked]" 

        result['Status'] = status_api
        result['RIR_Link'] = get_authoritative_rir_link(actual_ip, result['CountryCode'])
        result['Secondary_Security_Links'] = create_secondary_links(ip)

        # enable_aggregationフラグに関わらず、表示用に両方生成する
        isp_jp, country_jp = get_jp_names(result['ISP_API_Raw'], result['CountryCode'])
        result['ISP_JP'] = isp_jp
        result['Country_JP'] = country_jp
        
        # 互換性のため ISP キーにもセット（優先度: JP名 > Raw名）
        result['ISP'] = result['ISP_JP'] if result['ISP_JP'] != 'N/A' else result['ISP_API_Raw']

        # プロキシ判定更新
        result['Proxy_Type'] = base_proxy_type

        # キャッシュ作成
        if cidr_block:
            new_cache_entry = { cidr_block: result } # 簡略化: result全体をキャッシュ

    except requests.exceptions.RequestException as e:
        result['Status'] = f'Error: {type(e).__name__}'

    return result, new_cache_entry, new_learned_isp

def get_domain_details(domain, st_api_key=None, st_start_date=None, st_end_date=None):

    icann_link = f"[ICANN Whois (手動検索)]({RIR_LINKS['ICANN Whois']})"
    
    # --- 1. SecurityTrails (日付フィルタ対応) ---
    st_json = None
    if st_api_key:
        st_json = get_securitytrails_data(domain, st_api_key, st_start_date, st_end_date)
    
    # --- 2. ドメインRDAPの取得 (ここが抜けていたため追加) ---
    domain_rdap_json = None
    domain_rdap_url = ''
    try:
        # 既に定義されている fetch_domain_rdap_data を呼び出す
        rdap_res = fetch_domain_rdap_data(domain)
        if rdap_res:
            domain_rdap_json = rdap_res['json']
            domain_rdap_url = rdap_res['url']
    except Exception:
        pass

    # --- 3. 結果の返却 ---
    return {
        'Target_IP': domain, 
        'ISP': 'Domain/Host', 
        'Country': 'N/A', 
        'CountryCode': 'N/A',
        'RIR_Link': icann_link,
        'Secondary_Security_Links': create_secondary_links(domain),
        'Status': 'Success (Domain)',
        
        # IP用フィールドは空またはNone
        'RDAP': '', 
        'RDAP_JSON': None,
        'IP2PROXY_JSON': None, 
        'RDAP_URL': '', 
        'IPINFO_JSON': None, 
        'IoT_Risk': '',
        
        # ドメイン用フィールドにデータを格納 (これで表示されるようになる)
        'DOMAIN_RDAP_JSON': domain_rdap_json, 
        'DOMAIN_RDAP_URL': domain_rdap_url, 
        'ST_JSON': st_json, 
        'RDNS_DATA': None
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
        'RDAP': '', 'RDAP_JSON': None, 'IP2PROXY_JSON': None, 'RDAP_URL': '', 'IPINFO_JSON': None, 'IoT_Risk': '',
        'DOMAIN_RDAP_JSON': None, 'DOMAIN_RDAP_URL': '', 'ST_JSON': None, 'RDNS_DATA': None
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
        
        st.altair_chart(chart, width="stretch")
        
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
            st.altair_chart(chart, width="stretch")

            target_frequency_df_display = target_frequency_df.copy()
            target_frequency_df_display['Target_IP'] = target_frequency_df_display['Target_IP'].str.wrap(25)
            st.dataframe(target_frequency_df_display, hide_index=True, width="stretch")
        else:
            st.info("データがありません")
            
    with col_isp:
        st.markdown("#### 🏢 ISP別カウント (トップ10)")
        if not isp_summary_df.empty:
            chart = create_labeled_bar_chart(isp_summary_df, 'Count', 'ISP', 'ISP Counts')
            st.altair_chart(chart, width="stretch")
            
            st.dataframe(isp_summary_df, hide_index=True, width="stretch")
        else:
            st.info("データがありません")
            
    with col_country:
        st.markdown("#### 🌍 国別カウント (トップ10)")
        if not country_summary_df.empty:
            chart = create_labeled_bar_chart(country_summary_df, 'Count', 'Country', 'Country Counts')
            st.altair_chart(chart, width="stretch")
            
            st.dataframe(country_summary_df, hide_index=True, width="stretch")
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
    output = io.BytesIO()
    
    # 1. IPアドレスが含まれているかを判定
    target_col = 'IPアドレス' if 'IPアドレス' in df.columns else ('Target_IP' if 'Target_IP' in df.columns else df.columns[0])
    has_ip = False
    if target_col in df.columns:
        has_ip = any(is_valid_ip(str(val)) for val in df[target_col].dropna())
    
    # ==========================================
    # パターンA: すべてドメイン(非IP)の場合
    # ==========================================
    if not has_ip:
        if target_col in df.columns:
            df = df.rename(columns={target_col: 'Target Domain'})
        # 不要な列を削除（日本語名に対応）
        cols_to_drop = ['Whois結果（元データ）', 'Whois結果（日本語名称）', '国名（英語）', '国名', 'プロキシ種別', 'ステータス', 'IoTリスク', 'RDAP結果（元データ）', 'RDAP結果（日本語名称）', 'ISP', 'ISP_JP', 'Country', 'Country_JP']
        df = df.drop(columns=[c for c in cols_to_drop if c in df.columns], errors='ignore')
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Domain Results')

    # ==========================================
    # パターンB: IPアドレスが含まれる場合 (高度な分析グラフ付き)
    # ==========================================
    # 必須カラムの補完 (日本語名を基準にする)
    required_cols = {
        'プロキシ種別': 'Standard Connection',
        'Whois結果（日本語名称）': 'N/A',
        '国名': 'N/A'
    }
    for col, default_val in required_cols.items():
        if col not in df.columns:
            df[col] = default_val

    df['プロキシ種別'] = df['プロキシ種別'].fillna('Standard Connection').replace('', 'Standard Connection')
    
    has_time_analysis = False
    if time_col_name and time_col_name in df.columns:
        try:
            df['Hour'] = pd.to_datetime(df[time_col_name], errors='coerce').dt.hour
            has_time_analysis = True
        except Exception:
            pass

    count_col = df.columns[0]

    # 書き込み開始 (ブロックは1つだけに統合)
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Raw Data')
        wb = writer.book
        
        def add_chart_sheet(pivot_df, sheet_name, chart_title, x_title, y_title, description, chart_type="col", stacked=False):
            if pivot_df.empty: return
            pivot_df.to_excel(writer, sheet_name=sheet_name, startrow=4)
            ws = wb[sheet_name]
            ws['A1'] = chart_title
            ws['A1'].font = Font(size=14, bold=True, color="1E3A8A")
            ws['A2'] = description
            ws['A2'].font = Font(size=11, color="555555", italic=True)
            ws['A2'].alignment = Alignment(wrap_text=True, vertical="top")
            ws.merge_cells('A2:H3')
            chart = BarChart()
            chart.type = chart_type
            chart.style = 10 
            chart.title = chart_title
            chart.height = 15 
            chart.width = 25  
            chart.legend.position = 'b'
            if stacked:
                chart.grouping = "stacked"
                chart.overlap = 100
            else:
                chart.varyColors = True
            chart.dataLabels = DataLabelList()
            chart.dataLabels.showVal = True
            if not stacked:
                chart.dataLabels.position = 'outEnd'
            chart.x_axis.title = x_title
            chart.y_axis.title = y_title
            chart.layout = Layout(manualLayout=ManualLayout(x=0.03, y=0.05, h=0.75, w=0.85))
            data_start_row = 5 
            data_end_row = data_start_row + len(pivot_df)
            data = Reference(ws, min_col=2, min_row=data_start_row, max_row=data_end_row, max_col=len(pivot_df.columns)+1)
            cats = Reference(ws, min_col=1, min_row=data_start_row+1, max_row=data_end_row)
            chart.add_data(data, titles_from_data=True)
            chart.set_categories(cats)
            ws.add_chart(chart, "E5")

        # 1. Whois結果による集計
        isp_col = 'Whois結果（日本語名称）'
        if isp_col in df.columns:
            top_isps = df[isp_col].value_counts().head(20).index
            df_isp = df[df[isp_col].isin(top_isps)]
            pivot_isp_vol = df_isp.pivot_table(index=isp_col, values=count_col, aggfunc='count')
            if not pivot_isp_vol.empty:
                pivot_isp_vol = pivot_isp_vol.sort_values(count_col, ascending=False)
                add_chart_sheet(pivot_isp_vol, 'Report_Whois_Volume', 'Whois Access Volume Ranking', 'ISP Name', 'Count', "どの組織・プロバイダからのアクセスが多いかを可視化しています。")

            # 2. リスク分析
            pivot_isp_risk = df_isp.pivot_table(index=isp_col, columns='プロキシ種別', values=count_col, aggfunc='count', fill_value=0)
            if not pivot_isp_risk.empty:
                add_chart_sheet(pivot_isp_risk, 'Report_Whois_Risk', 'Risk Analysis by Whois', 'ISP Name', 'Count', "ISPごとの接続環境を分析しています。", stacked=True)
        
        # 3. 国別集計
        if '国名' in df.columns:
            pivot_country = df.pivot_table(index='国名', values=count_col, aggfunc='count')
            if not pivot_country.empty:
                pivot_country = pivot_country.sort_values(count_col, ascending=False).head(15)
                add_chart_sheet(pivot_country, 'Report_Country', 'Country Access Volume', 'Country Name', 'Count', "国ごとのアクセス数をランキング化しています。")

        # 4. 時間帯分析
        if has_time_analysis:
            pivot_time_vol = df.pivot_table(index='Hour', values=count_col, aggfunc='count', fill_value=0).reindex(range(24), fill_value=0)
            add_chart_sheet(pivot_time_vol, 'Report_Time_Volume', 'Hourly Access Trend', 'Hour (0-23h)', 'Count', "時間帯ごとのアクセス集中度を可視化しています。")

            if 'プロキシ種別' in df.columns:
                pivot_time_risk = df.pivot_table(index='Hour', columns='プロキシ種別', values=count_col, aggfunc='count', fill_value=0).reindex(range(24), fill_value=0)
                add_chart_sheet(pivot_time_risk, 'Report_Time_Risk', 'Hourly Risk Trend', 'Hour (0-23h)', 'Count', "時間帯ごとのリスク傾向を確認できます。", stacked=True)
            
    return output.getvalue()
            
    # ==========================================
    # パターンB: IPアドレスが含まれる場合の出力 (高度な分析グラフ付き)
    # ==========================================
    # --- 【重要】列の存在チェックと補完 (IPとドメインが混在した場合のKeyError対策) ---
    required_cols = {
        'Proxy Type': 'Standard Connection',
        'ISP_JP': 'N/A',
        'Country_JP': 'N/A'
    }
    for col, default_val in required_cols.items():
        if col not in df.columns:
            df[col] = default_val

    # データ前処理
    df['Proxy Type'] = df['Proxy Type'].fillna('Standard Connection')
    df['Proxy Type'] = df['Proxy Type'].replace('', 'Standard Connection')
    
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

            pivot_df.to_excel(writer, sheet_name=sheet_name, startrow=4)
            ws = wb[sheet_name]
            
            ws['A1'] = chart_title
            ws['A1'].font = Font(size=14, bold=True, color="1E3A8A")
            ws['A2'] = description
            ws['A2'].font = Font(size=11, color="555555", italic=True)
            ws['A2'].alignment = Alignment(wrap_text=True, vertical="top")
            ws.merge_cells('A2:H3')
            
            chart = BarChart()
            chart.type = chart_type
            chart.style = 10 
            chart.title = chart_title
            chart.height = 15 
            chart.width = 25  
            chart.legend.position = 'b'

            if stacked:
                chart.grouping = "stacked"
                chart.overlap = 100
            else:
                chart.varyColors = True

            chart.dataLabels = DataLabelList()
            chart.dataLabels.showVal = True
            if not stacked:
                chart.dataLabels.position = 'outEnd'
            
            chart.x_axis.title = x_title
            chart.y_axis.title = y_title
            chart.y_axis.majorGridlines = ChartLines() 
            chart.y_axis.delete = False        
            chart.y_axis.numFmt = '0'          
            chart.y_axis.majorTickMark = 'out' 
            chart.y_axis.tickLblPos = 'nextTo' 

            chart.layout = Layout(manualLayout=ManualLayout(x=0.03, y=0.05, h=0.75, w=0.85))

            data_start_row = 5 
            data_end_row = data_start_row + len(pivot_df)
            data = Reference(ws, min_col=2, min_row=data_start_row, max_row=data_end_row, max_col=len(pivot_df.columns)+1)
            cats = Reference(ws, min_col=1, min_row=data_start_row+1, max_row=data_end_row)
            chart.add_data(data, titles_from_data=True)
            chart.set_categories(cats)
            ws.add_chart(chart, "E5")

        # ---------------------------------------------------------
        # 2. Report_ISP_Volume: [Whois JP (名寄せ)] x [Count]
        # ---------------------------------------------------------
        # 変更点: カラム名を 'ISP_JP' から 'Whois JP (名寄せ)' に変更
        # データフレームに当該列がない場合のフォールバックも考慮
        isp_col_name = 'Whois JP (名寄せ)' if 'Whois JP (名寄せ)' in df.columns else 'ISP_JP'
        
        if isp_col_name in df.columns:
            top_isps = df[isp_col_name].value_counts().head(20).index
            df_isp = df[df[isp_col_name].isin(top_isps)]
            pivot_isp_vol = df_isp.pivot_table(
                index=isp_col_name, 
                values=count_col, 
                aggfunc='count'
            )
            if not pivot_isp_vol.empty:
                pivot_isp_vol = pivot_isp_vol.sort_values(count_col, ascending=False)
                desc_isp_vol = "どのプロバイダからのアクセスが最も多いかを可視化しています。特定のISPからのアクセス集中は、そのサービスの利用者層または特定のキャンペーンの影響を示唆します。"
                add_chart_sheet(pivot_isp_vol, 'Report_ISP_Volume', 'ISP Access Volume Ranking (Top 20)', 'Internet Service Provider', 'Access Count (件数)', desc_isp_vol)

            # ---------------------------------------------------------
            # 3. Report_ISP_Risk: [Whois JP (名寄せ)] x [Proxy Type]
            # ---------------------------------------------------------
            pivot_isp_risk = df_isp.pivot_table(
                index=isp_col_name, 
                columns='Proxy Type', 
                values=count_col, 
                aggfunc='count', 
                fill_value=0
            )
            if not pivot_isp_risk.empty:
                desc_isp_risk = "そのISPが安全な一般回線か、注意が必要なサーバー/VPN経由かを判定しています。「Standard Connection」は一般的な安全な接続です。「Hosting」や「VPN」が多い場合は機械的なアクセスの可能性があります。"
                add_chart_sheet(pivot_isp_risk, 'Report_ISP_Risk', 'Risk Analysis by ISP (Top 20)', 'Internet Service Provider', 'Access Count (件数)', desc_isp_risk, stacked=True)
        if not pivot_isp_risk.empty:
            desc_isp_risk = "そのISPが安全な一般回線か、注意が必要なサーバー/VPN経由かを判定しています。「Standard Connection」は一般的な安全な接続です。「Hosting」や「VPN」が多い場合は機械的なアクセスの可能性があります。"
            add_chart_sheet(pivot_isp_risk, 'Report_ISP_Risk', 'Risk Analysis by ISP (Top 20)', 'Internet Service Provider', 'Access Count (件数)', desc_isp_risk, stacked=True)
        
        # ---------------------------------------------------------
        # 4. Report_Country: [Country_JP] x [Count]
        # ---------------------------------------------------------
        pivot_country = df.pivot_table(
            index='Country_JP',
            values=count_col,
            aggfunc='count'
        )
        if not pivot_country.empty:
            pivot_country = pivot_country.sort_values(count_col, ascending=False).head(15)
            desc_country = "国ごとのアクセス数をランキング化しています。サービス提供エリア外からの予期せぬアクセス検知や、海外からの攻撃予兆の発見に役立ちます。"
            add_chart_sheet(pivot_country, 'Report_Country', 'Country Access Volume (Top 15)', 'Country Name', 'Access Count (件数)', desc_country)

        # ---------------------------------------------------------
        # 5. Time Analysis (if available)
        # ---------------------------------------------------------
        if has_time_analysis:
            pivot_time_vol = df.pivot_table(
                index='Hour',
                values=count_col,
                aggfunc='count',
                fill_value=0
            ).reindex(range(24), fill_value=0)
            desc_time_vol = "何時にアクセスが集中しているかを可視化しています。一般的なユーザーは活動時間帯に、Botなどは深夜早朝や24時間一定のアクセスを行う傾向があります。"
            add_chart_sheet(pivot_time_vol, 'Report_Time_Volume', 'Hourly Access Trend', 'Time of Day (0-23h)', 'Access Count (件数)', desc_time_vol)

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

def generate_individual_html_report(res, clean_ip):
    """ 
    個別IPの詳細HTMLレポートを生成する独立関数
    (BugFix: HTMLエスケープ後の&quot;に対応し、ハイライトを確実に適用)
    """
    import json
    import html
    import re
    import datetime
    from urllib.parse import urlparse
    
    # --- 1. データの展開 ---
    target_ip = res.get('Target_IP', 'N/A')
    rdap_url = res.get('RDAP_URL')
    rdap_json = res.get('RDAP_JSON')
    ipinfo_json = res.get('IPINFO_JSON')
    ip2proxy_json = res.get('IP2PROXY_JSON')
    domain_rdap_json = res.get('DOMAIN_RDAP_JSON')
    domain_rdap_url = res.get('DOMAIN_RDAP_URL')
    st_json = res.get('ST_JSON')
    
    rdns_data = res.get('RDNS_DATA', {})
    rdns_raw = rdns_data.get('raw', '') if isinstance(rdns_data, dict) else ""
    rdns_hosts = rdns_data.get('hosts', []) if isinstance(rdns_data, dict) else []
    
    nslookup_data = {}
    domain_name_for_nslookup = ""
    
    if "(" in target_ip and ")" in target_ip:
        domain_name_for_nslookup = target_ip.split("(")[0].strip()
        nslookup_data = st.session_state.get('resolved_dns_map', {}).get(domain_name_for_nslookup, {})
    elif not is_valid_ip(target_ip): 
        domain_name_for_nslookup = target_ip
        nslookup_data = st.session_state.get('resolved_dns_map', {}).get(domain_name_for_nslookup, {})
    
    nslookup_raw = nslookup_data.get('raw', '') if isinstance(nslookup_data, dict) else ""
    nslookup_ips = nslookup_data.get('ips', []) if isinstance(nslookup_data, dict) else []
    
    if isinstance(nslookup_data, str):
        nslookup_raw = nslookup_data
    
    if not ((rdap_url and rdap_json) or ipinfo_json or domain_rdap_json or nslookup_raw or st_json or rdns_raw):
        return None

    jst_timezone = datetime.timezone(datetime.timedelta(hours=9))
    now_jst = datetime.datetime.now(jst_timezone)
    current_time_str = now_jst.strftime("%Y年%m月%d日 %H時%M分")

    tabs_html = ""
    contents_html = ""
    first_tab_id = None
    
    # --- 3. nslookup (DNS正引き) ---
    if nslookup_raw:
        tab_id = "tab-nslookup"
        if not first_tab_id: first_tab_id = tab_id
        tabs_html += f'<button class="tab-button" onclick="openTab(event, \'{tab_id}\')" id="btn-{tab_id}">DNS正引き</button>\n'
        
        escaped_nslookup = html.escape(nslookup_raw)
        for ip_str in nslookup_ips:
            escaped_ip = html.escape(ip_str)
            escaped_nslookup = escaped_nslookup.replace(escaped_ip, f'<span class="json-hl">{escaped_ip}</span>')
            
        cmd_str = f"resolver = dns.resolver.Resolver(); resolver.nameservers=['8.8.8.8']; resolver.resolve('{domain_name_for_nslookup}', 'A/AAAA')"
        ip_list_str = "<br>".join([html.escape(ip) for ip in nslookup_ips]) if nslookup_ips else "取得なし"
        
        nslookup_content = f"""
        <div id="{tab_id}" class="tab-content">
            <h1 class="theme-rdap" style="color: #424242; border-color: #424242;">DNS正引き解決結果 (dnspython)</h1>
            <div class="description" style="background-color: #eceff1; border-color: #cfd8dc;">
                <strong>DNS (Domain Name System) 正引き解決記録：</strong><br>
                入力されたドメイン名に対し、IPアドレス（A/AAAAレコード）の特定を行った結果を示す。<br>
                一般的な <code>nslookup</code> コマンドは実行環境のDNS設定に依存するが、本ツールではPythonの専門ライブラリを使用して、信頼性の高いパブリックDNS（Google/Cloudflare）へ<strong>直接かつ強制的に問い合わせ</strong>を行っている。<br>
                これにより、実行環境に依存せず、nslookupと同等以上の確実な名前解決を実現している。
            </div>
            <h2>対象ドメイン及び取得結果</h2>
            <table>
                <tr><th>対象ドメイン<br>(Target Domain)</th><td><strong>{html.escape(domain_name_for_nslookup)}</strong></td></tr>
                <tr><th>取得日時<br>(Timestamp)</th><td><strong>{current_time_str}</strong></td></tr>
                <tr><th>取得IPアドレス<br>(Resolved IPs)</th><td><strong>{ip_list_str}</strong></td></tr>
            </table>
            <h2>内部実行クエリ (Python)</h2>
            <div class="raw-data" style="background-color: #263238; color: #eceff1; font-weight: bold; font-family: Consolas, monospace;">>>> {cmd_str}</div>
            <h2>実行結果 (ライブラリ出力)</h2>
            <div class="raw-data" style="font-family: Consolas, monospace;">{escaped_nslookup}</div>
        </div>
        """
        contents_html += nslookup_content

    # --- 4. RDAP (Domain) ---
    if domain_rdap_json and domain_rdap_url:
        tab_id = "tab-domain-rdap"
        if not first_tab_id: first_tab_id = tab_id
        tabs_html += f'<button class="tab-button" onclick="openTab(event, \'{tab_id}\')" id="btn-{tab_id}">RDAP(Domain)</button>\n'
        d_name = domain_rdap_json.get("ldhName", "情報なし")

        parsed_url_d = urlparse(domain_rdap_url)
        registry_name_d = parsed_url_d.netloc if parsed_url_d.netloc else "不明"

        events = domain_rdap_json.get("events", [])
        reg_date = "情報なし"
        exp_date = "情報なし"
        for ev in events:
            if ev.get("eventAction") == "registration":
                reg_date = ev.get("eventDate", "情報なし")
            elif ev.get("eventAction") == "expiration":
                exp_date = ev.get("eventDate", "情報なし")

        entities = domain_rdap_json.get("entities", [])
        registrar_name = "情報なし"
        for ent in entities:
            if "registrar" in ent.get("roles", []):
                if "vcardArray" in ent and len(ent["vcardArray"]) > 1:
                    for vcard in ent["vcardArray"][1]:
                        if vcard[0] == "fn":
                            registrar_name = vcard[3]
                            break
                break
        
        raw_json_str_d = json.dumps(domain_rdap_json, indent=4, ensure_ascii=False)
        escaped_json_d = html.escape(raw_json_str_d)
        
        # &quot; を対象にするよう変更
        highlight_keys_d = ['registrar', 'registration', 'expiration']
        for hk in highlight_keys_d:
            escaped_json_d = escaped_json_d.replace(f'&quot;{hk}&quot;', f'<span class="json-hl">&quot;{hk}&quot;</span>')

        extracted_values = [registrar_name, reg_date, exp_date]
        for val in extracted_values:
            if val and val != "情報なし":
                esc_val = html.escape(val)
                # 値のハイライトも &quot; に対応
                escaped_json_d = escaped_json_d.replace(f'&quot;{esc_val}&quot;', f'<span class="json-hl">&quot;{esc_val}&quot;</span>')

        domain_rdap_content = f"""
        <div id="{tab_id}" class="tab-content">
            <h1 class="theme-rdap">RDAP取得結果（ドメイン）</h1>
            <div class="description" style="background-color: #e8eaf6; border-color: #9fa8da;">
                ICANN管轄下のトップレベルドメイン（.com, .net, .jp等）の法的登録情報を公式レジストリから直接取得したデータであり、対象ドメインの「レジストラ（登録代行業者）」「登録日時」「有効期限」などのメタデータを確認でき、インフラ運用者（IPの持ち主）とは異なる、ドメイン自体の契約者を示す。
            </div>
            <h2>対象ドメイン及び回答元レジストリ情報等</h2>
            <table>
                <tr><th>対象ドメイン<br>(Target Domain)</th><td><strong>{d_name}</strong></td></tr>
                <tr><th>取得日時<br>(Timestamp)</th><td><strong>{current_time_str}</strong></td></tr>
                <tr><th>回答元レジストリ<br>(Registry)</th><td><strong>{registry_name_d}</strong></td></tr>
                <tr><th>参照元URL<br>(Source)</th><td><a href="{domain_rdap_url}" target="_blank" style="color: #0066cc; word-break: break-all; font-weight: bold;">{domain_rdap_url}</a></td></tr>
            </table>
            <h2>RDAP取得結果（ドメイン）</h2>
            <table>
                <tr><th>レジストラ<br>(Key: registrar)</th><td><strong>{registrar_name}</strong></td></tr>
                <tr><th>登録日時<br>(Key: registration)</th><td><strong>{reg_date}</strong></td></tr>
                <tr><th>有効期限<br>(Key: expiration)</th><td><strong>{exp_date}</strong></td></tr>
            </table>
            <h2>参照元データ (JSON形式)</h2>
            <div class="raw-data">{escaped_json_d}</div>
        </div>
        """
        contents_html += domain_rdap_content

    # --- 5. RDAP (IP) ---
    if rdap_url and rdap_json:
        tab_id = "tab-rdap"
        if not first_tab_id: first_tab_id = tab_id
        
        tabs_html += f'<button class="tab-button" onclick="openTab(event, \'{tab_id}\')" id="btn-{tab_id}">RDAP(IP)</button>\n'
        
        actual_rdap_url = rdap_url
        for link in rdap_json.get("links", []):
            if link.get("rel") == "self":
                actual_rdap_url = link.get("href", actual_rdap_url)
                break
        
        name_val = rdap_json.get("name", "情報なし")
        country_val = rdap_json.get("country", "情報なし")
        start_ip = rdap_json.get("startAddress", "情報なし")
        end_ip = rdap_json.get("endAddress", "情報なし")
        
        remarks_list = rdap_json.get("remarks", [])
        descriptions = []
        for remark in remarks_list:
            desc = remark.get("description", [])
            if isinstance(desc, list):
                descriptions.extend(desc)
            elif isinstance(desc, str):
                descriptions.append(desc)
        
        remarks_html = ""
        if descriptions:
            remarks_text = "<br>".join(descriptions)
            remarks_html = f"""
                <tr>
                    <th>備考・プロジェクト情報<br>(Remarks / Description)</th>
                    <td><strong>{remarks_text}</strong><span class="help-text">RDAPデータの備考欄に記載されている付加情報であり、保有者と運用者が異なる理由（共同プロジェクト、クラウド基盤の利用など）が記載されている場合がある。</span></td>
                </tr>
            """

        country_display = country_val
        if country_val == "JP": country_display = "JP (Japan)"
        elif country_val == "US": country_display = "US (United States)"
        
        parsed_url = urlparse(actual_rdap_url)
        registry_name = parsed_url.netloc if parsed_url.netloc else "RDAP"

        raw_json_str = json.dumps(rdap_json, indent=4, ensure_ascii=False)
        escaped_json = html.escape(raw_json_str)
        
        # 正規表現を &quot; に対応させる
        highlight_keys = ['name', 'country', 'startAddress', 'endAddress']
        for hk in highlight_keys:
            # HTMLエスケープ後は " が &quot; になっているため、正規表現もそれに合わせる
            simple_pattern = r'(&quot;' + hk + r'&quot;:\s*&quot;.*?&quot;)'
            escaped_json = re.sub(simple_pattern, r'<span class="json-hl">\1</span>', escaped_json)
        
        if descriptions:
            # remarks/description キー自体のハイライト
            escaped_json = re.sub(r'(&quot;(remarks|description)&quot;\s*:)', r'<span class="json-hl">\1</span>', escaped_json)
            # 実際の記述内容(Value)のハイライト
            for desc in descriptions:
                esc_desc = html.escape(desc)
                # 値も &quot; で囲まれている
                target_str = f'&quot;{esc_desc}&quot;'
                replacement = f'<span class="json-hl">{target_str}</span>'
                escaped_json = escaped_json.replace(target_str, replacement)

        rdap_content = f"""
        <div id="{tab_id}" class="tab-content">
            <h1 class="theme-rdap">RDAP取得結果</h1>
            <div class="description">
                <strong>登録データアクセスプロトコル（RDAP）：</strong><br>
                RDAPとは、インターネット資源（IPアドレス等）の登録主体（組織又は個人）を法的に特定し得る登録情報を取得するための標準化された通信プロトコルである。
            </div>
            <h2>対象IPアドレス及び回答元レジストリ情報等</h2>
            <table>
                <tr><th>対象IPアドレス<br>(Target IP)</th><td><strong>{clean_ip}</strong></td></tr>
                <tr><th>取得日時<br>(Timestamp)</th><td><strong>{current_time_str}</strong></td></tr>
                <tr><th>回答元レジストリ<br>(Registry)</th><td><strong>{registry_name}</strong></td></tr>
                <tr><th>参照元URL<br>(Source)</th><td><a href="{actual_rdap_url}" target="_blank" style="color: #0066cc; word-break: break-all; font-weight: bold;">{actual_rdap_url}</a></td></tr>
            </table>
            <h2>RDAP取得結果（IPアドレス）</h2>
            <table>
                <tr><th>法的保有者<br>(Key: name)</th><td><strong>{name_val}</strong><span class="help-text">対象のIPアドレスブロックを公式に管理・保有している組織名（レジストリ登録情報）を示す。</span></td></tr>
                {remarks_html}
                <tr><th>登録国コード<br>(Key: country)</th><td><strong>{country_display}</strong><span class="help-text">当該IPアドレス資源が法的に割り当てられている管轄国を示す。</span></td></tr>
                <tr><th>IPアドレス割当範囲<br>(Key: startAddress, endAddress)</th><td><strong>{start_ip} ～ {end_ip}</strong><span class="help-text">対象のIPアドレスを包含する、レジストリから当該組織に対して運用および管理権限が委譲（割り当て）された一連のIPアドレス帯域を示す。</span></td></tr>
            </table>
            <h2>参照元データ (JSON形式)</h2>
            <div class="raw-data">{escaped_json}</div>
        </div>
        """
        contents_html += rdap_content

    # --- 6. IPinfo ---
    if ipinfo_json:
        tab_id = "tab-ipinfo"
        if not first_tab_id: first_tab_id = tab_id
        
        tabs_html += f'<button class="tab-button" onclick="openTab(event, \'{tab_id}\')" id="btn-{tab_id}">IPinfo</button>\n'
        
        raw_json_str = json.dumps(ipinfo_json, indent=4, ensure_ascii=False)
        escaped_json = html.escape(raw_json_str)
        
        # &quot; 対応
        highlight_keys = ['ip', 'hostname', 'city', 'region', 'country', 'loc', 'org']
        for hk in highlight_keys:
            simple_pattern = r'(&quot;' + hk + r'&quot;:\s*&quot;.*?&quot;)'
            escaped_json = re.sub(simple_pattern, r'<span class="json-hl">\1</span>', escaped_json)

        ip_val = ipinfo_json.get("ip", "情報なし")
        hostname_val = ipinfo_json.get("hostname", "情報なし")
        city_val = ipinfo_json.get("city", "情報なし")
        region_val = ipinfo_json.get("region", "情報なし")
        country_val = ipinfo_json.get("country", "情報なし")
        loc_val = ipinfo_json.get("loc", "情報なし")
        org_val = ipinfo_json.get("org", "情報なし")
        
        req_ipinfo_url = f"https://ipinfo.io/{ip_val if ip_val != '情報なし' else clean_ip}"

        privacy_html = ""
        geo_heading = "<h2>地理的情報</h2>"

        if "privacy" in ipinfo_json:
            privacy = ipinfo_json.get("privacy", {})
            privacy_flags = []
            if privacy.get("vpn"): privacy_flags.append("VPN")
            if privacy.get("proxy"): privacy_flags.append("Proxy")
            if privacy.get("tor"): privacy_flags.append("Tor")
            if privacy.get("relay"): privacy_flags.append("Relay")
            if privacy.get("hosting"): privacy_flags.append("Hosting")
            
            if privacy_flags:
                geo_heading = "<h2>地理的情報・匿名化判定</h2>"
                privacy_val = ", ".join(privacy_flags)
                privacy_html = f"""
                    <tr>
                        <th>プライバシー・リスク判定<br>(Privacy Status)</th>
                        <td><strong>{privacy_val}</strong><span class="help-text">VPN、Proxy、Tor、Hosting等として利用されているかを判定した結果。</span></td>
                    </tr>
                """

        map_html = ""
        if loc_val != "情報なし" and "," in loc_val:
            map_url = f"https://maps.google.com/maps?q={loc_val}&hl=ja&z=14&output=embed"
            map_html = f"""
            <h2>位置情報マップ</h2>
            <div class="map-container" style="width: 100%; height: 400px; margin-bottom: 20px; border: 1px solid #ccc; border-radius: 5px; overflow: hidden;">
                <iframe width="100%" height="100%" frameborder="0" scrolling="no" marginheight="0" marginwidth="0" src="{map_url}"></iframe>
            </div>
            """

        ipinfo_content = f"""
        <div id="{tab_id}" class="tab-content">
            <h1 class="theme-ipinfo">Whois属性及び地理位置情報取得結果</h1>
            <div class="description">
                <strong>IPinfo（IP Geolocation Data）：</strong><br>
                IPinfoとは、IPアドレスに基づき、当該アドレスの推定地理的位置（国、都市、地域、郵便番号、緯度経度等）、所属組織（ASN、ISP名、ドメイン等）、ネットワーク特性を判定するサービスである。
            </div>
            <h2>基本情報</h2>
            <table>
                <tr><th>対象IPアドレス<br>(Key: ip)</th><td><strong>{ip_val}</strong></td></tr>
                <tr><th>取得日時<br>(Timestamp)</th><td><strong>{current_time_str}</strong></td></tr>
                <tr><th>リクエストURL<br>(Request URL)</th><td><a href="{req_ipinfo_url}" target="_blank" style="color: #00897b; word-break: break-all;">{req_ipinfo_url}</a></td></tr>
            </table>
            <h2>IP情報取得結果</h2>
            <table>
                <tr><th>ホストネーム<br>(Key: hostname)</th><td><strong>{hostname_val}</strong></td></tr>
                <tr><th>組織/ISP<br>(Key: org)</th><td><strong>{org_val}</strong></td></tr>
            </table>
            {geo_heading}
            <table>
                <tr><th>地域<br>(Key: city, region, country)</th><td><strong>{country_val}, {region_val}, {city_val}</strong></td></tr>
                <tr><th>推定座標<br>(Key: loc)</th><td><strong>{loc_val}</strong></td></tr>
                {privacy_html}
            </table>
            {map_html}
            <h2>参照元データ (JSON形式)</h2>
            <div class="raw-data">{escaped_json}</div>
        </div>
        """
        contents_html += ipinfo_content

    # --- 7. IP2Proxy ---
    if ip2proxy_json:
        tab_id = "tab-ip2proxy"
        if not first_tab_id: first_tab_id = tab_id
        tabs_html += f'<button class="tab-button" onclick="openTab(event, \'{tab_id}\')" id="btn-{tab_id}">IP2Proxy</button>\n'
        
        is_proxy_val = ip2proxy_json.get('is_proxy')
        if is_proxy_val is True:
            proxy_status_text = "該当あり (プロキシ検知)"
            status_color = "red"
        elif is_proxy_val is False:
            proxy_status_text = "該当なし"
            status_color = "green"
        else:
            proxy_status_text = "情報なし"
            status_color = "gray"

        p_type_val = ip2proxy_json.get('proxy_type', '情報なし')
        if p_type_val == "-" or p_type_val is None: 
            p_type_val = "情報なし"
            p_type_desc = ""
        else:
            proxy_descriptions = {
                "VPN": "【VPN Anonymizer】 自身のIPアドレスを隠蔽し、匿名性を確保するために利用される。",
                "PUB": "【Open Proxies】 公開プロキシ。",
                "WEB": "【Web Proxies】 Webベースのプロキシ。",
                "TOR": "【Tor Exit Nodes】 Tor匿名化ネットワークの出口ノード。",
                "SES": "【Search Engine Spider】 検索エンジンのクローラーやボット。",
                "DCH": "【Data Center Ranges】 ホスティング事業者やデータセンター。",
                "RES": "【Residential Proxies】 一般家庭のISP回線を経由したプロキシ。",
                "CPN": "【Consumer Privacy Network】 プライバシーネットワーク。",
                "EPN": "【Enterprise Private Network】 企業の専用ネットワーク。"
            }
            p_type_desc = proxy_descriptions.get(p_type_val, "")

        c_name_val = ip2proxy_json.get('country_name', '情報なし')
        if c_name_val == "-": c_name_val = "情報なし"

        raw_json_str = json.dumps(ip2proxy_json, indent=4, ensure_ascii=False)
        escaped_json = html.escape(raw_json_str)
        # &quot; 対応
        highlight_keys_ip2p = ['is_proxy', 'proxy_type', 'country_name', 'ip', 'as', 'isp']
        for hk in highlight_keys_ip2p:
            simple_pattern = r'(&quot;' + hk + r'&quot;:\s*.*?,?\n)'
            escaped_json = re.sub(simple_pattern, r'<span class="json-hl">\1</span>', escaped_json)

        ip2p_req_ip = ip2proxy_json.get('ip', clean_ip)
        req_ip2proxy_url = f"https://api.ip2location.io/?key=********&ip={ip2p_req_ip}&format=json"

        ip2p_content = f"""
        <div id="{tab_id}" class="tab-content">
            <h1 class="theme-ip2proxy">匿名通信判定結果</h1>
            <div class="description" style="background-color: #f3e5f5; border-color: #ce93d8;">
                <strong>IP2Proxy / IP2Location.io (PX1):</strong><br>
                IP2Proxyとは、IPアドレスが匿名ネットワークとして利用されているかを検知するためのプロキシ検知データベースである。
            </div>
            <h2>基本情報</h2>
            <table>
                <tr><th>対象IPアドレス<br>(Key: ip)</th><td><strong>{ip2p_req_ip}</strong></td></tr>
                <tr><th>取得日時<br>(Timestamp)</th><td><strong>{current_time_str}</strong></td></tr>
                <tr><th>リクエストURL<br>(Request URL)</th><td><a href="{req_ip2proxy_url}" target="_blank" style="color: #6a1b9a; word-break: break-all;">{req_ip2proxy_url}</a></td></tr>
            </table>
            <h2>IP2Proxy取得結果</h2>
            <table>
                <tr><th>プロキシ判定<br>(Key: is_proxy)</th><td><strong style="color:{status_color};">{proxy_status_text}</strong></td></tr>
                <tr><th>プロキシ種別<br>(Key: proxy_type)</th><td><strong>{p_type_val}</strong><span class="help-text">{p_type_desc}</span></td></tr>
                <tr><th>運用組織名<br>(Key: as)</th><td><strong>{ip2proxy_json.get('as', '情報なし')}</strong></td></tr>
                <tr><th>判定国名<br>(Key: country_name)</th><td><strong>{c_name_val}</strong></td></tr>
            </table>
            <h2>解析用生データ (JSON形式)</h2>
            <div class="raw-data">{escaped_json}</div>
        </div>
        """
        contents_html += ip2p_content

    # --- 8. SecurityTrails ---
    if st_json:
        tab_id = "tab-st"
        if not first_tab_id: first_tab_id = tab_id
        tabs_html += f'<button class="tab-button" onclick="openTab(event, \'{tab_id}\')" id="btn-{tab_id}">SecurityTrails</button>\n'
        
        records = st_json.get("records", [])
        is_date_filtered = st_json.get("is_date_filtered", False)
        
        st_html_rows = ""
        unique_ips_ordered = []
        seen_ips = set()

        for rec in records: 
            values = rec.get("values", [])
            ips_in_rec = []
            for v in values:
                ip_val = v.get("ip", "")
                if ip_val:
                    ips_in_rec.append(html.escape(ip_val))
                    if ip_val not in seen_ips:
                        seen_ips.add(ip_val)
                        unique_ips_ordered.append(ip_val)

            ips = "<br>".join(ips_in_rec)
            first_seen = html.escape(str(rec.get("first_seen", "情報なし")))
            last_seen = html.escape(str(rec.get("last_seen", "情報なし")))
            orgs = rec.get("organizations", [])
            org = html.escape(orgs[0]) if orgs else "情報なし"
            st_html_rows += f"<tr><td>{ips}</td><td>{first_seen}</td><td>{last_seen}</td><td>{org}</td></tr>"
            
        if not st_html_rows:
            st_html_rows = "<tr><td colspan='4' style='text-align:center;'>A/AAAAレコードの履歴データが見つかりませんでした。</td></tr>"
            
        unique_ips_rows = ""
        for ip in unique_ips_ordered:
            unique_ips_rows += f"<tr><td><strong>{html.escape(ip)}</strong></td></tr>"
        if not unique_ips_rows:
            unique_ips_rows = "<tr><td style='text-align:center;'>取得されたIPアドレスはありません。</td></tr>"

        raw_json_str_st = json.dumps(st_json, indent=4, ensure_ascii=False)
        escaped_json_st = html.escape(raw_json_str_st)
        
        # &quot; 対応
        highlight_keys_st = ['ip']
        for hk in highlight_keys_st:
            simple_pattern = r'((?:&quot;|")' + hk + r'(?:&quot;|")\s*:\s*[^\n\r]*)'
            escaped_json_st = re.sub(simple_pattern, r'<span class="json-hl">\1</span>', escaped_json_st)
            
        table_heading = "レコード履歴 (抽出結果全件)" if is_date_filtered else "レコード履歴 (最新20件)"
        target_domain_esc = html.escape(domain_name_for_nslookup)
        url_a = f"https://api.securitytrails.com/v1/history/{target_domain_esc}/dns/a"
        url_aaaa = f"https://api.securitytrails.com/v1/history/{target_domain_esc}/dns/aaaa"
        
        st_content = f"""
        <div id="{tab_id}" class="tab-content">
            <h1 class="theme-ip2proxy" style="color: #e65100; border-color: #e65100;">レコード履歴 (SecurityTrails)</h1>
            <div class="description" style="background-color: #fff3e0; border-color: #ffcc80;">
                <strong>SecurityTrails Historical DNS Data：</strong><br>
                SecurityTrailsのAPIを利用して、対象ドメインに過去紐付いていたIPアドレス（Aレコード/AAAAレコード）の変遷を取得した結果を示す。
            </div>
            <h2>対象ドメイン及び取得情報</h2>
            <table>
                <tr><th>対象ドメイン<br>(Target Domain)</th><td><strong>{target_domain_esc}</strong></td></tr>
                <tr><th>取得日時<br>(Timestamp)</th><td><strong>{current_time_str}</strong></td></tr>
                <tr><th>リクエストURL<br>(Request URL)</th><td>
                    <a href="{url_a}" target="_blank" style="color: #0066cc; word-break: break-all;">{url_a}</a><br>
                    <a href="{url_aaaa}" target="_blank" style="color: #0066cc; word-break: break-all;">{url_aaaa}</a>
                </td></tr>
            </table>
            <h2>判明したIPアドレス一覧 (重複排除)</h2>
            <table>
                <tr><th>抽出されたIPアドレス (IPv4/IPv6)</th></tr>
                {unique_ips_rows}
            </table>
            <h2>{table_heading}</h2>
            <table>
                <tr><th>IPアドレス (IPv4/IPv6)</th><th>初回観測日 (First Seen)</th><th>最終観測日 (Last Seen)</th><th>組織 (Organization)</th></tr>
                {st_html_rows}
            </table>
            <h2>参照元データ (JSON形式)</h2>
            <div class="raw-data">{escaped_json_st}</div>
        </div>
        """
        contents_html += st_content

    # --- 9. rDNS ---
    if rdns_raw:
        tab_id = "tab-rdns"
        if not first_tab_id: first_tab_id = tab_id
        tabs_html += f'<button class="tab-button" onclick="openTab(event, \'{tab_id}\')" id="btn-{tab_id}">逆引き(rDNS)</button>\n'
        
        escaped_rdns = html.escape(rdns_raw)
        for h_str in rdns_hosts:
            escaped_h = html.escape(h_str)
            escaped_rdns = escaped_rdns.replace(escaped_h, f'<span class="json-hl">{escaped_h}</span>')
            
        cmd_str = f"resolver = dns.resolver.Resolver(configure=False); resolver.nameservers = ['8.8.8.8']; resolver.resolve(dns.reversename.from_address('{clean_ip}'), 'PTR')"
        host_list_str = "<br>".join([html.escape(h) for h in rdns_hosts]) if rdns_hosts else "取得なし"
        
        rdns_content = f"""
        <div id="{tab_id}" class="tab-content">
            <h1 class="theme-rdap" style="color: #424242; border-color: #424242;">DNS逆引き解決結果 (dnspython)</h1>
            <div class="description" style="background-color: #eceff1; border-color: #cfd8dc;">
                <strong>DNS逆引き(Reverse DNS) 解決記録：</strong><br>
                対象のIPアドレスに対してPython公式の国際標準ライブラリである <code>dnspython</code> を実行し、紐づくホスト名（PTRレコード）を取得した結果を示す。
            </div>
            <h2>対象IPアドレス及び取得結果</h2>
            <table>
                <tr><th>対象IPアドレス<br>(Target IP)</th><td><strong>{clean_ip}</strong></td></tr>
                <tr><th>取得日時<br>(Timestamp)</th><td><strong>{current_time_str}</strong></td></tr>
                <tr><th>取得ホスト名<br>(Resolved Hostnames)</th><td><strong>{host_list_str}</strong></td></tr>
            </table>
            <h2>内部実行クエリ (Python)</h2>
            <div class="raw-data" style="background-color: #263238; color: #eceff1; font-weight: bold; font-family: Consolas, monospace;">>>> {cmd_str}</div>
            <h2>実行結果 (ライブラリ出力)</h2>
            <div class="raw-data" style="font-family: Consolas, monospace;">{escaped_rdns}</div>
        </div>
        """
        contents_html += rdns_content

    # --- 10. 統合HTML構築 ---
    full_html = f"""
    <!DOCTYPE html>
    <html lang="ja">
    <head>
        <meta charset="UTF-8">
        <title>IP-OSINT - {clean_ip}</title>
        <style>
            body {{ font-family: 'Helvetica Neue', Arial, sans-serif; padding: 30px; color: #333; line-height: 1.6; max-width: 800px; margin: 0 auto; }}
            .tab-container {{ margin-bottom: 20px; border-bottom: 2px solid #ccc; display: flex; }}
            .tab-button {{ background-color: #f8f9fa; border: 1px solid #ccc; border-bottom: none; outline: none; cursor: pointer; padding: 10px 20px; font-size: 16px; font-weight: bold; color: #555; border-radius: 5px 5px 0 0; margin-right: 5px; transition: 0.3s; }}
            .tab-button:hover {{ background-color: #e9ecef; }}
            .tab-button.active {{ background-color: #1e3a8a; color: white; border-color: #1e3a8a; }}
            .tab-content {{ display: none; animation: fadeEffect 0.4s; }}
            @keyframes fadeEffect {{ from {{opacity: 0;}} to {{opacity: 1;}} }}
            h1 {{ font-size: 24px; border-bottom: 2px solid; padding-bottom: 5px; text-align: center; margin-bottom: 30px;}}
            h1.theme-rdap {{ color: #1e3a8a; border-color: #1e3a8a; }}
            h1.theme-ipinfo {{ color: #00897b; border-color: #00897b; }}
            h1.theme-ip2proxy {{ color: #6a1b9a; border-color: #6a1b9a; }}
            h2 {{ font-size: 18px; margin-top: 30px; border-left: 4px solid #666; padding-left: 10px; }}
            .description {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; border: 1px solid #e9ecef; margin-bottom: 20px; font-size: 14px; text-align: justify; }}
            table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
            th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; font-size: 14px; vertical-align: top; }}
            th {{ background-color: #f2f2f2; width: 30%; }}
            .help-text {{ font-size: 12px; color: #666; display: block; margin-top: 4px; line-height: 1.4; }}
            .raw-data {{ font-family: monospace; background-color: #f4f4f4; padding: 15px; border-radius: 5px; white-space: pre-wrap; font-size: 12px; border: 1px solid #ccc; word-break: break-all; }}
            .json-hl {{ background-color: #fff59d; color: #c62828; font-weight: bold; border-radius: 2px; padding: 1px 3px; transition: 0.3s; -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
            body.hide-hl .json-hl {{ background-color: transparent; color: inherit; font-weight: normal; padding: 0; }}
            body.hide-desc .description, body.hide-desc .help-text {{ display: none; }}
            body.compress-json .raw-data {{ white-space: normal; word-break: break-all; }}
            .controls {{ margin-bottom: 20px; text-align: right; background: #e3f2fd; padding: 10px; border-radius: 5px; border: 1px solid #bbdefb; }}
            .controls label {{ font-size: 14px; cursor: pointer; font-weight: bold; color: #1565c0; margin-right: 15px; display: inline-block; margin-bottom: 5px; }}
            .controls button {{ padding: 8px 16px; font-size: 14px; cursor: pointer; background-color: #1e3a8a; color: white; border: none; border-radius: 3px; transition: background 0.3s; margin-top: 5px; }}
            .controls button:hover {{ background-color: #1565c0; }}
            @media print {{
                body {{ padding: 0; max-width: 100%; }}
                .no-print, .tab-container {{ display: none !important; }}
                .tab-content {{ display: block !important; page-break-after: always; }}
                .tab-content:last-child {{ page-break-after: auto; }}
                .raw-data {{ page-break-inside: auto; }}
                .map-container iframe {{ width: 100% !important; }}
            }}
        </style>
    </head>
    <body>
        <div class="controls no-print">
            <div>
                <label><input type="checkbox" checked onchange="document.body.classList.toggle('hide-desc', !this.checked)"> 解説・ヘルプテキストを表示</label>
                <label><input type="checkbox" checked onchange="document.body.classList.toggle('hide-hl', !this.checked)"> JSONのハイライトを有効化</label>
                <label><input type="checkbox" onchange="document.body.classList.toggle('compress-json', this.checked)"> 生データ(JSON)を圧縮表示</label>
            </div>
            <button onclick="window.print()">🖨️ すべての情報を一括印刷</button>
        </div>
        
        <div class="tab-container no-print">
            {tabs_html}
        </div>
        
        {contents_html}

        <script>
            function openTab(evt, tabId) {{
                let i, tabcontent, tablinks;
                tabcontent = document.getElementsByClassName("tab-content");
                for (i = 0; i < tabcontent.length; i++) {{
                    tabcontent[i].style.display = "none";
                }}
                tablinks = document.getElementsByClassName("tab-button");
                for (i = 0; i < tablinks.length; i++) {{
                    tablinks[i].className = tablinks[i].className.replace(" active", "");
                }}
                document.getElementById(tabId).style.display = "block";
                if(evt) {{
                    evt.currentTarget.className += " active";
                }} else {{
                    document.getElementById("btn-" + tabId).className += " active";
                }}
            }}
            if('{first_tab_id}' !== 'None') {{ openTab(null, '{first_tab_id}'); }}
            window.onbeforeprint = function() {{
                let tabcontents = document.getElementsByClassName("tab-content");
                for (let j = 0; j < tabcontents.length; j++) {{ tabcontents[j].style.display = "block"; }}
            }};
            window.onafterprint = function() {{
                let activeTabId = "";
                let tablinks = document.getElementsByClassName("tab-button");
                for (let k = 0; k < tablinks.length; k++) {{
                    if (tablinks[k].className.indexOf("active") > -1) {{ activeTabId = tablinks[k].id.replace("btn-", ""); break; }}
                }}
                if (activeTabId) {{ openTab(null, activeTabId); }}
            }};
        </script>
    </body>
    </html>
    """
    return full_html

def display_results(results, current_mode_full_text, display_mode):
    st.markdown("### 📝 検索結果")

    # --- 1. リンク集ガイド ---
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
        | 📝 **登録者情報** | **Whois.com** | `Dom` | ドメインの保有者情報（英語）を確認するのに最適。IP検索時は非表示。 |
        | 📡 **伝播確認** | **DNS Checker** | `v6` | IPv6のWhois情報が世界中でどう見えているかを確認。 |
        | 📚 **公式情報** | **CP-WHOIS** | `ALL` | 利用者認証が必要な検索ツール。ここでの検索結果はデータとして信頼性が高い。 |
        
        <small>※ `v4`: IPv4アドレス, `v6`: IPv6アドレス, `Dom`: ドメイン名, `ALL`: 全て</small>
        """, unsafe_allow_html=True)

    # --- 2. 判定アイコンと表示ルールの解説 ---
    with st.expander("⚠️ 判定アイコンと表示ルールについて"):
        st.info("""
        ### 🔍 判定ロジックの概要
        本ツールは、IPアドレスに紐付けられた**ASN（Autonomous System Number）およびISP（インターネットサービスプロバイダ）の名称・属性**を解析し、通信主体のネットワーク種別を自動的に分類しています。
        
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
        
        ※ 本判定はISP名称等に基づく推論であるため、実際の利用状況と異なる場合があります。
        """)

    if not results:
        st.info("検索結果がここに表示されます。")
        return

    # --- 1. データフレーム構築 (4列構成) ---
    df_list = []
    for idx, res in enumerate(results):
        # 国名の整形
        c_code = res.get('CountryCode', 'N/A')
        c_jp = res.get('Country_JP', 'N/A')
        country_display = f"{c_jp} ({c_code})"
        
        df_list.append({
            "No.": idx + 1,
            "IPアドレス": res.get('Target_IP', 'N/A'),
            "国名": country_display,
            "Whois(元データ)": res.get('ISP_API_Raw', 'N/A'),
            "Whois(日本語名)": res.get('ISP_JP', 'N/A'),
            "RDAP(元データ)": res.get('RDAP_Name_Raw', ''),
            "RDAP(日本語名)": res.get('RDAP_JP', ''),
            "Proxy種別": res.get('Proxy_Type', ''),
            "IoTリスク": res.get('IoT_Risk', ''),
            "ステータス": res.get('Status', 'N/A')
        })
    
    df = pd.DataFrame(df_list)

    # --- 2. マスタービュー (on_select有効化) ---
    st.markdown("#### 📊 一覧ビュー (行クリックで選択)")
    
    # 選択モードを有効化 (複数選択可能)
    selection_state = st.dataframe(
        df,
        hide_index=True,
        use_container_width=True,
        height=450,
        on_select="rerun", 
        selection_mode="multi-row",
        column_config={
            "No.": st.column_config.NumberColumn(width="small"),
            "IPアドレス": st.column_config.TextColumn(width="medium"),
            "Whois(元データ)": st.column_config.TextColumn(width="medium"),
            "Whois(日本語名)": st.column_config.TextColumn(width="medium"),
            "RDAP(元データ)": st.column_config.TextColumn(width="medium"),
            "RDAP(日本語名)": st.column_config.TextColumn(width="medium"),
        }
    )

    st.markdown("---")

    # --- 3. ディテールビュー (一括表示対応) ---
    if "集約" in current_mode_full_text:
        st.info("💡 集約モードでは個別レポート出力はできません。")
        return

    st.markdown("#### 🔍 個別調査 ＆ レポート出力 (Detail View)")
    
    # 選択されたターゲットのリストを作成
    selected_indices = selection_state.selection.rows
    target_results = []

    # A. 行が選択されている場合 -> その行を対象にする
    if selected_indices:
        st.success(f"✅ 一覧から **{len(selected_indices)}** 件が選択されています。")
        for idx in selected_indices:
            if idx < len(results):
                target_results.append(results[idx])
    
    # B. 行が選択されていない場合 -> フィルタリングUIを表示
    else:
        st.info("👆 一覧の行をクリックすると、そのターゲットが自動選択されます。または、以下の条件で一括指定も可能です。")
        
        # フィルタリングUI
        with st.expander("🔎 条件でターゲットを一括指定する", expanded=True):
            col_f1, col_f2 = st.columns(2)
            with col_f1:
                # 国でフィルタ
                all_countries = sorted(list(set([r.get('Country_JP', 'N/A') for r in results])))
                sel_countries = st.multiselect("国名で選択:", all_countries)
            with col_f2:
                # ISP(名寄せ)でフィルタ
                all_isps = sorted(list(set([r.get('ISP_JP', 'N/A') for r in results])))
                sel_isps = st.multiselect("Whois(日本語名)で選択:", all_isps)
            
            if sel_countries or sel_isps:
                for res in results:
                    c_match = res.get('Country_JP', 'N/A') in sel_countries if sel_countries else True
                    i_match = res.get('ISP_JP', 'N/A') in sel_isps if sel_isps else True
                    if c_match and i_match:
                        target_results.append(res)
                st.success(f"条件ヒット: **{len(target_results)}** 件")

    # --- 4. 選択された全ターゲットに対してレポートを表示 ---
    if target_results:
        for i, res in enumerate(target_results):
            target_ip = res.get('Target_IP', 'N/A')
            clean_ip = get_copy_target(target_ip)
            
            with st.container():
                st.markdown(f"##### 🎯 [{i+1}/{len(target_results)}] Target: `{target_ip}`")
                
                c1, c2 = st.columns([2, 1])
                with c1:
                    # リンク集
                    st.markdown(f"**🛡️ 外部調査リンク:**")
                    st.markdown(f"{res.get('Secondary_Security_Links', '-')}")
                    
                    # RIRリンクとコピー用コードブロック
                    st.markdown("**📚 RIR / Whois 窓口:**")
                    st.write(res.get('RIR_Link', '-'))
                    
                    # コピーしやすいようにIPのみを表示
                    st.code(clean_ip, language=None)
                    
                    # 補足情報
                    st.caption(f"ISP: {res.get('ISP_JP', '-')} / RDAP: {res.get('RDAP_JP', '-')}")
                
                with c2:
                    # HTMLレポート生成
                    html_report = generate_individual_html_report(res, clean_ip)
                    if html_report:
                        st.download_button(
                            label=f"⬇️ レポートDL ({clean_ip})",
                            data=html_report,
                            file_name=f"Report_{clean_ip}.html",
                            mime="text/html",
                            key=f"dl_btn_multi_{clean_ip}_{i}",
                            use_container_width=True
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

    # GraphvizのDOT言語でグラフ構造を定義
    dot_lines = [
        'graph {',
        '  layout=neato;', # ノードを物理的な反発力で自動配置するエンジン
        '  overlap=false;',
        '  splines=true;',
        '  node [fontname="Helvetica", fontsize=10];'
    ]
    
    nodes = set()
    edges = set()
    
    # 描画負荷を考慮し、上位50件程度でプロット
    plot_df = df.head(50).fillna("N/A")

    for _, row in plot_df.iterrows():
        # カラム名の取得を日本語版に変更
        ip = row.get('IPアドレス', row.get('Target_IP', 'Unknown'))
        
        # 優先度: 日本語カラム > 英語カラム > N/A
        isp = row.get('Whois結果（日本語名称）', row.get('ISP_JP', row.get('ISP', 'N/A')))
        country = row.get('国名', row.get('Country_JP', row.get('Country', 'N/A')))
        risk = row.get('IoTリスク', row.get('IoT_Risk', ''))
        proxy = row.get('プロキシ種別', row.get('Proxy Type', ''))

        # 1. IPノード (水色の丸)
        nodes.add(f'"{ip}" [shape=circle, style=filled, fillcolor="#E0F2F1", width=0.8];')

        # 2. ISPノード (オレンジの四角) - IPと線を結ぶ
        if isp != "N/A":
            nodes.add(f'"{isp}" [shape=box, style=filled, fillcolor="#FFF3E0", color="#FF9800", penwidth=2];')
            edges.add(f'"{ip}" -- "{isp}" [color="#FF9800", alpha=0.5];')

        # 3. 国ノード (緑の楕円)
        if country != "N/A":
            nodes.add(f'"{country}" [shape=ellipse, style=filled, fillcolor="#F1F8E9", color="#8BC34A"];')
            edges.add(f'"{ip}" -- "{country}" [style=dotted, color="#8BC34A"];')

        # 4. リスクノード (赤の二重丸) - 複数リスクは分割して線を結ぶ
        if risk and risk not in ["[No Match]", "[Not Checked]", "[No Data]", "N/A", ""]:
            for r in risk.split(" / "):
                nodes.add(f'"{r}" [shape=doublecircle, style=filled, fillcolor="#FFEBEE", color="#F44336", fontcolor="#B71C1C", penwidth=3];')
                edges.add(f'"{ip}" -- "{r}" [color="#F44336", penwidth=2];')

        # 5. プロキシノード (紫の六角形)
        if proxy and proxy != "Standard Connection":
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

# 📊 元データ結合分析機能 (タブ化対応)
def render_merged_analysis(df_merged):
    st.markdown("### 📈 分析センター")
    
    tab_cross, tab_spider = st.tabs(["📊 クロス分析 (マクロ視点)", "🕸️ リンク分析 (ミクロ視点)"])
    
    with tab_cross:
        st.info("アップロードされたファイルの元の列と、検索で得られたWhois情報を組み合わせて可視化します。")
        # 除外するカラムを日本語名に変更
        exclude_cols = ['Whois結果（元データ）', 'Whois結果（日本語名称）', '国名（英語）', '国名', 'プロキシ種別', 'ステータス', 'IoTリスク', 'RDAP結果（元データ）', 'RDAP結果（日本語名称）', 'ISP', 'ISP_JP', 'Country', 'Country_JP']
        original_cols = [c for c in df_merged.columns if c not in exclude_cols]
        
        # 分析に使用するWhois系カラムを日本語名に変更
        whois_cols = ['国名', 'Whois結果（日本語名称）', 'プロキシ種別', 'IoTリスク', 'ステータス']
        
        col_x, col_grp, col_chart_type = st.columns(3)
        with col_x:
            x_col = st.selectbox("X軸 (カテゴリ/元の列)", original_cols + whois_cols, index=0)
        with col_grp:
            group_col = st.selectbox("積み上げ/色分け (Whois情報など)", ['(なし)'] + whois_cols + original_cols, index=1)
        with col_chart_type:
            chart_type = st.radio("グラフタイプ", ["バーチャート (集計)", "ヒートマップ"], horizontal=True)

        if not df_merged.empty:
            chart = None
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
                st.altair_chart(chart, width="stretch")
                chart_json = chart.to_dict()
                html_content = generate_cross_analysis_html(chart_json, x_col, group_col if group_col != '(なし)' else 'Count')
                st.download_button(
                    label="⬇️ クロス分析レポート(HTML)をダウンロード",
                    data=html_content,
                    file_name=f"cross_analysis_{x_col}_vs_{group_col}.html",
                    mime="text/html"
                )

    with tab_spider:
        # リンク分析関数を呼び出す
        render_spider_web_analysis(df_merged)



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
    
    # --- セッション中のみ有効な学習済みプロキシISPリスト ---
    if 'learned_proxy_isps' not in st.session_state:
        st.session_state['learned_proxy_isps'] = {} # {ISP名: ProxyType}

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

            # 2. IP2Proxy (IP2Location.io) の設定
            ip2proxy_api_key = ""
            if HARDCODED_IP2PROXY_KEY:
                use_hc_ip2p = st.checkbox("埋め込みキー (IP2Proxy) を使用", value=True, help="オフにすると、埋め込まれたAPIキーを無効化し、空欄または手動入力モードに切り替えます。")
                if use_hc_ip2p:
                    ip2proxy_api_key = HARDCODED_IP2PROXY_KEY
                    st.success(f"✅ IP2Proxy Key Loaded: {ip2proxy_api_key[:4]}***")
                else:
                    ip2proxy_api_key = st.text_input("IP2Proxy API Key", type="password", key="input_ip2p", help="IP2Proxy Web ServiceのAPIキーを入力することで、IPアドレスの匿名通信判定を取得します。").strip()    
            else:
                ip2proxy_api_key = st.text_input("IP2Proxy API Key", type="password", key="input_ip2p", help="IP2Proxy Web ServiceのAPIキーを入力することで、IPアドレスの匿名通信判定を取得します。").strip()    

            # モード選択変数の初期化
            ip2proxy_mode = "自動節約 (不審なIPのみ)"
            if ip2proxy_api_key:
                ip2proxy_mode = st.radio(
                    "IP2Proxy 判定モード",
                    ["自動節約 (不審なIPのみ)", "全件検査 (API消費大)"],
                    help="「自動」は海外IPや不審なISPにのみAPIを使用し枠を節約します。「全件」はすべてのIPに匿名通信判定を行いますが、APIの月間枠を消費します。"
                )

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

            st_start_date = None
            st_end_date = None
            if st_api_key:
                import datetime
                st.markdown("##### 📅 履歴取得期間 (SecurityTrails)")
                use_st_date_filter = st.checkbox("期間を指定して全件抽出する", value=False, help="チェックを入れると指定期間の履歴を制限なく抽出します。チェックがない場合は最新20件のみを取得します。")
            
                if use_st_date_filter:
                    col_dt1, col_dt2 = st.columns(2)
                    with col_dt1:
                        st_start_date = st.date_input("開始日", datetime.date(2020, 1, 1), help="この日以降に観測された履歴のみを抽出します。")
                    with col_dt2:
                        st_end_date = st.date_input("終了日", datetime.date.today(), help="この日以前に観測された履歴のみを抽出します。")

        st.markdown("---")
        if st.button("🔄 IPキャッシュクリア", help="キャッシュが古くなった場合にクリック"):
            st.session_state['cidr_cache'] = {} 
            st.info("IP/CIDRキャッシュをクリアしました。")
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
                - `ip-api.com` (無料版) の情報に加え、各地域の**公式レジストリ(RDAP)** にも問い合わせを行います。
                - **メリット**: 「運用者(ISP)」だけでなく「法的な保有組織(Org)」まで特定できる確率が上がります。
            
            - **🔑 高精度判定 (ipinfo Key)**
                - **メリット**: VPN/Proxy/Hostingの判定精度が劇的に向上し、企業名の特定精度も高まります。
                - **注意**: データプランの種類（無料プラン、有料プラン）やAPIの利用状況に応じて、提供される情報の項目が異なり、無料版は、地理的位置情報やISP情報などの基本的なデータに限定されます。
                        
            - **🕵️ 匿名通信判定 (IP2Proxy Key)**
                - **メリット**: VPN、Proxy、Tor等の利用が疑われる不審なIPに対し、IP2Location.ioの専門データベースから「匿名通信該当結果」を自動取得します。

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
            pip install streamlit pandas requests streamlit-option-menu altair openpyxl dnspython
            ```
            
            **3. アプリの起動**
            コマンドプロンプトまたはターミナルで以下を実行します。
            ```bash
            streamlit run WhoisAppxxxx.py
            ```
            """)
 
        with tab2:
            st.markdown("""
            #### 1. データソース
            - **IP Geolocation / ISP 情報**: 
                - 通常版: `ip-api.com` (毎分45リクエスト制限)
                - 高精度版: `ipinfo.io` (APIキーに基づく制限)
            - **匿名通信判定 (Proxy/VPN)**: `IP2Location.io` (不審なIPのみ実行)
            - **過去のDNS履歴 (Historical DNS)**: `SecurityTrails` (ドメイン入力時のみ実行)
            - **DNS解析 (Forward/Reverse)**: OS標準 `nslookup` (正引き) / `dnspython` ライブラリ (逆引き)
            - **Whois (RDAP)**: APNIC等の各地域レジストリ公式サーバー
            - **IoT Risk Intelligence**: Shodan InternetDB (ポートスキャン履歴/キャッシュ)
            - **Tor出口ノード**: Tor Project公式サイト

            #### 2. 多角的解析の仕組み (API・RDAP・ProxyEvidence・DNS History)
            - **運用者判定 (ip-api/ipinfo)**: 
                - **役割**: 「今、誰がそのIPを運用しているか？」(Service Provider) を答えます。
                - **特徴**: 高速。ISPやクラウド事業者名（Cloudflare, Amazon等）を特定します。
            - **法的保有者判定 (RDAP公式台帳)**: 
                - **役割**: 「そのIPアドレス(土地)の法的な持ち主は誰か？」(Registry Owner) を答えます。
                - **特徴**: 厳密。各地域のレジストリに登録された組織名を特定します。
            - **インフラ紐付け (rDNS/PTR)**: 
                - **役割**: 「そのIPにはどんなホスト名が付いているか？」を特定。Windowsの `nslookup` の制限を回避するため、専用のリゾルバを用いて全レコードを抽出します。
            - **匿名性判定 (IP2Proxy)**: 
                - **役割**: 「そのIPは意図的に隠蔽（VPN/Proxy等）されているか？」を答えます。
                - **特徴**: 不審な判定時に専門DBから詳細なJSONを取得します。
            - **レコード履歴特定 (SecurityTrails)**: 
                - **役割**: 「そのドメインはどのIPアドレスがレコードに設定されていたか？」を答えます。
                - **特徴**: 履歴追跡。WAF等で現在のIPが隠蔽されていても、過去のIPアドレスを特定できる可能性があります。
            - **メリット**: これらを統合することで、単なる「場所の特定」を超え、「通信主体の隠蔽意図」や「インフラの変遷」までを浮き彫りにします。

            #### 3. 技術的仕様
            - **並列処理**: マルチスレッドによる高速検索
            - **動的負荷調整**: 逆引きオプション有効時は、クエリの衝突とタイムアウトを回避するため、**自動でシングルスレッド・待機延長モード**へ移行し、調査の確実性を担保します。
            - **CIDRキャッシュ**: 同一ネットワーク帯域への重複リクエスト回避
            """)
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
            * **匿名通信判定 (IP2Proxy)**: [IP2Location.io サインアップ](https://www.ip2location.io/sign-up)
            * **過去のDNS履歴取得 (SecurityTrails)**: [SecurityTrails サインアップ](https://securitytrails.com/app/signup)

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
    # モード表示ロジック
    if IS_PUBLIC_MODE:
        mode_title = "☁️ Public Cloud Edition (機能制限あり)"
        mode_color = "gray"
    else:
        mode_title = "🏠 Local Private Edition (フル機能版)"
        mode_color = "green"

    st.title("🔎 検索大臣 - IP/Domain OSINT -")
    st.markdown(f"**Current Mode:** <span style='color:{mode_color}; font-weight:bold;'>{mode_title}</span>", unsafe_allow_html=True)
    # --- アップデート通知エリア  ---
    with st.expander("🌸アップデート情報 (令和８年３月３日) - 各種API連携・レポート出力の実装・UI変更 🌸", expanded=False):
        st.markdown("""
        **Update:**\n
        **🕵️ 匿名通信判定 (IP2Proxy / IP2Location.io 連携)**: 
        * VPN、Proxy、Tor、データセンター等の利用を専門データベースで照合可能になりました。不審なIPを検知した際、自動で「匿名通信判定情報」を取得します。\n
        **📜 過去のDNS履歴取得 (SecurityTrails 連携)**: 
        * ドメインを入力した際、対象ドメインに過去紐付いていたIPアドレス（A/AAAAレコード）の変遷をSecurityTrails APIから自動取得可能になりました。\n
        **🔄 高精度IP逆引き (dnspython 連携)**: 
        * IPアドレスからホスト名を特定する「逆引き」機能を実装。Windows標準コマンドの制限（複数レコードの欠落）を克服するため、専用ライブラリによる直接クエリを採用しました。これに伴い、DNSクエリのタイムアウトを防ぐ**「動的負荷調整ロジック（自動シングルスレッド化）」**を搭載しています。\n
        **📄 詳細レポート (HTML)**:
        * RDAP、ipinfo、IP2Proxy、SecurityTrailsに加え、逆引き結果も一つのHTMLファイルに集約。タブ切り替えによるシームレスな閲覧と、書類提出に最適な「一括印刷機能」を搭載しました。 \n
        **🏢 企業名「名寄せ」の任意選択機能**:
        * RDAPとWhois（API）の回答結果の差異を解消するため、ISP名や組織名の「名寄せ（日本語企業名への統一）」のオン/オフを選択できるようになりました。オフに設定することで、レジストリから取得した生データをそのまま表示し、より厳密な実態調査が可能です。\n
        **🔎 検索一覧ビューのUIデザイン変更**:
        * 行クリック、または「国別」「ISP別」フィルタで対象を絞り込み、ヒットした全件分の調査リンクとレポートDLボタンを表示させます。            
        """)
    # ------------------------------------------------
    # 【改善】タブを使って入力モードを切り替え、画面を広く使う
    input_tab1, input_tab2 = st.tabs(["📋 テキスト貼り付け", "📂 ファイル読み込み"])

    with input_tab1:
        manual_input = st.text_area(
            "検索対象を入力 (IPアドレス または ドメイン)",
            height=200, # 高さを少し広げて見やすく
            placeholder="8.8.8.8\nexample.com\n2404:6800:...",
            help="1行に1つのターゲットを入力してください。"
        )

    with input_tab2:
        # --- モードによるアップロード制限の切り替え ---
        if IS_PUBLIC_MODE:
            # 公開モード (st版の挙動): txtのみ許可、警告あり
            allowed_types = ['txt']
            label_text = "IPリストをアップロード (.txtのみ)"
            help_text = "※ 1行に1つのターゲットを記載"
        else:
            # ローカルモード (my版の挙動): csv/excel許可
            allowed_types = ['txt', 'csv', 'xlsx', 'xls']
            label_text = "リストをアップロード (txt/csv/xlsx)"
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
            
            # --- ローカルモードの場合の読み込み処理  ---
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
                            
                            # --- アップロードデータのプレビュー ---
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

    # 生データからすべての空白文字（半角・全角スペース、タブ等）を完全に除去し、空行を排除する
    raw_targets = [re.sub(r'\s+', '', t) for t in raw_targets if t.strip()]

    if raw_targets:
        cleaned_raw_targets_list = [clean_ocr_error_chars(t) for t in raw_targets]
        target_freq_counts = pd.Series(cleaned_raw_targets_list).value_counts().to_dict()
    else:
        target_freq_counts = {}

    targets = []
    invalid_targets_skipped = [] # 無効としてスキップされたターゲットを記録
    ocr_error_chars = set('Iil|OoSsAaBⅡ')
    resolved_dns_map = {} # nslookupの生出力保存用辞書

    def resolve_domain_nslookup(domain):
    
        ips = []
        raw_lines = []
    
        try:
            # システムのリゾルバに依存せず、Google/CloudflareのパブリックDNSを明示的に使用
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = ['8.8.8.8', '1.1.1.1', '2001:4860:4860::8888']
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

        except Exception as e:
            raw_lines.append(f";; Critical DNS Error: {str(e)}")
    
        return ips, "\n".join(raw_lines)

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
            # ドメイン形式の厳格チェック
            if is_valid_domain(t):
                # --- nslookupによる複数IP完全取得 ---
                ip_list, raw_output = resolve_domain_nslookup(t)
                if t not in targets: targets.append(t)
                if ip_list:
                    resolved_dns_map[t] = {'ips': ip_list, 'raw': raw_output}
                    for resolved_ip in ip_list:
                        combined_t = f"{t} ({resolved_ip})"
                        # IP紐付きターゲットを追加 (こちらはIP検索エンジンに回る)
                        if combined_t not in targets: targets.append(combined_t)
            else:
                invalid_targets_skipped.append(t) # 不正なドメインとして除外
        else:
            cleaned_t_final = clean_ocr_error_chars(t)
            if is_valid_ip(cleaned_t_final):
                if cleaned_t_final not in targets: targets.append(cleaned_t_final)
            else:
                # クリーンアップ後もドメイン形式の厳格チェック
                if is_valid_domain(cleaned_t_final):
                    ip_list, raw_output = resolve_domain_nslookup(cleaned_t_final)
                    if ip_list:
                        resolved_dns_map[cleaned_t_final] = {'ips': ip_list, 'raw': raw_output}
                        for resolved_ip in ip_list:
                            combined_t = f"{cleaned_t_final} ({resolved_ip})"
                            if combined_t not in targets: targets.append(combined_t)
                    else:
                        if cleaned_t_final not in targets: targets.append(cleaned_t_final)
                else:
                    invalid_targets_skipped.append(t) # 不正なドメインとして除外

    # スキップされたターゲットがあれば警告を表示
    if invalid_targets_skipped:
        st.warning(f"⚠️ 以下の入力は「IPアドレス」または「有効なドメイン形式 (例: example.com)」を満たしていないため、検索対象から除外されました: **{', '.join(list(set(invalid_targets_skipped)))}**")

    has_new_targets = (targets != st.session_state.targets_cache)
    
    if has_new_targets or 'target_freq_map' not in st.session_state:
        st.session_state['target_freq_map'] = target_freq_counts
        st.session_state['original_input_list'] = cleaned_raw_targets_list
        st.session_state['resolved_dns_map'] = resolved_dns_map # nslookupの生出力を保存

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

    st.markdown("---")
    # 設定エリアをExpanderに格納し、デフォルトで閉じておく
    with st.expander("⚙️ 検索表示・解析オプション (クリックして展開)", expanded=False):
        col_set1, col_set2 = st.columns(2)
        with col_set1:
            display_mode = st.radio(
                "**表示モード:** (検索結果の表示形式とAPI使用有無を設定)",
                ("標準モード", "集約モード (IPv4 Group)", "簡易モード (APIなし)"),
                key="display_mode_radio",
                horizontal=False
            )
            st.markdown("---") 
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
            
        with col_set2:
            st.markdown("**解析モード:** (追加の解析オプションを選択)")
            # InternetDBオプション
            use_internetdb_option = st.checkbox("IoTリスク検知 (InternetDBを利用)", value=True, help="Shodan InternetDBを利用して、対象IPの開放ポートや踏み台リスクを検知します。不要な場合はオフにすることで処理を最適化できます。")
            # RDAPオプション
            use_rdap_option = st.checkbox("公式レジストリ情報 (RDAP公式台帳の併用 - 低速)", value=True, help="RDAP(公式台帳)から最新のネットワーク名を取得します。通信が増えるため処理が遅くなります。")
            # 逆引き(rDNS)オプション
            use_rdns_option = st.checkbox("IP逆引き (Reverse DNS - dnspython)", value=False, help="対象IPアドレスに対してdnspythonを実行し、ホスト名(PTRレコード)を取得して詳細レポートに追加します。")

    mode_mapping = {
        "標準モード": "標準モード (1ターゲット = 1行)",
        "集約モード (IPv4 Group)": "集約モード (IPv4アドレスをISP/国別でグループ化)",
        "簡易モード (APIなし)": "簡易モード (APIなし - セキュリティリンクのみ)"
    }
    current_mode_full_text = mode_mapping[display_mode]

    col_act1, col_act2 = st.columns([3, 1])

    is_currently_searching = st.session_state.is_searching and not st.session_state.cancel_search
    
    total_ip_targets_for_display = len(ip_targets) + len(st.session_state.deferred_ips)

    with col_act1:
        status_msg = (
            f"**検索対象:** IPアドレス: {count_direct_ipv4}件(v4)・{count_direct_ipv6}件(v6) /"
            f"ドメイン: {count_domain} 件/ (正引きIP: {count_resolved_ip}件) / "
            f"(待機中: {count_pending}件) / **キャッシュ:** {len(st.session_state.cidr_cache)}件"
        )
        st.success(status_msg)
        
        # 1. IPinfo (Pro Mode) の判定
        if pro_api_key:
            st.info("🔑 **IPinfo Pro Active:** 高精度な地理位置・ISP情報を使用します。")
        else:
            st.warning("ℹ️ **IPinfo Inactive:** 通常版(ip-api)を使用するため、判定精度が制限されます。")

        # 2. IP2Proxy (IP2Location.io) の判定
        if ip2proxy_api_key:
            st.info("🕵️ **IP2Proxy Evidence Active:** 不審判定(VPN/Hosting等)時に自動で匿名通信判定結果を取得します。")
        else:
            st.caption("※ **IP2Proxy Inactive:** 匿名通信の判定結果は生成されません。")

        # 3. IoT Risk (InternetDB) の判定
        if use_internetdb_option:
            st.info("🔎 **IoT Check Active:** Shodan InternetDBによるスキャン履歴を参照します。")
        else:
            st.info("ℹ️ **IoT Check Inactive:** IoT/脆弱性リスク検知はスキップされます。")

    with col_act2:
        if is_currently_searching:
            if st.button("❌ 中止", type="secondary", width="stretch"):
                st.session_state.cancel_search = True
                st.session_state.is_searching = False
                st.session_state.deferred_ips = {}
                st.rerun()
        else:
            execute_search = st.button(
            "🚀 検索開始",
            type="primary",
            width="stretch",
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
                    st.session_state.raw_results.extend([get_domain_details(d, st_api_key, st_start_date, st_end_date) for d in domain_targets])
                    st.session_state.finished_ips.update(domain_targets)
                    
                prog_bar_container = st.empty()
                status_text_container = st.empty()
                summary_container = st.empty() 

                if immediate_ip_queue:
                    cidr_cache_snapshot = st.session_state.cidr_cache.copy() 
                    learned_isps_snapshot = st.session_state.learned_proxy_isps.copy()
                    
                    # --- 逆引き(rDNS)有効時の動的負荷調整 (安全装置) ---
                    current_max_workers = max_workers
                    current_delay = delay_between_requests
                    
                    if use_rdns_option:
                        # DNSクエリの競合とタイムアウトを防ぐため強制的にシングルスレッド化
                        current_max_workers = 1 
                        # 待機時間が短い場合は、安全のために最低2.0秒まで引き上げる
                        if current_delay < 2.0:
                            current_delay = 2.0
                        st.info("ℹ️ 逆引き精度向上のため、負荷調整モード（シングルスレッド/待機延長）で実行中...")

                    with ThreadPoolExecutor(max_workers=current_max_workers) as executor:
                        future_to_ip = {
                            executor.submit(
                                get_ip_details_from_api, 
                                ip, 
                                cidr_cache_snapshot, 
                                learned_isps_snapshot, 
                                current_delay,
                                rate_limit_wait_seconds,
                                tor_nodes,
                                use_rdap_option,
                                use_internetdb_option,
                                use_rdns_option,
                                pro_api_key,
                                ip2proxy_api_key,
                                ip2proxy_mode,
                                st_api_key,
                                st_start_date,
                                st_end_date
                            ): ip for ip in immediate_ip_queue
                        }
                        remaining = set(future_to_ip.keys())
                        
                        while remaining and not st.session_state.cancel_search:
                            done, remaining = wait(remaining, timeout=0.1, return_when=FIRST_COMPLETED)
                            
                            for f in done:
                                res_tuple = f.result()
                                res = res_tuple[0]
                                new_cache_entry = res_tuple[1] if len(res_tuple) > 1 else None
                                new_learned_isp = res_tuple[2] if len(res_tuple) > 2 else None
                                ip = res['Target_IP']
                                
                                if new_cache_entry:
                                    st.session_state.cidr_cache.update(new_cache_entry)
                                
                                # メインスレッド側で学習済みリストを安全に更新
                                if new_learned_isp:
                                    st.session_state.learned_proxy_isps.update(new_learned_isp)
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
                                    eta_display = f"{minutes:02d}分{seconds:02d}秒"
                                    
                                with prog_bar_container:
                                    st.progress(pct)
                                with status_text_container:
                                    st.info(f"**⏳ 処理中... ({pct}%)** | 完了: {processed_api_ips_count}/{total_ip_api_targets} | ⏸️ 保留: {len(st.session_state.deferred_ips)} | 📦 キャッシュ: {len(st.session_state.cidr_cache)} | ⏱️ 残り: {eta_display}")
                                
                                isp_df, country_df, freq_df, country_all_df, isp_full_df, country_full_df, freq_full_df = summarize_in_realtime(st.session_state.raw_results)
                                with summary_container.container():
                                    st.markdown("---")
                                    draw_summary_content(isp_df, country_df, freq_df, country_all_df, "📊 リアルタイム分析") 
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
                                st.success(f"**✅ 処理完了 (100%)** | 完了: {processed_api_ips_count}/{total_ip_api_targets} | 📦 キャッシュ: {len(st.session_state.cidr_cache)}")
                        
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
                    # 変更点: 4つのカラム用リストを追加
                    whois_raws, whois_jps, rdap_raws, rdap_jps = [], [], [], []
                    countries, countries_jp, proxy_type, iot_risks, statuses = [], [], [], [], []

                    for ip_val in df_with_res[ip_col]:
                        ip_val_str = str(ip_val).strip()
                        info = res_dict.get(ip_val_str, {})
                        
                        # 4つの詳細カラムを取得
                        whois_raws.append(info.get('ISP_API_Raw', 'N/A'))
                        whois_jps.append(info.get('ISP_JP', 'N/A'))
                        rdap_raws.append(info.get('RDAP_Name_Raw', ''))
                        rdap_jps.append(info.get('RDAP_JP', ''))
                        
                        countries.append(info.get('Country', 'N/A'))
                        countries_jp.append(info.get('Country_JP', 'N/A'))
                        proxy_type.append(info.get('Proxy_Type', ''))
                        iot_risks.append(info.get('IoT_Risk', '')) 
                        statuses.append(info.get('Status', 'N/A'))
                    
                    # 結合 (列の挿入) - 挿入順序を調整 (右から順に入っていくため、逆順で指定すると左から並ぶ)
                    insert_idx = df_with_res.columns.get_loc(ip_col) + 1
                    df_with_res.insert(insert_idx, 'ステータス', statuses)
                    df_with_res.insert(insert_idx, 'IoTリスク', iot_risks) 
                    df_with_res.insert(insert_idx, 'プロキシ種別', proxy_type)
                    
                    df_with_res.insert(insert_idx, 'Whois結果（日本語名称）', whois_jps)
                    df_with_res.insert(insert_idx, 'Whois結果（元データ）', whois_raws)
                    df_with_res.insert(insert_idx, 'RDAP結果（日本語名称）', rdap_jps)
                    df_with_res.insert(insert_idx, 'RDAP結果（元データ）', rdap_raws)
                    df_with_res.insert(insert_idx, '国名', countries_jp)
                    df_with_res.insert(insert_idx, '国名（英語）', countries)

            # 2. アップロードがない場合（検索結果のみから分析データを作成）
            elif st.session_state.raw_results:
                # 検索結果リストをベースにDataFrame化
                temp_data = []
                for res in st.session_state.raw_results:
                    # 必要なカラムのみ抽出・リネーム
                    row = {
                        'IPアドレス': res.get('Target_IP'),
                        'RDAP結果（元データ）': res.get('RDAP_Name_Raw', ''),
                        'RDAP結果（日本語名称）': res.get('RDAP_JP', ''),
                        'Whois結果（元データ）': res.get('ISP_API_Raw', 'N/A'),
                        'Whois結果（日本語名称）': res.get('ISP_JP', 'N/A'),
                        
                        '国名（英語）': res.get('Country'),
                        '国名': res.get('Country_JP'),
                        'プロキシ種別': res.get('Proxy_Type', ''), 
                        'IoTリスク': res.get('IoT_Risk', ''), 
                        'ステータス': res.get('Status')
                    }
                    temp_data.append(row)
                df_with_res = pd.DataFrame(temp_data)

            # --- 元データ x 検索結果 クロス分析表示 ---
            if not df_with_res.empty:
                st.markdown("---")
                if st.session_state.get('ip_column_name') and st.session_state['ip_column_name'] in df_with_res.columns:
                    df_with_res['Target_IP'] = df_with_res[st.session_state['ip_column_name']].astype(str)
                    
                render_merged_analysis(df_with_res)
            # ------------------------------------------------

            # --- UI改善：ダウンロードセンター ---
        st.markdown("---")
        st.markdown("### 📥 レポート ＆ データ出力")

        # メイン：最も価値の高い「分析済みレポート」を大きく配置
        main_col1, main_col2 = st.columns(2)
        
        with main_col1:
            st.info("📊 **分析マスター (推奨)**\n\n生データに加えて、ISP別・国別・時間帯別の集計表とグラフが自動生成されたExcelファイルです。")
            if not df_with_res.empty:
                # 時間帯分析用の列選択（ひっそりと配置）
                time_cols = [c for c in df_with_res.columns if any(k in c.lower() for k in ['date', 'time', 'jst'])]
                selected_time_col = None
                if time_cols:
                    selected_time_col = st.selectbox(
                        "時間分析に使用する列:", 
                        df_with_res.columns, 
                        index=df_with_res.columns.get_loc(time_cols[0]),
                        key="time_col_selector_new"
                    )
                
                excel_advanced = create_advanced_excel(df_with_res, selected_time_col)
                st.download_button(
                    label="📥 Excelレポート (集計・グラフ付き) を保存",
                    data=excel_advanced,
                    file_name="whois_analysis_master.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    use_container_width=True,
                    type="primary"
                )
            else:
                st.button("データなし", disabled=True, use_container_width=True)

        with main_col2:
            st.success("🌐 **全件グラフ HTMLレポート**\n\nブラウザで閲覧・印刷可能なグラフィカルな分析レポートです。")
            html_report = generate_full_report_html(isp_full_df, country_full_df, freq_full_df)
            st.download_button(
                label="📥 HTMLレポート (閲覧・印刷用) を表示",
                data=html_report,
                file_name="whois_analysis_report.html",
                mime="text/html",
                use_container_width=True
            )

        # サブ：用途別のローデータ (Expanderに格納してごちゃつきを解消)
        with st.expander("🛠️ システム連携用・RAWデータ (CSV / 単純Excel)"):
            st.caption("データベースへの取り込みや、独自の加工を行いたい場合に利用してください。")
            
            sub_tab1, sub_tab2 = st.tabs(["📄 検索結果リスト", "📈 統計・カウントデータ"])
            
            with sub_tab1:
                c1, c2 = st.columns(2)
                csv_display = pd.DataFrame(display_res).astype(str)
                rename_map = {
                    'Target_IP': 'IPアドレス',
                    'Country_JP': '国名', 
                    'ISP_API_Raw': 'Whois(元データ)',
                    'ISP_JP': 'Whois(日本語名)',
                    'RDAP_Name_Raw': 'RDAP(元データ)',
                    'RDAP_JP': 'RDAP(日本語名)',
                    'Proxy_Type': 'Proxy種別',
                    'IoT_Risk': 'IoTリスク',
                    'Status': 'ステータス'
                }
                csv_display = csv_display.rename(columns=rename_map)
                with c1:
                    st.markdown("**画面表示順 (現在の並び)**")
                    st.download_button("CSV形式", csv_display.to_csv(index=False).encode('utf-8-sig'), "results_display.csv", "text/csv", use_container_width=True)
                    st.download_button("Excel形式", convert_df_to_excel(csv_display), "results_display.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", use_container_width=True)
                
                # 全入力順（アップロードしたファイルと同じ並び）
                result_lookup = {r['Target_IP']: r for r in st.session_state.raw_results}
                full_output_data = [{'Target_IP': t, **result_lookup.get(t, {'ISP': 'N/A', 'Status': 'Error'})} for t in st.session_state.get('original_input_list', [])]
                full_output_df = pd.DataFrame(full_output_data).astype(str)
                full_output_df = full_output_df.rename(columns=rename_map) # 上記のrename_mapを再利用
                csv_full = full_output_df.drop(columns=['CountryCode', 'Secondary_Security_Links', 'RIR_Link', 'ISP', 'Country'], errors='ignore')
                with c2:
                    st.markdown("**全データ (入力した順番)**")
                    st.download_button("CSV形式", csv_full.to_csv(index=False).encode('utf-8-sig'), "results_full.csv", "text/csv", use_container_width=True)
                    st.download_button("Excel形式", convert_df_to_excel(csv_full), "results_full.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", use_container_width=True)

            with sub_tab2:
                sc1, sc2, sc3 = st.columns(3)
                with sc1:
                    st.download_button("🎯 ターゲット別件数 (CSV)", freq_full_df.to_csv(index=False).encode('utf-8-sig'), "freq_all.csv", "text/csv", use_container_width=True)
                with sc2:
                    st.download_button("🏢 ISP別件数 (CSV)", isp_full_df.to_csv(index=False).encode('utf-8-sig'), "isp_all.csv", "text/csv", use_container_width=True)
                with sc3:
                    st.download_button("🌍 国別件数 (CSV)", country_full_df.to_csv(index=False).encode('utf-8-sig'), "country_all.csv", "text/csv", use_container_width=True)

if __name__ == "__main__":
    main()

# utils.py
# (純粋にPython標準ライブラリだけで動く、Streamlitに依存しないユーティリティ群)

import ipaddress
import socket
import struct
import re


def extract_actual_ip(target):
    """ 'ドメイン (IP)' の形式からIPアドレスだけを抽出する関数 """
    if not isinstance(target, str):
        return target
    if "(" in target and ")" in target:
        possible_ip = target.split("(")[-1].replace(")", "").strip()
        try:
            ipaddress.ip_address(possible_ip)
            return possible_ip
        except ValueError:
            pass
    return target

import re

def clean_ocr_error_chars(target):
    """OCR誤読やWebからのコピペゴミを除去し、デジタル分析で扱いやすい文字に強制置換する"""
    if not isinstance(target, str):
        return target
        
    # HTMLタグの除去 (例: <img src="img/dot.gif"> -> .)
    cleaned = re.sub(r'<[^>]+>', '.', target)
    
    # ＠や全角ドットを半角に
    cleaned = cleaned.replace('＠', '@').replace('．', '.')
    
    # @が含まれる場合は、メールアドレスと判定して@以降（ドメイン）だけを抽出
    if '@' in cleaned:
        cleaned = cleaned.split('@')[-1]
        
    # 連続するドットを1つに正規化
    cleaned = re.sub(r'\.+', '.', cleaned).strip()
    
    # ドメイン(IP)の複合型の場合はドメイン名破壊を防ぐためそのまま返す
    if "(" in cleaned and ")" in cleaned:
        return cleaned

    # 一旦、IP向けのOCR補正を試みる
    ocr_fixed = cleaned.replace('Ⅱ', '11').replace('I', '1').replace('l', '1').replace('|', '1')
    ocr_fixed = ocr_fixed.replace('O', '0').replace('o', '0')
    ocr_fixed = ocr_fixed.replace(';', '.').replace(',', '.')
    if ':' not in ocr_fixed:
        ocr_fixed = ocr_fixed.replace('S', '5').replace('s', '5')
        
    # 安全装置: 補正結果が正しいIPアドレスになる場合のみ、OCR補正版を採用する
    try:
        possible_ip = extract_actual_ip(ocr_fixed)
        ipaddress.ip_address(possible_ip)
        return ocr_fixed
    except ValueError:
        pass
        
    # 正しいIPにならない場合（ドメイン名など）は、文字置換せずに元の文字列を返す
    return cleaned

def is_valid_ip(target):
    try:
        ipaddress.ip_address(extract_actual_ip(target))
        return True
    except ValueError:
        return False


def is_bogon_ip(ip_str):
    """ ローカルIP、マルチキャスト、ループバック等のプライベートIPを判定する """
    try:
        ip_obj = ipaddress.ip_address(extract_actual_ip(ip_str))
        if ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_link_local or ip_obj.is_private or ip_obj.is_reserved:
            return True
        if ip_obj.version == 4 and str(ip_obj).startswith('0.'):
            return True
        return False
    except ValueError:
        return False


def is_valid_domain(target):
    """ 入力された文字列が有効なFQDN（ドメイン名）の形式を満たしているか判定する """
    if not isinstance(target, str):
        return False
    if is_valid_ip(target):
        return False
    if '.' not in target or target.startswith('.') or target.endswith('.'):
        return False
    if re.search(r'\s', target):
        return False
    parts = target.split('.')
    if len(parts) < 2 or not parts[-1].isalpha() or len(parts[-1]) < 2:
        return False
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


# ===========================================================================
# DuckDB による IPレンジ検索 (Streamlitには依存しない、生の DuckDB API)
# ===========================================================================
# ※ @st.cache_resource は呼び出し側 (WhoisApp260719-09.py) で
#    接続オブジェクトをキャッシュする形にする。utils 自体は装飾しない。
import duckdb

_DB_CONN = None  # プロセス内で単一の接続を共有


def get_db_connection():
    """ 永続化されたDuckDBファイルへの接続 (なければ作成) """
    global _DB_CONN
    if _DB_CONN is None:
        _DB_CONN = duckdb.connect("whois_intel.db")
        _DB_CONN.execute("""
            CREATE TABLE IF NOT EXISTS ip_proxy_db (
                ip_from INTEGER,
                ip_to   INTEGER,
                proxy_type VARCHAR
            )
        """)
    return _DB_CONN


def query_local_proxy_db(ip):
    """ 指定IPがローカルDB上のプロキシリストに含まれるか検索 """
    try:
        ip_int = ip_to_int(ip)
        conn = get_db_connection()
        query = f"SELECT proxy_type FROM ip_proxy_db WHERE {ip_int} BETWEEN ip_from AND ip_to LIMIT 1"
        result = conn.execute(query).fetchone()
        if result:
            return result[0]
    except Exception as e:
        import logging
        logging.error(f"Local DB Search Error: {e}")
    return None


def classify_local_proxy(actual_ip, threat_intel_list, proxy_intel_list):
    """
    ローカルDBベースでプロキシ種別を判定する（同期/非同期共通）

    返り値: Proxy_Type 列に格納する文字列 (str) or None
      - 文字列例: "VPN (Source: IP2Location LITE)" / "Open Proxy (Source: FireHOL)"
      - None: 該当なし

    備考: 脅威インテリジェンス (Abuse.ch) のヒットは呼び出し側で
          `actual_ip in threat_intel_list` のチェックで別途処理する
    """
    # 2. IP2Location LITE (DuckDB) — 同モジュール内の query_local_proxy_db を直接呼ぶ
    local_proxy_type = query_local_proxy_db(actual_ip)
    if local_proxy_type:
        return f"{local_proxy_type} (Source: IP2Location LITE)"

    # 3. FireHOL
    if proxy_intel_list and actual_ip in proxy_intel_list:
        return "Open Proxy (Source: FireHOL)"

    return None

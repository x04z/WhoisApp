import streamlit as st
import pandas as pd
import requests
import time
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import socket
import struct
import random
import ipaddress
from urllib.parse import quote # URLエンコードに使用

# --- 設定：API通信と並行処理 ---
# 【重要】レートリミット対策として、無料枠(45req/min)に対し安全な値に調整
MAX_WORKERS = 3
DELAY_BETWEEN_REQUESTS = 1.4 # 約42req/min 程度に抑え、安全性を高める

# IP-APIでISP情報と国情報を取得
IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,country,isp,query,message"

# --- RIR/RegistryのURL定義 ---
RIR_LINKS = {
    # 検索IPを直接埋め込む (IPv6対応)
    'RIPE': 'https://apps.db.ripe.net/db-web-ui/#/query?searchtext={ip}',
    'ARIN': 'https://search.arin.net/rdap/?query={ip}',
    # 検索フォームへ誘導（手動検索が必要）
    'APNIC': 'https://wq.apnic.net/static/search.html',
    'JPNIC': 'https://www.nic.ad.jp/ja/whois/ja-gateway.html',
    'AFRINIC': 'https://www.afrinic.net/whois',
    'ICANN Whois': 'https://lookup.icann.org/',
}

# --- 国名からRIRを判定するマッピング (IP-APIは国名を返すため) ---
COUNTRY_TO_RIR = {
    'Japan': 'JPNIC',
    'United States': 'ARIN', 'Canada': 'ARIN', 'Mexico': 'LACNIC',
    'Germany': 'RIPE', 'France': 'RIPE', 'United Kingdom': 'RIPE', 'Russia': 'RIPE',
    'China': 'APNIC', 'Australia': 'APNIC', 'South Korea': 'APNIC', 'India': 'APNIC',
    'Brazil': 'LACNIC', 'Argentina': 'LACNIC',
    'Egypt': 'AFRINIC', 'South Africa': 'AFRINIC',
}

# --- グローバルなrequestsセッションを初期化 (レートリミット対策) ---
@st.cache_resource
def get_session():
    """requests.Sessionを初期化し、User-Agentを設定"""
    session = requests.Session()
    # 適切なUser-Agentを設定
    session.headers.update({"User-Agent": "WhoisBatchTool/1.3 (+PythonStreamlitApp)"})
    return session

session = get_session()

# --- IPアドレスの検証ヘルパー関数 ---
def is_valid_ip(target):
    """IPv4またはIPv6アドレス形式であるかを判定"""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False

def is_ipv4(target):
    """ターゲットがIPv4アドレス形式であるかを判定"""
    try:
        ipaddress.IPv4Address(target)
        return True
    except ValueError:
        return False

# --- IPアドレスを32bit整数に変換するヘルパー関数 (IPv4専用) ---
def ip_to_int(ip):
    """IPv4アドレス文字列を整数に変換"""
    try:
        if is_ipv4(ip):
            # !I はネットワークバイト順の符号なし整数 (32bit)
            return struct.unpack("!I", socket.inet_aton(ip))[0]
        return 0
    except OSError:
        return 0

# --- 権威あるRIRリンクを生成する関数 ---
def get_authoritative_rir_link(ip, country):
    """国名に基づき、唯一の正式なRIRリンクを特定し生成する"""

    rir_name = COUNTRY_TO_RIR.get(country)

    # JPNIC, APNICなど、検索フォームへの誘導が必要なRIR
    if rir_name in ['JPNIC', 'APNIC', 'LACNIC', 'AFRINIC']:
        # IPを含めない静的リンクまたは検索フォームへ誘導
        return f"[{rir_name} (手動検索)]({RIR_LINKS[rir_name]})"

    # RIPE, ARINはIPv6検索に対応しており、IPを埋め込み可能
    if rir_name in ['RIPE', 'ARIN']:
        # IPv6のコロンがURLを壊さないよう、URLエンコードを適用 (最重要)
        encoded_ip = quote(ip, safe='')
        link_url = RIR_LINKS[rir_name].format(ip=encoded_ip)
        # IPv6の場合もリンクは有効。手動検索は不要
        return f"[{rir_name}]({link_url})"

    # フォールバック処理
    return f"[APNIC (Fallback - 手動検索)]({RIR_LINKS['APNIC']})"


# --- 二次調査サイトのリンク生成関数 ---
def create_secondary_links(target):
    """信頼性の高いセキュリティ・Whois調査サイトへのリンクを生成する。IPv6の場合は検索実績のあるサイトに限定する。"""

    # URLエンコードを適用して、IPアドレスやドメインがURL内で安全に扱われるようにする
    encoded_target = quote(target, safe='')
    is_ip = is_valid_ip(target)
    is_ipv6 = is_ip and not is_ipv4(target) # IPv6判定

    # Who.is のリンクをIPアドレスのタイプに応じて調整
    who_is_url = f'https://who.is/whois-ip/ip-address/{encoded_target}' if is_ip else f'https://who.is/whois/{encoded_target}'

    # --- DNS Checkerリンクの処理 (動的キーの挿入) ---
    dns_checker_url = ''
    dns_checker_key = ''

    if is_ip:
        # IPアドレスの場合
        dns_checker_path = 'ipv6-whois-lookup.php' if is_ipv6 else 'ip-whois-lookup.php'
        dns_checker_url = f'https://dnschecker.org/{dns_checker_path}?query={encoded_target}'

        if is_ipv6:
            # ユーザー要望に基づき、IPv6の場合は手動を明記し、一意なキーとする
            dns_checker_key = 'DNS Checker (手動 - IPv6)'
        else:
            # IPv4の場合は自動検索
            dns_checker_key = 'DNS Checker'
    else:
        # ドメインの場合
        dns_checker_url = f'https://dnschecker.org/whois-lookup.php?query={encoded_target}'
        dns_checker_key = 'DNS Checker (ドメイン)'


    # 基本のリンクセット
    all_links = {
        'VirusTotal': f'https://www.virustotal.com/gui/search/{encoded_target}',
        'Aguse': f'https://www.aguse.jp/?url={encoded_target}',
        'Whois.com': f'https://www.whois.com/whois/{encoded_target}',
        'DomainSearch.jp': f'https://www.domainsearch.jp/whois/?q={encoded_target}',
        'Who.is': who_is_url,
        'IP2Proxy': f'https://www.ip2proxy.com/{encoded_target}',
        # 手動検索リンク（IP埋め込み不可のため手動を維持）
        'DNSlytics (手動)': 'https://dnslytics.com/whois-lookup/',
        'IP Location (手動)': 'https://iplocation.io/ip-whois-lookup',
        'CP-WHOIS (手動)': 'https://doco.cph.jp/whoisweb.php',
    }

    # 動的に生成したDNS Checkerのリンクを追加
    if dns_checker_url:
        all_links[dns_checker_key] = dns_checker_url # 動的キーでリンクを追加

    # IPv6の場合は、リンクを限定
    if is_ipv6:
        # IPv6対応のIP埋め込みサイトと、手動検索サイトに限定
        links = {
            'VirusTotal': all_links['VirusTotal'],
            # DomainSearch.jp は IP/Domain 検索に対応
            'DomainSearch.jp': all_links['DomainSearch.jp'],
            dns_checker_key: all_links[dns_checker_key], # 動的なキーを使用
            'IP2Proxy': all_links['IP2Proxy'], # IPv6もIPアドレス検索に対応
            'DNSlytics (手動)': all_links['DNSlytics (手動)'],
            'IP Location (手動)': all_links['IP Location (手動)'],
            'CP-WHOIS (手動)': all_links['CP-WHOIS (手動)'],
        }
    else:
        # IPv4またはドメインの場合は全リンクを表示
        links = all_links

    link_html = ""
    for name, url in links.items():
        link_html += f"[{name}]({url}) | "

    return link_html.rstrip(' | ')


# --- IP情報をAPIで取得する関数 (リトライ機構付き) ---
def get_ip_details_from_api(ip):
    """IPアドレスの詳細情報をAPI経由で取得し、RIRリンクを判定する"""

    result = {
        'Target_IP': ip,
        'ISP': 'N/A',
        'Country': 'N/A',
        'RIR_Link': 'N/A',
        'Secondary_Security_Links': 'N/A',
        'Status': 'N/A'
    }

    # リトライ機構の導入 (最大3回試行)
    for attempt in range(3):
        try:
            # 1.4秒待機 (安全なレートリミット対策)
            time.sleep(DELAY_BETWEEN_REQUESTS)

            url = IP_API_URL.format(ip=ip)
            response = session.get(url, timeout=8)

            # レートリミット応答(429)の検出
            if response.status_code == 429:
                if attempt == 2:
                    result['Status'] = 'Final Error: Rate Limit (429)'
                    break

                st.warning(f"⚠️ Rate Limit (429) detected. Waiting 60 seconds for retry ({ip}).")
                time.sleep(60)
                continue # 次のattemptへ

            response.raise_for_status() # 2xx以外のステータスコードはここで例外発生
            data = response.json()

            if data.get('status') == 'success':
                country = data.get('country', 'N/A')
                result['ISP'] = data.get('isp', 'N/A')
                result['Country'] = country
                # IPv4/IPv6両対応のRIRリンクを生成
                result['RIR_Link'] = get_authoritative_rir_link(ip, country)

                status_type = "IPv6 API" if not is_ipv4(ip) else "IPv4 API"
                result['Status'] = f'Success ({status_type})'
                break # 成功したのでループを抜ける
            elif data.get('status') == 'fail':
                     # API側で失敗が明示された場合（例: Private IP, Reserved IP, Invalid Query）
                result['Status'] = f"API Fail: {data.get('message', 'Unknown Fail')}"
                result['RIR_Link'] = get_authoritative_rir_link(ip, 'N/A')
                break
            else:
                     # 想定外の応答
                result['Status'] = f"API Error: Unknown Response"
                result['RIR_Link'] = get_authoritative_rir_link(ip, 'N/A')
                break

        except requests.exceptions.RequestException as e:
            # ネットワークエラーやタイムアウト
            if attempt == 2:
                result['Status'] = f'Final Error: Network/Timeout ({type(e).__name__})'
            else:
                time.sleep(3) # 短い時間待ってリトライ
                continue # 次のattemptへ

    # IPv6アドレスも二次調査サイトのリンク生成の対象
    result['Secondary_Security_Links'] = create_secondary_links(ip)

    return result

# --- ドメイン情報取得関数 (Whoisリンクのみ) ---
def get_domain_details(domain):
    """ドメイン名に対するWhoisリンクのみを生成する"""

    # ICANNのWhois検索ページへ誘導
    icann_link = f"[ICANN Whois (手動検索)]({RIR_LINKS['ICANN Whois']})"

    return {
        'Target_IP': domain,
        'ISP': 'Domain/Host',
        'Country': 'N/A',
        'RIR_Link': icann_link,
        'Secondary_Security_Links': create_secondary_links(domain),
        'Status': 'Success (Domain)'
    }

# --- 簡易モード用（API通信なし）のダミー情報取得関数 ---
def get_simple_mode_details(target):
    """簡易モード用のダミー情報を生成する。ISP/CountryはN/A、RIRリンクはSecondaryリンクを流用。"""
    return {
        'Target_IP': target,
        'ISP': 'N/A (簡易モード)',
        'Country': 'N/A (簡易モード)',
        'RIR_Link': create_secondary_links(target), # 簡易モードではSecondaryリンクをここに表示
        'Secondary_Security_Links': '', # RIR_Linkで表示済みのため空欄
        'Status': 'Success (簡易モード)'
    }


# --- 結果を集約する関数 (ISPとCountryでグループ化) ---
# ※ この機能はIPv4のみを対象とします（IPv6は集約の複雑さが高いため）
def group_results_by_isp(results):
    """IPv4アドレスのみを対象に、ISPとCountryが同じIPアドレスをグループ化し、範囲表示に変換する"""
    grouped = {}
    final_grouped_results = []

    # 1. IPv4以外、情報欠損、またはドメインを集約対象外として先にリストに追加
    non_aggregated_results = []
    for res in results:
        is_ip = is_valid_ip(res['Target_IP'])

        # IPv6またはドメイン、またはAPI情報が欠けている場合は集約対象外
        if not is_ip or not is_ipv4(res['Target_IP']) or res['ISP'] == 'N/A' or res['Country'] == 'N/A' or res['ISP'] == 'N/A (簡易モード)': # 簡易モードも集約対象外
            non_aggregated_results.append(res)
            continue

        # IPv4のみを対象
        key = (res['ISP'], res['Country'])
        if key not in grouped:
            # グループキーが存在しない場合、新しいグループを初期化
            grouped[key] = {
                'IP_Ints': [],
                'IPs_List': [],
                'RIR_Link': res['RIR_Link'],
                # キーは 'Secondary_Security_Links' で統一
                'Secondary_Security_Links': res['Secondary_Security_Links'],
                'ISP': res['ISP'],
                'Country': res['Country'],
                'Status': res['Status']
            }

        # IPv4への変換時にエラーが発生した場合も安全に処理
        ip_int = ip_to_int(res['Target_IP'])
        if ip_int != 0:
            grouped[key]['IP_Ints'].append(ip_int)
            grouped[key]['IPs_List'].append(res['Target_IP'])
        else:
            # IPv4と判定されてもip_to_intで失敗するケース(非常に稀)
            res['Status'] = 'Error: IPv4 Int Conversion Failed'
            non_aggregated_results.append(res)

    final_grouped_results.extend(non_aggregated_results)

    # 2. グループごとに範囲を決定し、整形
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
            # 念のためフォールバック
            min_ip = data['IPs_List'][0]
            max_ip = data['IPs_List'][-1]


        if count == 1:
            target_ip_display = min_ip
            status_display = data['Status']
        else:
            target_ip_display = f"{min_ip} - {max_ip} (x{count} IPs)"
            status_display = f"Aggregated ({count} IPs)"

        final_grouped_results.append({
            'Target_IP': target_ip_display,
            'Country': data['Country'],
            'ISP': data['ISP'],
            'RIR_Link': data['RIR_Link'],
            'Secondary_Security_Links': data['Secondary_Security_Links'],
            'Status': status_display
        })

    return final_grouped_results

# --- 結果を表示する関数 ---
def display_results(results_to_display, display_mode):
    """結果をStreamlitのカスタムグリッドとして表示し、すべてのターゲットに対してコピー補助機能を提供する"""

    st.markdown("### 📝 検索結果")

    # 結果件数が多いときのためのコンテナでテーブルを囲む
    with st.container(height=600):
        # 1. ヘッダー行
        # 簡易モードでは列数を5列に限定してレイアウト崩れを防止
        if display_mode == "簡易モード (APIなし - セキュリティリンクのみ)":
            col_widths = [0.6, 3.0, 3.0, 0.9, 0.6]  # No., Target, RIR, Status, Checkbox
            cols = st.columns(col_widths)
            header_cols = cols
            header_names = ["No.", "Target IP", "RIR Links", "Status", "✅"]
        else:
            col_widths = [0.5, 1.0, 1.0, 1.0, 1.8, 2.2, 0.9, 0.5]
            cols = st.columns(col_widths)
            header_cols = cols
            header_names = ["No.", "Target IP", "Country", "ISP", "RIR Links", "Secondary Links", "Status", "✅"]

        header_style = "font-weight: bold; background-color: #f0f2f6; padding: 10px; border-radius: 5px; color: #1e3a8a;"

        for i, name in enumerate(header_names):
            with header_cols[i]:
                st.markdown(f'<div style="{header_style}">{name}</div>', unsafe_allow_html=True)

        st.markdown("--- ")

        # 2. 結果行
        for i, row in enumerate(results_to_display):
            ip_display = row['Target_IP']
            rir_link_markdown = row['RIR_Link']
            secondary_links = row['Secondary_Security_Links'].replace('\n', ' ')

            checkbox_key = f"checked_{ip_display}_{i}"
            target_to_copy = ip_display.split(' - ')[0].split(' ')[0]

            # 行用のカラムはヘッダーと同じ幅で生成
            row_cols = st.columns(col_widths)

            # 簡易モード（5列）と通常モード（8列）で描画するカラムインデックスを分ける
            if display_mode == "簡易モード (APIなし - セキュリティリンクのみ)":
                with row_cols[0]:
                    st.markdown(f"**{i + 1}**")
                with row_cols[1]:
                    st.markdown(ip_display)
                with row_cols[2]:
                    st.markdown(rir_link_markdown)
                    st.code(target_to_copy, language=None)
                with row_cols[3]:
                    st.markdown(row.get('Status', ''))
                with row_cols[4]:
                    if checkbox_key not in st.session_state:
                        st.session_state[checkbox_key] = False
                    st.checkbox("", key=checkbox_key, help="この調査が完了したかを手動でマーク")
            else:
                with row_cols[0]: st.markdown(f"**{i + 1}**")
                with row_cols[1]: st.markdown(ip_display)
                with row_cols[2]: st.markdown(row.get('Country', ''))
                with row_cols[3]: st.markdown(row.get('ISP', ''))
                with row_cols[4]:
                    st.markdown(rir_link_markdown)
                    st.code(target_to_copy, language=None)
                with row_cols[5]: st.markdown(secondary_links)
                with row_cols[6]: st.markdown(row.get('Status', ''))
                with row_cols[7]:
                    if checkbox_key not in st.session_state:
                        st.session_state[checkbox_key] = False
                    st.checkbox("", key=checkbox_key, help="この調査が完了したかを手動でマーク")

            if i < len(results_to_display) - 1:
                st.markdown('<div style="margin-top: 5px; margin-bottom: 5px; border-bottom: 1px solid #eee;"></div>', unsafe_allow_html=True)

    st.markdown("--- ")

# --- Streamlitアプリのメイン処理 ---
def main():
    # Streamlitセッション状態にキャンセルフラグと結果キャッシュを初期化
    if 'cancel_search' not in st.session_state:
        st.session_state['cancel_search'] = False
    # 検索結果をキャッシュするためのキー
    if 'raw_results' not in st.session_state:
        st.session_state['raw_results'] = []
    # 検索に使ったターゲットリストをキャッシュするためのキー
    if 'targets_cache' not in st.session_state:
        st.session_state['targets_cache'] = []

    st.set_page_config(layout="wide")

    st.markdown('<h1 style="color: #1e3a8a; text-shadow: 1px 1px 2px #9ca3af; font-weight: bold;">🌐WhoisSearch</h1>', unsafe_allow_html=True)
    st.markdown("IPアドレス/ドメインリストを解析し、国情報に基づき**管轄RIRリンク**を自動判定します。**IPv4/IPv6の両方に対応**しています。")

    # --- Whois特性比較テーブルの追加 ---
    st.markdown("""
### 🔎 各Whois/セキュリティ検索リソースの特性比較

| リソース | 説明 |
| :--- | :--- |
| **公式RIRレジストリ** (APNIC, JPNIC, RIPEなど) | **正確性、権威性が最も高く**、IPアドレスの**割り当て元情報**（組織名、連絡先）が確認できます。ただし、**JPNIC/APNIC/LACNIC/AFRINICは手動入力が必要**な検索ページへ誘導されます。 |
| **VirusTotal** | **セキュリティ上の評判**（マルウェア、攻撃履歴）に関する情報が確認できます。 |
| **Whois.com / Who.is IP** | 公式RIRの情報を**見やすいUIで集約**して提供しており、ドメイン名とIPアドレスの両方のWhois検索に利用しやすいです。 |
| **DomainSearch.jp / Aguse** | 日本国内のサービスであり、IPアドレスのほか、**関連するドメイン名、ネームサーバ、Webサイトの安全性**を複合的に調査できます。 |
| **IP2Proxy** | IPアドレスが**プロキシ、VPN、TORノードなどの匿名化技術**を使用しているかどうかの判定に特化しています。|
| **DNS Checker** | IPv6対応。DNSレコードの状況や、IPアドレスのWhois情報を取得できる**多機能なDNS・Whoisツール**です。 |
| **DNSlytics / IP Location** | IPv6対応。IPアドレスやドメインに関連する地理情報、ホスティング情報、逆引きDNS情報などを確認するための**補助的な手動検索リソース**です。 |
| **CP-WHOIS** | **信頼性**が高いWhois検索サイト。利用者認証が必要。 |
""")
    # --- モード選択のラジオボタン ---
    display_mode = st.radio(
        "📝 結果の表示モードを選択してください:",
        ("標準モード (1ターゲット = 1行)", "集約モード (IPv4アドレスをISP/国別でグループ化)", "簡易モード (APIなし - セキュリティリンクのみ)"),
        horizontal=True,
        key="display_mode_radio" # キーを追加
    )

    # --- 1. 手動IPアドレス入力 ---
    manual_input = st.text_area(
        "または、IPアドレス/ドメイン名を直接入力してください (複数行可)",
        height=100,
        placeholder="例:\n8.8.8.8\nexample.com\n2404:6800:4004:80c::2004 (IPv6も可)"
    )

    # --- 2. ファイルアップロード ---
    uploaded_file = st.file_uploader("ターゲットリストのテキストファイルをアップロードしてください (1行に1つのターゲット)", type=['txt'])

    # --- ターゲットリストの決定と分類 ---
    targets = []

    if manual_input:
        targets.extend(manual_input.splitlines())

    if uploaded_file is not None:
        targets.extend(uploaded_file.read().decode("utf-8").splitlines())

    # --- 構文エラーを修正したリスト内包表記 ---
    targets = [t.strip() for t in targets if t.strip()]

    # IPアドレスとドメインに分類
    ip_targets = []
    domain_targets = []
    ipv6_count = 0

    for t in targets:
        if is_valid_ip(t):
            ip_targets.append(t)
            if not is_ipv4(t):
                ipv6_count += 1
        else:
            domain_targets.append(t)

    # ターゲットリストが変更されたかどうかをチェック
    has_new_targets = (targets != st.session_state.targets_cache)

    if len(targets) > 0:
        ipv4_count = len(ip_targets) - ipv6_count
        st.write(f"✅ **ターゲット数:** **{ipv4_count}** 件のIPv4、**{ipv6_count}** 件のIPv6、**{len(domain_targets)}** 件のドメインが見つかりました。")

        # 4. 検索実行ボタン
        execute_search = st.button(
            "🚀Whois検索実行",
            key="execute_search",
            # 新しいターゲットがない場合はボタンを無効化（誤実行防止）
            disabled=st.session_state.cancel_search or not has_new_targets
        )

        # 処理中に「キャンセル」ボタン
        if st.session_state.cancel_search or (execute_search and has_new_targets):
             cancel_button = st.button("❌ 処理中止", key="cancel_search_btn", type="secondary")
             if cancel_button:
                 st.session_state.cancel_search = True
                 st.warning("処理を中断しています...")
                 st.rerun()

        # 3. 入力ターゲットリストの確認セクションをボタンの下に配置 (修正済み)
        with st.expander("📝 入力ターゲットリストの確認"):
             st.code("\n".join(targets), language=None)

        # --- メイン検索ロジック ---
        if execute_search and has_new_targets and not st.session_state.cancel_search:

            st.session_state.cancel_search = False # 念のためリセット
            st.session_state.raw_results = [] # 新規検索のためキャッシュをクリア
            st.session_state.targets_cache = targets # ターゲットリストをキャッシュ

            # --- プログレスバーと進捗表示領域を確保 ---
            st.subheader("処理進捗")
            progress_container = st.container()
            status_placeholder = progress_container.empty()
            progress_placeholder = progress_container.empty()


            total_ip_targets = len(ip_targets)
            processed_count = 0
            raw_results = []

            # ドメインの静的結果を事前に追加
            if display_mode == "簡易モード (APIなし - セキュリティリンクのみ)":
                raw_results.extend([get_simple_mode_details(d) for d in domain_targets])
            else:
                raw_results.extend([get_domain_details(d) for d in domain_targets])

            # トリビアの更新間隔を30秒に設定
            tip_update_interval = 30.0
            last_tip_time = time.time()

            # 【改善点】処理開始時にスピナーを表示し、UXを向上
            with st.spinner(f"API検索を開始しています... ({total_ip_targets} 件のIPを処理予定)"):
                time.sleep(1) # スピナー表示のための短い待機

                if st.session_state.cancel_search:
                     st.warning("検索がキャンセルされました。")
                     return

                if display_mode == "簡易モード (APIなし - セキュリティリンクのみ)":
                    # 簡易モードではAPI呼び出しをスキップし、ダミー情報を生成
                    for ip in ip_targets:
                        raw_results.append(get_simple_mode_details(ip))
                        processed_count += 1

                        percent_complete = int((processed_count / total_ip_targets) * 100) if total_ip_targets > 0 else 100
                        progress_placeholder.progress(percent_complete)
                        status_placeholder.markdown(f"**🔍 処理中:** **{processed_count}** / **{total_ip_targets}** 件のIPアドレスを処理完了 ({percent_complete}%) | 簡易モード (APIスキップ)")
                        time.sleep(0.01) # UI更新のための短い待機

                else:
                    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                        future_to_ip = {executor.submit(get_ip_details_from_api, ip): ip for ip in ip_targets}
                        remaining_futures = set(future_to_ip.keys())

                        while remaining_futures and not st.session_state.cancel_search:
                            # 0.1秒ごとに完了したFutureを確認
                            done, not_done = wait(
                                remaining_futures,
                                timeout=0.1,
                                return_when=FIRST_COMPLETED
                            )

                            # 1. 完了したタスクを処理
                            for future in done:
                                result = future.result()
                                raw_results.append(result)
                                processed_count += 1
                                remaining_futures.remove(future)

                            # 2. 進捗とステータスを更新
                            if total_ip_targets > 0:
                                percent_complete = int((processed_count / total_ip_targets) * 100)

                                # 残り時間目安 (ETA)
                                remaining_tasks = total_ip_targets - processed_count
                                # リクエスト間の遅延時間 (DELAY_BETWEEN_REQUESTS) に基づき推定
                                estimated_seconds = remaining_tasks * DELAY_BETWEEN_REQUESTS / MAX_WORKERS

                                if estimated_seconds > 60:
                                     eta_display = f"{int(estimated_seconds / 60)}分 {int(estimated_seconds % 60)}秒"
                                else:
                                     eta_display = f"{int(estimated_seconds)}秒"

                                progress_placeholder.progress(percent_complete)
                                status_placeholder.markdown(f"**🔍 処理中:** **{processed_count}** / **{total_ip_targets}** 件のIPアドレスを処理完了 ({percent_complete}%) | **ETA: 約{eta_display}**")

                            # 3. トリビアの更新 (30秒ごと)
                            if time.time() - last_tip_time >= tip_update_interval and processed_count < total_ip_targets:
                                # display_prefecture_trivia(tip_placeholder) # この関数は定義されていないためコメントアウト
                                last_tip_time = time.time()

                            time.sleep(0.1) # スレッドがCPUを占有しすぎないように待機

            if st.session_state.cancel_search:
                 st.warning("❌ 検索はユーザーによって中断されました。今回はまだ結果が生成されていないため、表示されるものはありません。")
            else:
                 st.success("🎉 検索が完了しました！")
                 st.session_state.raw_results = raw_results # 検索結果をセッションに保存

    # --- キャッシュされた結果の表示ロジック ---
    if st.session_state.raw_results:
        results_to_process = st.session_state.raw_results

        # --- 集約ロジックの適用 ---
        if display_mode == "集約モード (IPv4アドレスをISP/国別でグループ化)":
            st.info("💡 **集約モード**：**IPv4アドレスのみを対象**に、同じISPとCountryを持つものをまとめて表示しています。IPv6とドメイン名は個別表示です。")
            results_to_display = group_results_by_isp(results_to_process)
        elif display_mode == "簡易モード (APIなし - セキュリティリンクのみ)":
            st.info("💡 **簡易モード**：APIへの通信は行わず、二次セキュリティリンクのみを表示しています。")
            results_to_display = results_to_process
        else:
            st.info("💡 **標準モード**：入力されたターゲット全てを個別に表示しています。")
            results_to_display = results_to_process

        # 結果のテーブル描画とコピー機能の表示
        display_results(results_to_display, display_mode)

        # 7. 結果のダウンロード機能
        if len(results_to_process) > 0:
            df_download = pd.DataFrame(results_to_process)

            df_download = df_download.rename(columns={
                'Target_IP': 'Target IP',
                'RIR_Link': 'RIR Link',
                'Secondary_Security_Links': 'Secondary Security Links'
            })
            # Adjust columns for download based on display mode
            if display_mode == "簡易モード (APIなし - セキュリティリンクのみ)":
                df_download = df_download[['Target IP', 'RIR Link', 'Status']]
            else:
                df_download = df_download[['Target IP', 'Country', 'ISP', 'RIR Link', 'Secondary Security Links', 'Status']]

            # CSVとしてダウンロード
            csv = df_download.to_csv(index=False).encode('utf-8')

            st.download_button(
                label="⬇️ 結果を CSV ファイルでダウンロード",
                data=csv,
                file_name='ip_whois_results_final.csv',
                mime='text/csv',
            )

if __name__ == "__main__":
    main()


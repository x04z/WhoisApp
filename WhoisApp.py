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
DELAY_BETWEEN_REQUESTS = 4.3 # 約42req/min 程度に抑え、安全性を高める (3 worker * 4.3 sec/req -> 約42req/min)

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
    'ICANN Whois': 'https://lookup.icann.org/', # 追加
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
        if not is_ip or not is_ipv4(res['Target_IP']) or res['ISP'] == 'N/A' or res['Country'] == 'N/A':
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


# --- 47都道府県のトリビアデータ (3つの真面目な豆知識と2つのユーモアのある豆知識) ---
# このデータは、ユーザーの要望に基づき、AIモデルが生成し組み込んだものです。
PREFECTURE_TRIVIA_47 = {
    '北海道': {
        'serious_1': "日本の食料自給率はカロリーベースで38%だが、北海道単体だと200%を超え、日本全体の食を支えている。",
        'serious_2': "全国で最も多い火山数を誇る。温泉地が多い理由の一つ。",
        'serious_3': "公立高校の受験は、学区制ではなく全道一学区制を採用している。",
        'humorous_1': "北海道民は「道民」と称されるが、道外への引っ越しは「内地へ行く」と表現することが多い。",
        'humorous_2': "コンビニのレジ袋は有料化以前から基本的に無料だったため、エコバッグ文化が遅れたと言われる。",
    },
    '青森県': {
        'serious_1': "リンゴの生産量は全国1位で、約50種類もの品種が栽培されている。",
        'serious_2': "縄文時代の三内丸山遺跡は、約5900年前から4200年前の集落跡であり、規模は日本最大級。",
        'serious_3': "世界遺産の白神山地は、東アジアで最大級のブナの原生林が広がる。",
        'humorous_1': "夏には冷たい「生姜味噌おでん」を食べる。寒い時期に温まるための食べ物が、冷やされる理由は謎。",
        'humorous_2': "県内の鉄道には、冬にストーブ列車が走り、車内でスルメを焼くことができる。",
    },
    '岩手県': {
        'serious_1': "県の面積は北海道に次いで全国2位だが、人口密度は全国で下から2番目に低い。",
        'serious_2': "平泉にある中尊寺金色堂は、建立から約900年が経過しているにもかかわらず、現在も当時のままの姿を保っている。",
        'serious_3': "宮沢賢治の出身地であり、彼の作品に登場する場所のモデルが数多く存在する。",
        'humorous_1': "麺類の消費量が非常に高く、わんこそば、盛岡冷麺、じゃじゃ麺を合わせて「盛岡三大麺」と呼ぶ。",
        'humorous_2': "小岩井農場のソフトクリームはあまりにも有名で、県民の多くは「小岩井農場ソフトクリーム」と聞くと小躍りする。",
    },
    '宮城県': {
        'serious_1': "松島は日本三景の一つであり、大小260余りの島々が浮かぶ景勝地である。",
        'serious_2': "仙台市は「杜の都」と呼ばれ、市内中心部にもケヤキ並木などの緑が多い。",
        'serious_3': "伊達政宗が築いた仙台城（青葉城）の石垣は、自然の地形を活かした難攻不落の構造であった。",
        'humorous_1': "地元テレビ局のゆるキャラ「おにぎりくん」は、見た目がシンプルすぎて県外で驚かれる。",
        'humorous_2': "牛タンは仙台名物だが、牛自体は宮城県産ではないことが多い。輸入牛に感謝。",
    },
    '秋田県': {
        'serious_1': "「秋田美人」で知られるが、これは日照時間の短さから肌が白く保たれるためと言われている。",
        'serious_2': "国の重要無形民俗文化財に指定されている「なまはげ」は、怠惰を戒める神の使いとされる。",
        'serious_3': "田沢湖は水深が423.4mあり、日本で最も深い湖である。",
        'humorous_1': "郷土料理の「きりたんぽ」は、炊いたご飯を潰して棒に巻き付けて焼いたもので、見た目が薪ストーブの燃料に似ている。",
        'humorous_2': "秋田犬は忠犬ハチ公の犬種として有名だが、街中で見かけることは稀で、見かけると幸運と言われる。",
    },
    '山形県': {
        'serious_1': "将棋の駒の生産量が日本一で、特に天童市は将棋の街として知られている。",
        'serious_2': "山寺（立石寺）は、松尾芭蕉が『奥の細道』で「閑さや岩にしみ入る蝉の声」と詠んだことで有名。",
        'serious_3': "サクランボ（特に佐藤錦）の収穫量は全国トップクラスで、日本の約7割を占める。",
        'humorous_1': "冬の風物詩である「樹氷」は、巨大な雪の怪物のように見えるため、観光客を驚かせる。",
        'humorous_2': "芋煮会は一大イベントで、参加人数や鍋の大きさで競う「日本一の芋煮フェスティバル」が開かれる。",
    },
    '福島県': {
        'serious_1': "全国3位の広大な面積を持ち、会津、中通り、浜通りの3つの異なる地域に分けられる。",
        'serious_2': "日本三大ラーメンの一つとされる喜多方ラーメンの発祥地である。",
        'serious_3': "猪苗代湖は、日本で4番目に大きな湖で、水質も非常に良い。",
        'humorous_1': "赤べこは郷土玩具として有名だが、首が勝手にゆらゆら揺れる様子はどこかシュール。",
        'humorous_2': "円盤餃子は、円盤状にきれいに並べて焼くスタイルで、見た目がUFOに似ている。",
    },
    '茨城県': {
        'serious_1': "納豆の消費量が全国トップクラスで、特に水戸納豆は有名である。",
        'serious_2': "日本の三大庭園の一つ、偕楽園は、梅の名所として知られている。",
        'serious_3': "つくば市には宇宙航空研究開発機構（JAXA）をはじめとする研究機関が集積している。",
        'humorous_1': "茨城には「いばらぎ」ではなく「いばらき」と読むのが正解。県民は常に訂正の準備ができている。",
        'humorous_2': "メロンの生産量が日本一。ただし、ほとんどが地元で消費されるため、幻のメロンになりがち。",
    },
    '栃木県': {
        'serious_1': "日光東照宮は、徳川家康を祀る神社であり、豪華絢爛な「陽明門」は国宝である。",
        'serious_2': "餃子の街として知られる宇都宮市は、1世帯あたりの餃子購入額で常に上位を争う。",
        'serious_3': "那須高原は皇室の静養地としても利用される自然豊かなリゾート地である。",
        'humorous_1': "栃木県民にとって、テレビ番組で栃木が取り上げられると、その日は県民の祝日となる。",
        'humorous_2': "とちぎ和牛のパッケージには牛の絵が描かれているが、その牛の顔は妙に真顔でシュール。",
    },
    '群馬県': {
        'serious_1': "上毛かるたは県民の必須教養であり、県民の誰もが「つる舞う形の群馬県」を詠める。",
        'serious_2': "こんにゃくの生産量が日本一で、全国シェアの約9割を占めている。",
        'serious_3': "草津温泉は、日本三名泉の一つに数えられ、毎分3万リットル以上の湯量を誇る。",
        'humorous_1': "群馬県の形が鶴に似ていることから、「鶴舞う形の群馬県」と歌われる。",
        'humorous_2': "冬場、群馬名物の空っ風が吹き荒れる日は、洗濯物が乾くより先に飛んでいく可能性がある。",
    },
    '埼玉県': {
        'serious_1': "都心へのアクセスが良く、ベッドタウンとしての機能を持つ一方、県内総生産は全国5位と経済力も高い。",
        'serious_2': "日本最古の貨幣鋳造所である和同開珎の遺跡が秩父市で発見されている。",
        'serious_3': "盆栽の聖地として知られるさいたま市大宮区には、盆栽園が集まる「大宮盆栽村」がある。",
        'humorous_1': "「ダ埼玉」という自虐ネタがあるが、最近は住みやすさランキングで上位に入ることも多い。",
        'humorous_2': "アニメや漫画の聖地が多く、特に鷲宮神社は『らき☆すた』の聖地として有名になり、初詣客が急増した。",
    },
    '千葉県': {
        'serious_1': "成田国際空港があり、日本の空の玄関口として重要な役割を担っている。",
        'serious_2': "ピーナッツ（落花生）の生産量が日本一であり、畑の土の下で育つ。",
        'serious_3': "東京ディズニーリゾートがあるが、住所は千葉県浦安市である（東京ではない）。",
        'humorous_1': "チーバくんというマスコットキャラは、横から見ると千葉県の形そのものになっている。",
        'humorous_2': "東京湾アクアラインの海ほたるPAは、実際にはPAだが、リゾート地のような雰囲気がある。",
    },
    '東京都': {
        'serious_1': "世界で最も人口密度の高い都市圏の一つでありながら、高尾山や小笠原諸島など豊かな自然も有する。",
        'serious_2': "日本銀行があり、日本の金融の中心地として機能している。",
        'serious_3': "新宿駅は、1日の乗降客数で世界一とギネス認定されている。",
        'humorous_1': "「東京ばな奈」は、東京土産の定番だが、都民の多くは自分で買って食べたことがない。",
        'humorous_2': "満員電車での通勤は、一種の武術であり、鍛えられた体幹が求められる。",
    },
    '神奈川県': {
        'serious_1': "横浜港は日本の主要な港の一つであり、近代化の歴史において重要な役割を果たした。",
        'serious_2': "鎌倉には、源頼朝が築いた鎌倉幕府の史跡や、高徳院の鎌倉大仏など歴史的遺産が多い。",
        'serious_3': "箱根は温泉地として有名で、富士山と芦ノ湖の絶景が楽しめる。",
        'humorous_1': "横浜と川崎以外を「神奈川の田舎」と呼ぶ傾向があり、独自の地域対立（？）が存在する。",
        'humorous_2': "サンマーメンという麺料理は、秋刀魚（サンマ）が入っているわけではなく、「生馬麺」と書く。",
    },
    '新潟県': {
        'serious_1': "米どころとして知られ、作付面積、収穫量ともに全国トップクラスで、特にコシヒカリが有名。",
        'serious_2': "佐渡島には、江戸時代に日本の金銀採掘を支えた佐渡金山（世界遺産候補）がある。",
        'serious_3': "冬には世界有数の豪雪地帯となり、その雪解け水が豊かな米作りを支えている。",
        'humorous_1': "「へぎそば」は、つなぎに海藻の布海苔（ふのり）を使うため、コシが強く、緑がかった色をしている。",
        'humorous_2': "新潟県民は、雪が降るとすぐに「今年の雪は少ない」と安心する傾向がある（そして次の日には大雪が降る）。",
    },
    '富山県': {
        'serious_1': "富山湾は「天然の生け簀」と呼ばれ、ホタルイカや寒ブリなど新鮮な魚介類が豊富に獲れる。",
        'serious_2': "黒部ダムは、高さ186mの巨大なダムで、日本の土木技術の結晶と言える。",
        'serious_3': "合掌造りの集落がある五箇山は、世界遺産に登録されている。",
        'humorous_1': "富山駅前にある「富山の薬売り」の銅像は、見慣れない人には謎の商人に見える。",
        'humorous_2': "県民は薬売りの文化が根付いているため、常に風邪薬や胃薬を常備している。",
    },
    '石川県': {
        'serious_1': "金沢市にある兼六園は、水戸偕楽園、岡山後楽園と並ぶ日本三名園の一つである。",
        'serious_2': "輪島塗や九谷焼など、伝統工芸が非常に盛んな地域である。",
        'serious_3': "能登半島は独特の文化や自然が残り、能登キリコ祭りなどの伝統行事が有名。",
        'humorous_1': "「加賀野菜」と呼ばれる伝統野菜があり、特に金沢一本太ネギは非常に長い。",
        'humorous_2': "お寿司のネタが豪華すぎて、回転寿司でも全国平均を軽く超える高級感を味わえる。",
    },
    '福井県': {
        'serious_1': "永平寺は、曹洞宗の大本山であり、座禅や修行の場として全国から多くの僧侶が集まる。",
        'serious_2': "恐竜の化石が多く発掘されており、福井県立恐竜博物館は世界三大恐竜博物館の一つに数えられる。",
        'serious_3': "越前ガニや若狭ふぐなど、高級な海産物が豊富に獲れる。",
        'humorous_1': "「水ようかん」は冬に食べるのが一般的。コタツで冷たい水ようかんを食べるのが福井流。",
        'humorous_2': "福井県民の多くは、県のPRキャラクター「ラプトくん」（恐竜）を真面目に愛している。",
    },
    '山梨県': {
        'serious_1': "富士山は静岡県と山梨県にまたがるが、山梨県側には富士五湖があり、美しい景観が楽しめる。",
        'serious_2': "日本のワイン発祥の地の一つとされ、甲州ワインは世界的にも知られている。",
        'serious_3': "武田信玄の出身地であり、戦国時代の重要な拠点であった。",
        'humorous_1': "「ほうとう」はうどんではないと主張する人が多い（味噌仕立ての平たい麺料理）。",
        'humorous_2': "山梨県民は、隣の静岡県民との間で「富士山はどちらのものか」という論争を静かに繰り広げている。",
    },
    '長野県': {
        'serious_1': "「日本の屋根」と呼ばれる日本アルプスがあり、3000m級の山々が連なる。",
        'serious_2': "1998年に長野オリンピック・パラリンピックが開催され、世界的な知名度が高まった。",
        'serious_3': "蕎麦の名産地であり、戸隠そばや信州そばは全国的に有名である。",
        'humorous_1': "長野県民は、隣の山梨県民を「海なし仲間」として静かに見下す傾向がある（長野は山が多い）。",
        'humorous_2': "長野県の形が細長いため、端から端まで移動するのに非常に時間がかかる。",
    },
    '岐阜県': {
        'serious_1': "白川郷・五箇山の合掌造り集落は、世界遺産に登録されており、日本の原風景が残る。",
        'serious_2': "長良川の鵜飼は、1300年以上の歴史を持つ伝統的な漁法である。",
        'serious_3': "関市は「刃物の街」として知られ、世界的な刃物生産地の一つである。",
        'humorous_1': "県内には「飛騨牛」という高級ブランド牛があるが、牛舎の隣に住んでいる人は香りに慣れすぎて気づかない。",
        'humorous_2': "岐阜県民は、県内のどこに海があるのか聞かれると困る（海に面していない）。",
    },
    '静岡県': {
        'serious_1': "茶の生産量が全国1位であり、特に静岡茶は日本茶の代名詞的存在。",
        'serious_2': "伊豆半島や熱海温泉など、観光地が多く、温暖な気候に恵まれている。",
        'serious_3': "浜松市は、ヤマハ、スズキ、ホンダといった世界的企業の発祥の地である。",
        'humorous_1': "静岡県民は、電車で移動する際に富士山が見えると、つい写真を撮ってしまう（見慣れているはずなのに）。",
        'humorous_2': "おでんに「黒はんぺん」を使うのが静岡流だが、県外の人には見た目が地味に映る。",
    },
    '愛知県': {
        'serious_1': "トヨタ自動車のお膝元であり、製造業が非常に盛んで、日本の産業を牽引している。",
        'serious_2': "名古屋城の金鯱は、本物の金で覆われていた時期があり、権威の象徴であった。",
        'serious_3': "熱田神宮は、三種の神器の一つ、草薙剣が祀られていると伝わる。",
        'humorous_1': "名古屋めし（味噌カツ、手羽先など）は、味が濃すぎて「名古屋味」と呼ばれる。",
        'humorous_2': "モーニングサービス（朝食）が豪華すぎて、コーヒー代だけでお腹いっぱいになる。",
    },
    '三重県': {
        'serious_1': "伊勢神宮は「お伊勢さん」と呼ばれ、日本の最高神を祀る最も格式高い神社の一つである。",
        'serious_2': "真珠の養殖が盛んであり、御木本幸吉が世界で初めて真珠の養殖に成功した。",
        'serious_3': "鈴鹿サーキットがあり、F1や鈴鹿8時間耐久ロードレースなど世界的なレースが開催される。",
        'humorous_1': "三重県民は、自分の県が「関西」か「東海」か「近畿」のどこに属するのかを常に論じている。",
        'humorous_2': "松阪牛は高級ブランド牛だが、松阪の人は意外と安価な部位を日常的に食べている。",
    },
    '滋賀県': {
        'serious_1': "日本最大の湖である琵琶湖があり、近畿地方の約1400万人の生活用水を供給している。",
        'serious_2': "近江商人は「三方よし」（売り手よし、買い手よし、世間よし）の精神を確立し、現代のビジネス倫理にも影響を与えた。",
        'serious_3': "彦根城は、国宝に指定されている城郭の一つであり、現存天守を持つ貴重な城である。",
        'humorous_1': "琵琶湖はあまりにも大きすぎて、県民の多くは「湖の対岸は外国」だと思っている。",
        'humorous_2': "ひこにゃんは、滋賀県のゆるキャラの中でも特に人気があり、その姿を見ると誰もが和む。",
    },
    '京都府': {
        'serious_1': "平安京以来、日本の都として1000年以上の歴史を持ち、数多くの世界遺産や国宝が存在する。",
        'serious_2': "西陣織や京友禅など、伝統工芸が発達し、日本の文化を象徴している。",
        'serious_3': "清水寺の舞台は、釘を一切使わずに組まれた懸造り（かけづくり）の構造である。",
        'humorous_1': "「ぶぶ漬けでもどうどす？」は、京都の人が「そろそろ帰れ」という意味で使うというジョークがある。",
        'humorous_2': "京都の人は、観光客が多すぎると内心では思っているが、決して口に出さない。",
    },
    '大阪府': {
        'serious_1': "江戸時代には「天下の台所」と呼ばれ、商業の中心地として栄えた。",
        'serious_2': "ユニバーサル・スタジオ・ジャパン（USJ）があり、関西地方の観光を牽引している。",
        'serious_3': "大阪城は、豊臣秀吉が築城した巨大な城郭であり、日本の歴史上重要な拠点であった。",
        'humorous_1': "大阪のおばちゃんは、一人残らずヒョウ柄の服を一着は持っているという説がある。",
        'humorous_2': "たこ焼きはおやつではなく「おかず」であり、ご飯と一緒に食べるのが一般的。",
    },
    '兵庫県': {
        'serious_1': "神戸港は日本五大港の一つであり、国際貿易の拠点として機能している。",
        'serious_2': "世界遺産の姫路城は、白鷺が羽を広げたような優美な姿から「白鷺城」とも呼ばれる。",
        'serious_3': "淡路島は、日本神話でイザナギとイザナミが最初に生んだ島とされている。",
        'humorous_1': "県内には「神戸」「阪神」「播磨」「但馬」「淡路」と5つの地域があり、それぞれ独自の文化を持つため、県民意識がバラバラである。",
        'humorous_2': "神戸牛は高級だが、神戸の人は意外と「ぼっかけ」（牛すじとこんにゃくの煮込み）をよく食べる。",
    },
    '奈良県': {
        'serious_1': "東大寺の大仏殿は、世界最大の木造建築であり、その大仏は高さ15mを超える。",
        'serious_2': "日本最古の仏教寺院である法隆寺は、世界遺産に登録されている。",
        'serious_3': "平城京は、710年から784年まで日本の都として栄えた。",
        'humorous_1': "奈良公園の鹿は天然記念物だが、鹿せんべいをあげない観光客には容赦なく突進してくる。",
        'humorous_2': "奈良県民は、隣の京都府民と「どちらが真の古都か」を静かに競い合っている。",
    },
    '和歌山県': {
        'serious_1': "高野山は真言密教の聖地であり、弘法大師空海が開いた。",
        'serious_2': "みかんの生産量が日本一で、温暖な気候を活かした果物栽培が盛ん。",
        'serious_3': "熊野古道は、世界遺産に登録された巡礼路であり、歴史と自然が融合している。",
        'humorous_1': "和歌山ラーメンは「中華そば」と呼ぶのが一般的で、豚骨醤油ベースの濃い味が特徴。",
        'humorous_2': "海に面しているため、県民の多くは釣りが得意だが、釣れなくても文句は言わない。",
    },
    '鳥取県': {
        'serious_1': "鳥取砂丘は、日本最大級の砂丘であり、ラクダに乗ることもできる。",
        'serious_2': "『ゲゲゲの鬼太郎』の作者である水木しげるの出身地であり、水木しげるロードがある。",
        'serious_3': "大山（だいせん）は「伯耆富士」とも呼ばれ、中国地方の最高峰である。",
        'humorous_1': "鳥取県にはスタバがなかなか上陸しなかったため、自虐ネタとして「スタバはないがスナバはある」というキャッチコピーが生まれた。",
        'humorous_2': "カニの消費量が日本一。特に冬の松葉ガニは高級すぎて、食べる際には無言になる。",
    },
    '島根県': {
        'serious_1': "出雲大社は、縁結びの神様として知られ、旧暦10月には全国の八百万の神が集まるとされる。",
        'serious_2': "石見銀山は、世界遺産に登録されており、かつて世界有数の銀山であった。",
        'serious_3': "『古事記』や『日本書紀』にも登場する神話の舞台が多く存在する。",
        'humorous_1': "島根県民は、隣の鳥取県と間違えられると、かなり複雑な表情をする。",
        'humorous_2': "島根のゆるキャラ「しまねっこ」は、見た目が可愛すぎて、全国のゆるキャラファンを虜にしている。",
    },
    '岡山県': {
        'serious_1': "「晴れの国おかやま」と呼ばれ、日照時間が長く、降水量が少ないため果物栽培に適している。",
        'serious_2': "倉敷市の美観地区は、白壁の土蔵や柳並木が美しい歴史的な街並みを残している。",
        'serious_3': "桃太郎伝説の発祥の地の一つとされ、桃やぶどう（マスカット）の生産が盛ん。",
        'humorous_1': "岡山駅の桃太郎像は、犬、猿、雉を従えているが、皆なぜか非常に真面目な顔をしている。",
        'humorous_2': "デニム生地の生産が非常に盛んで、国産ジーンズの発祥地とされる。",
    },
    '広島県': {
        'serious_1': "広島平和記念公園と原爆ドームは、人類史上初めて核兵器が使用された場所であり、平和の重要性を訴える。",
        'serious_2': "厳島神社は、海上に建つ朱色の大鳥居が有名で、世界遺産に登録されている。",
        'serious_3': "牡蠣の生産量が日本一であり、広島湾は養殖に適した環境を持つ。",
        'humorous_1': "お好み焼きは、そばやうどんが入った「広島風」が一般的だが、県民はこれを「お好み焼き」と呼ぶ。",
        'humorous_2': "広島カープの熱狂的なファンが多く、真っ赤なユニフォームを着て街を歩く人が多い。",
    },
    '山口県': {
        'serious_1': "幕末の志士（高杉晋作、伊藤博文など）を多く輩出し、明治維新の原動力となった。",
        'serious_2': "フグ（特にトラフグ）の水揚げ量が日本有数であり、下関のフグは高級食材として知られる。",
        'serious_3': "錦帯橋は、木造の五連アーチ橋であり、日本三名橋の一つに数えられる。",
        'humorous_1': "「ふぐ」のことを「ふく」と呼ぶ。幸福の「福」に通じるため縁起が良い。",
        'humorous_2': "山口県民は、隣の広島県と「どちらが中国地方の中心か」を密かに争っている。",
    },
    '徳島県': {
        'serious_1': "阿波踊りは、400年以上の歴史を持つ盆踊りであり、「踊る阿呆に見る阿呆」の掛け声で知られる。",
        'serious_2': "鳴門の渦潮は、潮の満ち引きによって発生する世界最大級の渦潮である。",
        'serious_3': "人形浄瑠璃「阿波人形浄瑠璃」は、国の重要無形民俗文化財に指定されている。",
        'humorous_1': "すだちの生産量が全国一。何にでもすだちをかけるのが徳島流。",
        'humorous_2': "徳島ラーメンは、茶色のスープに生卵を入れるのが特徴だが、初めて見た人は戸惑う。",
    },
    '香川県': {
        'serious_1': "うどんの消費量が全国トップクラスであり、讃岐うどんは全国的に有名。",
        'serious_2': "金刀比羅宮（こんぴらさん）は、船乗りや漁師から信仰を集める海の神様である。",
        'serious_3': "直島は、現代アートの島として知られ、世界中から観光客が訪れる。",
        'humorous_1': "香川県民は、うどんを食べていないと不安になる病にかかっていると言われる。",
        'humorous_2': "県内には「うどんタクシー」があり、運転手におすすめのうどん店を教えてもらえる。",
    },
    '愛媛県': {
        'serious_1': "道後温泉は、日本三古湯の一つであり、夏目漱石の小説『坊っちゃん』の舞台としても知られる。",
        'serious_2': "みかん（柑橘類）の生産量が全国トップクラスであり、特に温州みかんが有名。",
        'serious_3': "松山城は、現存する天守を持つ城郭の一つであり、美しい姿を保っている。",
        'humorous_1': "蛇口からみかんジュースが出る、という伝説がある（実際にイベントで実施されることがある）。",
        'humorous_2': "愛媛県民は、朝食に「じゃこ天」という魚のすり身を揚げたものをよく食べる。",
    },
    '高知県': {
        'serious_1': "坂本龍馬の出身地であり、幕末の志士が多く輩出された。",
        'serious_2': "四万十川は「日本最後の清流」と呼ばれ、自然の美しい景観が残る。",
        'serious_3': "室戸岬や足摺岬など、太平洋に突き出たダイナミックな海岸線を持つ。",
        'humorous_1': "「カツオのたたき」は、藁（わら）焼きで表面を炙るため、炎の香りがする。",
        'humorous_2': "高知の人は酒に強く、「べろべろの神様」というユニークな酒の席での遊びがある。",
    },
    '福岡県': {
        'serious_1': "博多はアジアの玄関口として栄え、古くから国際貿易の拠点であった。",
        'serious_2': "とんこつラーメンや明太子、もつ鍋など、独自の食文化が発達している。",
        'serious_3': "太宰府天満宮は、学問の神様として知られ、受験生が多く訪れる。",
        'humorous_1': "福岡の人は、他県民を「上京」ではなく「博多上陸」と呼ぶことがある。",
        'humorous_2': "屋台文化が残っており、深夜まで賑わう屋台の雰囲気は独特で、観光客を魅了する。",
    },
    '佐賀県': {
        'serious_1': "有田焼や伊万里焼といった、世界的にも有名な陶磁器の産地である。",
        'serious_2': "吉野ヶ里遺跡は、弥生時代の最大級の環濠集落跡であり、歴史的に重要。",
        'serious_3': "佐賀平野は、干拓によって生まれた広大な土地であり、米作が盛ん。",
        'humorous_1': "佐賀の「シシリアンライス」は、ご飯の上に肉と野菜を乗せ、マヨネーズをかけたもので、見た目からしてカロリーが高い。",
        'humorous_2': "佐賀県民は、隣の福岡県と比べられると、控えめに「佐賀もいいところですよ」とアピールする。",
    },
    '長崎県': {
        'serious_1': "江戸時代、唯一の貿易窓口であった出島があり、海外文化の玄関口として栄えた。",
        'serious_2': "長崎市と天草地方の潜伏キリシタン関連遺産は、世界遺産に登録されている。",
        'serious_3': "平和公園と原爆資料館は、第二次世界大戦の悲劇を伝える重要な場所である。",
        'humorous_1': "カステラは長崎土産の定番だが、地元では「ざぼん漬け」という柑橘類の砂糖漬けも人気。",
        'humorous_2': "長崎ちゃんぽんは、具材が多すぎて麺が見えないことがよくある。",
    },
    '熊本県': {
        'serious_1': "阿蘇山は、世界最大級のカルデラを持つ活火山であり、雄大な景観が広がる。",
        'serious_2': "熊本城は、加藤清正が築いた難攻不落の城であり、地震からの復興が進められている。",
        'serious_3': "水が非常にきれいで、熊本市は地下水で水道水のほぼ全量を賄っている。",
        'humorous_1': "くまモンは、知事の仕事を手伝うほどの知名度と人気を誇り、多忙である。",
        'humorous_2': "辛子蓮根は、見た目が地味だが、鼻にツーンとくる辛さが特徴で、酒の肴に最適。",
    },
    '大分県': {
        'serious_1': "別府温泉は、源泉数・湧出量ともに日本一であり、温泉地として世界的にも有名。",
        'serious_2': "宇佐神宮は、全国4万以上の八幡社の総本宮であり、歴史的に重要。",
        'serious_3': "国東半島には、独特の仏教文化が残り、石仏や磨崖仏が多い。",
        'humorous_1': "「とり天」は鶏肉の天ぷらだが、県民はこれを唐揚げとは区別して特別視している。",
        'humorous_2': "温泉が多く、家庭の風呂の蛇口からも温泉が出る地域がある。",
    },
    '宮崎県': {
        'serious_1': "日向灘に面し、温暖な気候に恵まれ、サーフィンなどのマリンスポーツが盛ん。",
        'serious_2': "神話のふるさととして知られ、天孫降臨の地とされる高千穂峡がある。",
        'serious_3': "マンゴー（特に太陽のタマゴ）などの高級フルーツの生産が盛ん。",
        'humorous_1': "宮崎県民は、チキン南蛮にタルタルソースをかけることに異常なこだわりを持つ。",
        'humorous_2': "東国原英夫（そのまんま東）が知事になってから、宮崎県の知名度が急上昇した。",
    },
    '鹿児島県': {
        'serious_1': "桜島は、鹿児島市の目の前にある活火山であり、現在も噴火を繰り返している。",
        'serious_2': "屋久島は、樹齢1000年以上の屋久杉が生い茂る原生林があり、世界遺産に登録されている。",
        'serious_3': "西郷隆盛をはじめとする明治維新の偉人を多く輩出した薩摩藩の中心地であった。",
        'humorous_1': "「黒豚」と「白熊」（かき氷）という、見た目と中身が全く違う二大名物がある。",
        'humorous_2': "桜島の火山灰が降ると、県民は傘をさして歩くか、車に積もった灰を黙々と片付ける。",
    },
    '沖縄県': {
        'serious_1': "かつて琉球王国として独立した歴史を持ち、独自の文化、言語、生活習慣が残る。",
        'serious_2': "首里城は、琉球王国の政治・文化の中心地であり、世界遺産に登録されていた（再建中）。",
        'serious_3': "太平洋戦争末期の激戦地であり、多くの犠牲者を出した歴史を持つ。",
        'humorous_1': "沖縄のぜんざいは、冷たいかき氷の下に甘く煮た豆が入っているのが特徴。",
        'humorous_2': "シーサーは魔除けだが、最近は観光客向けに可愛らしいデザインのものが増えている。",
    }
}

# 47都道府県のキーリスト（ランダム選択用）
PREFECTURE_KEYS = list(PREFECTURE_TRIVIA_47.keys())
# 5つのトリビアのキーリスト（ランダム選択用）
TRIVIA_KEYS = ['serious_1', 'serious_2', 'serious_3', 'humorous_1', 'humorous_2']

# --- 待ち時間表示のための都道府県トリビア関数 (更新版) ---
def display_prefecture_trivia(tip_placeholder):
    """ランダムな都道府県トリビアを生成し、指定のプレースホルダーに表示する"""
    # 1. ランダムに都道府県を選択
    selected_prefecture = random.choice(PREFECTURE_KEYS)

    # 2. その都道府県からランダムにトリビアの種類を選択
    selected_key = random.choice(TRIVIA_KEYS)

    # 3. トリビアを取得
    selected_tip_text = PREFECTURE_TRIVIA_47[selected_prefecture][selected_key]

    # 4. トリビアの種別を判定してタイトルを設定
    if selected_key.startswith('humorous'):
        tip_type_title = "✨ ユーモア豆知識"
    else:
        tip_type_title = "📚 真面目な豆知識"

    # 5. Markdownで整形して表示
    tip_markdown = (
        f"**{selected_prefecture}** のトリビア:\n"
        f"> {selected_tip_text}"
    )
    tip_placeholder.info(tip_markdown)


# --- 結果を表示する関数 ---
def display_results(results_to_display):
    """結果をStreamlitのカスタムグリッドとして表示し、すべてのターゲットに対してコピー補助機能を提供する"""

    st.markdown("### 📝 検索結果")

    # 結果件数が多いときのためのコンテナでテーブルを囲む
    with st.container(height=600):
        # 1. ヘッダー行
        # No., Target_IP, Country, ISP, RIR_Link, Secondary_Security_Links, Status, Checkbox
        col_widths = [0.5, 1.0, 1.0, 1.0, 1.8, 2.2, 0.9, 0.5]
        cols = st.columns(col_widths)

        header_style = "font-weight: bold; background-color: #f0f2f6; padding: 10px; border-radius: 5px; color: #1e3a8a;"

        with cols[0]: st.markdown(f'<div style="{header_style}">No.</div>', unsafe_allow_html=True)
        with cols[1]: st.markdown(f'<div style="{header_style}">Target IP</div>', unsafe_allow_html=True)
        with cols[2]: st.markdown(f'<div style="{header_style}">Country</div>', unsafe_allow_html=True)
        with cols[3]: st.markdown(f'<div style="{header_style}">ISP</div>', unsafe_allow_html=True)
        with cols[4]: st.markdown(f'<div style="{header_style}">RIR Links</div>', unsafe_allow_html=True)
        with cols[5]: st.markdown(f'<div style="{header_style}">Secondary Links</div>', unsafe_allow_html=True)
        with cols[6]: st.markdown(f'<div style="{header_style}">Status</div>', unsafe_allow_html=True)
        with cols[7]: st.markdown(f'<div style="{header_style}">✅</div>', unsafe_allow_html=True) # チェックボックスのヘッダー

        st.markdown("---")

        # 2. 結果行
        for i, row in enumerate(results_to_display):
            ip_display = row['Target_IP']
            rir_link_markdown = row['RIR_Link']
            secondary_links = row['Secondary_Security_Links'].replace('\n', ' ')

            # チェックボックスの状態をセッションステートから取得・管理するためのキー
            # IP表示内容と行番号を組み合わせることで、集約モードでも一意性を保つ
            checkbox_key = f"checked_{ip_display}_{i}"

            # 集約されたIP範囲の場合は、最初のIPをコピー対象とする
            # "XXX.XXX.XXX.XXX - YYY.YYY.YYY.YYY (xN IPs)" の場合、XXX.XXX.XXX.XXX を取得
            target_to_copy = ip_display.split(' - ')[0].split(' ')[0]

            row_cols = st.columns(col_widths)

            with row_cols[0]: st.markdown(f"**{i + 1}**") # 行番号
            with row_cols[1]: st.markdown(ip_display)
            with row_cols[2]: st.markdown(row['Country'])
            with row_cols[3]: st.markdown(row['ISP'])

            with row_cols[4]:
                st.markdown(rir_link_markdown)

                # Streamlitの機能を利用して、検索値をコピー可能にする
                st.code(
                    target_to_copy,
                    language=None
                )

            with row_cols[5]: st.markdown(secondary_links)
            with row_cols[6]: st.markdown(row['Status'])

            with row_cols[7]:
                # セッションステートにチェック状態を保存し、再実行時も状態を保持
                # Streamlitのバグ対策として、デフォルト値で初期化
                if checkbox_key not in st.session_state:
                    st.session_state[checkbox_key] = False
                st.checkbox("", key=checkbox_key, help="この調査が完了したかを手動でマーク")

            if i < len(results_to_display) - 1:
                st.markdown('<div style="margin-top: 5px; margin-bottom: 5px; border-bottom: 1px solid #eee;"></div>', unsafe_allow_html=True)

    st.markdown("---")

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

    st.markdown('<h1 style="color: #1e3a8a; text-shadow: 1px 1px 2px #9ca3af; font-weight: bold;">🌐Whois一括検索アプリ (v1.3.1)</h1>', unsafe_allow_html=True)
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
""")
    # --- モード選択のラジオボタン ---
    display_mode = st.radio(
        "📝 結果の表示モードを選択してください:",
        ("標準モード (1ターゲット = 1行)", "集約モード (IPv4アドレスをISP/国別でグループ化)"),
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

            # --- トリビア表示用のプレースホルダーを確保 ---
            tip_placeholder = st.empty()
            display_prefecture_trivia(tip_placeholder) # 最初のトリビアを表示

            total_ip_targets = len(ip_targets)
            processed_count = 0
            raw_results = []

            # ドメインの静的結果を事前に追加
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
                            display_prefecture_trivia(tip_placeholder)
                            last_tip_time = time.time()

                        time.sleep(0.1) # スレッドがCPUを占有しすぎないように待機

            # 6. 完了後の処理
            status_placeholder.empty()
            progress_placeholder.empty()
            tip_placeholder.empty() # トリビアをクリア

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
        else:
            st.info("💡 **標準モード**：入力されたターゲット全てを個別に表示しています。")
            results_to_display = results_to_process

        # 結果のテーブル描画とコピー機能の表示
        display_results(results_to_display)

        # 7. 結果のダウンロード機能
        if len(results_to_process) > 0:
            df_download = pd.DataFrame(results_to_process)

            df_download = df_download.rename(columns={
                'Target_IP': 'Target IP',
                'RIR_Link': 'RIR Link',
                'Secondary_Security_Links': 'Secondary Security Links'
            })

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


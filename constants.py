# constants.py

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
VPNAPI_URL = "https://vpnapi.io/api/{ip}?key={key}"
RDAP_BOOTSTRAP_URL = "https://rdap.apnic.net/ip/{ip}"

RATE_LIMIT_WAIT_SECONDS = 120 

# パブリックDNSサーバーリスト (分散処理用)
PUBLIC_DNS_SERVERS = [
    '8.8.8.8', '8.8.4.4',             # Google
    '1.1.1.1', '1.0.0.1',             # Cloudflare
    '9.9.9.9', '149.112.112.112',     # Quad9
    '208.67.222.222', '208.67.220.220'# OpenDNS
]
PUBLIC_DNS_V6_SERVERS = [
    '2001:4860:4860::8888', '2001:4860:4860::8844', # Google
    '2606:4700:4700::1111', '2606:4700:4700::1001'  # Cloudflare
]
  
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
    'VPNAPI.io': 'https://vpnapi.io/',
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
    "IR": "イラン・イスラム共和国","IQ": "イラク共和国","IE": "アイルランド","IL": "イスラエル国","IT": "イタリア共和国","JP": "日本","KR": "大韓民国","TW": "台湾","MY": "マレーシア",
    "MX": "メキシコ合衆国","NL": "オランダ王国","NZ": "ニュージーランド","NO": "ノルウェー王国","PK": "パキスタン・イスラム共和国","PA": "パナマ共和国","PE": "ペルー共和国","PH": "フィリピン共和国",
    "PL": "ポーランド共和国","PT": "ポルトガル共和国","QA": "カタール国","RO": "ルーマニア","RU": "ロシア連邦","SA": "サウジアラビア王国","SG": "シンガポール共和国","ZA": "南アフリカ共和国",
    "ES": "スペイン王国","SE": "スウェーデン王国","CH": "スイス連邦","TH": "タイ王国","TR": "トルコ共和国","UA": "ウクライナ","AE": "アラブ首長国連邦","GB": "グレートブリテン及び北アイルランド連合王国",
    "US": "アメリカ合衆国","VN": "ベトナム社会主義共和国","YE": "イエメン共和国","ZM": "ザンビア共和国","ZW": "ジンバブエ共和国"
}

# --- TLD (Top Level Domain) 情報辞書 ---
TLD_INFO = {
    "ru": {"name": "Russian Federation", "jp_name": "ロシア連邦", "url": "https://cctld.ru/en"},
    "cn": {"name": "China", "jp_name": "中華人民共和国", "url": "https://www.cnnic.cn/"},
    "jp": {"name": "Japan", "jp_name": "日本", "url": "https://jprs.jp/"},
    "kr": {"name": "Republic of Korea", "jp_name": "大韓民国", "url": "https://kisa.or.kr/"},
    "kp": {"name": "Democratic People's Republic of Korea", "jp_name": "北朝鮮", "url": "N/A"},
    "tw": {"name": "Taiwan", "jp_name": "台湾", "url": "https://www.twnic.tw/"},
    "hk": {"name": "Hong Kong", "jp_name": "香港", "url": "https://www.hkirc.hk/"},
    "us": {"name": "United States", "jp_name": "アメリカ合衆国", "url": "https://www.about.us/"},
    "uk": {"name": "United Kingdom", "jp_name": "イギリス", "url": "https://www.nominet.uk/"},
    "io": {"name": "British Indian Ocean Territory", "jp_name": "英領インド洋地域 (IT系多用)", "url": "https://www.nic.io/"},
    "co": {"name": "Colombia", "jp_name": "コロンビア (企業多用)", "url": "https://www.cointernet.com.co/"},
    "tv": {"name": "Tuvalu", "jp_name": "ツバル (メディア多用)", "url": "https://www.nic.tv/"},
    "com": {"name": "Commercial", "jp_name": "商用組織 (VeriSign)", "url": "https://www.verisign.com/"},
    "net": {"name": "Network", "jp_name": "ネットワーク組織 (VeriSign)", "url": "https://www.verisign.com/"},
    "org": {"name": "Organization", "jp_name": "非営利組織 (PIR)", "url": "https://pir.org/"},
    "info": {"name": "Information", "jp_name": "情報提供 (Identity Digital)", "url": "https://identity.digital/"},
    "biz": {"name": "Business", "jp_name": "ビジネス (GoDaddy)", "url": "https://www.go.co/"},
    "xyz": {"name": "General", "jp_name": "一般 (XYZ.COM)", "url": "https://gen.xyz/"},
    "top": {"name": "General", "jp_name": "一般 (.TOP Registry)", "url": "https://www.nic.top/"},
}

# --- ISP名称の日本語マッピング (企業名統一版) ---
ISP_JP_NAME = {
    # --- NTT Group ---
    'NTT Communications Corporation': 'NTTドコモビジネス株式会社', 
    'NTT COMMUNICATIONS CORPORATION': 'NTTドコモビジネス株式会社',
    'NTT DOCOMO BUSINESS,Inc.': 'NTTドコモビジネス株式会社',
    'NTT DOCOMO, INC.': '株式会社NTTドコモ',
    'NTT PC Communications, Inc.': 'NTTPCコミュニケーションズ株式会社',
    'NTT Communications Corporation / EDION': 'OCN(NTTドコモビジネス株式会社)',
    'BP-DOUJIMA': 'エヌ・ティ・ティ・ブロードバンドプラットフォーム株式会社',
    
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
    'Wire and Wireless Co., Ltd.': '株式会社ワイヤ・アンド・ワイヤレス',
    
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
    'LogicLinks, Inc.': '株式会社LogicLinks',
}

# 強力な名寄せルール (部分一致検索)
ISP_REMAP_RULES = [
    ('jcn', 'JCOM株式会社'), ('jupiter', 'JCOM株式会社'), ('cablenet', 'JCOM株式会社'),
    ('dion', 'KDDI株式会社'), ('au one', 'KDDI株式会社'), ('kddi', 'KDDI株式会社'),
    ('k-opti', 'オプテージ株式会社'), ('ctc', '中部テレコミュニケーションズ株式会社'),
    ('vectant', 'アルテリア・ネットワークス株式会社'), ('arteria', 'アルテリア・ネットワークス株式会社'),('v-vne', 'アルテリア・ネットワークス株式会社'),
    ('softbank', 'ソフトバンク株式会社'), ('bbtec', 'ソフトバンク株式会社'),
    ('ocn', 'OCN(NTTドコモビジネス株式会社)'), ('nifty', 'ニフティ株式会社'), ('asahi net', '株式会社朝日ネット'),
    ('rakuten mobile', '楽天モバイル株式会社'),('rmn', '楽天モバイル株式会社'), ('rakuten communications', '楽天コミュニケーションズ株式会社'),
    ('so-net', 'ソニーネットワークコミュニケーションズ株式会社'), ('nuro', 'ソニー (NURO)'),
    ('biglobe', 'ビッグローブ株式会社'), ('iij', '株式会社インターネットイニシアティブ(IIJ)'),
    ('transix', 'インターネットマルチフィード株式会社 (transix)'),
    ('v6plus', 'JPNE (v6プラス)'),
    ('logiclinks', '株式会社LogicLinks'),('lgls', '株式会社LogicLinks'),
    ('plala', '株式会社NTTドコモ (ぷらら)'),('docomo', '株式会社NTTドコモ'),('maps', '株式会社NTTドコモ'),
    ('wi2', '株式会社ワイヤ・アンド・ワイヤレス'),
    ('GMO Internet, Inc.','GMOインターネットグループ株式会社'),
]

def normalize_isp_key(text):
    if not text: return ""
    return text.lower().replace(',', '').replace('.', '').strip()

ISP_JP_NAME_NORMALIZED = {normalize_isp_key(k): v for k, v in ISP_JP_NAME.items()}

# --- 捨てアド (Disposable Email) 検知用グローバル辞書 ---
DISPOSABLE_MX_SERVICES = {
    'sute.jp': '捨てメアド (メルアドぽいぽい)',
    'erinn.biz': '捨てメアド (メルアドぽいぽい)',
    'kuku.lu': '捨てメアド (メルアドぽいぽい)',
    'instaddr.com': '捨てメアド (メルアドぽいぽい)',
    'instaddr.jp': '捨てメアド (メルアドぽいぽい)',
    'm.miril.jp': '捨てメアド (メルアドぽいぽい)',
    '10minutemail': '10 Minute Mail',
    'guerrillamail': 'Guerrilla Mail',
    'temp-mail': 'Temp Mail',
    'nada.email': 'Nada / Tmpmail',
    'maildrop.cc': 'Maildrop',
    'yopmail.com': 'YOPmail',
    'tempmail.plus': 'Temp Mail Plus',
    '1secmail.com': '1SecMail',
    'throwawaymail.com': 'Throwaway Mail',
    'tempmail.org': 'Temp-Mail.org',
    'mail.tm': 'Mail.tm',
    'sharklasers.com': 'Guerrilla Mail',
    'dispostable.com': 'Dispostable',
    'getnada.com': 'Nada.email',
    'mailinator.com': 'Mailinator',
    'moakt.com': 'Moakt',
    'tmails.net': 'T-Mails',
    '33mail.com': '33mail',
    'airmail.cc': 'Airmail',
    'generator.email': 'Generator.email'
}

DISPOSABLE_DOMAIN_SERVICES = {
    'instaddr.com': '捨てメアド (メルアドぽいぽい)',
    'instaddr.jp': '捨てメアド (メルアドぽいぽい)',
    'm.miril.jp': '捨てメアド (メルアドぽいぽい)',
    '10minutemail.com': '10 Minute Mail',
    '10minutemail.net': '10 Minute Mail',
    'guerrillamail.com': 'Guerrilla Mail',
    'mailinator.com': 'Mailinator',
    'yopmail.com': 'YOPmail'
}
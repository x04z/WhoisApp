# utils.py
import ipaddress
import socket
import struct
import re

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
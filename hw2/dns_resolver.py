import socket
import struct
import random
import ipaddress
from collections import deque
from parser import parse_dns_message
from dns_packet_builder import encode_domain_name, create_dns_packet, FLAGS_INT_TO_REQUEST_WITHOT_RECURSION

ROOT_DNS_SERVERS = [
    "198.41.0.4",      # A-root
    "170.247.170.2",   # B-root
    # "192.33.4.12",     # C-root
    # "199.7.91.13",     # D-root
    # "192.203.230.10",  # E-root
    # "192.5.5.241",     # F-root
    # "192.112.36.4",    # G-root
    # "198.97.190.53",   # H-root
    # "192.36.148.17",   # I-root
    # "192.58.128.30",   # J-root
    # "193.0.14.129",    # K-root
    # "199.7.83.42",     # L-root
    # "202.12.27.33",    # M-root
]
ITER_COUNT = 20
TIMEOUT = 3


DNS_TYPES = {
    1:   "A",       # IPv4-адрес
    2:   "NS",      # Авторитетный DNS-сервер
    # 5:   "CNAME",   # Псевдоним домена
    # 6:   "SOA",     # Информация об авторитетной зоне
    15:  "MX",      # Почтовый сервер
    16:  "TXT",     # Текстовые данные
    28:  "AAAA",    # IPv6-адрес
}
TYPE_A = 1
TYPE_NS = 2

def dns_iterator(domain_name: str, record_type: int, recursion_depth: int = 0, visited_servers: set = None,):
    if visited_servers is None:
        visited_servers = set()
    
    if recursion_depth >= ITER_COUNT or domain_name in visited_servers:
        return []

    dns_servers = deque()
    for root_dns_server in ROOT_DNS_SERVERS:
        dns_servers.append(root_dns_server)
    curr_iter_number = 0

    while len(dns_servers) > 0 and curr_iter_number < ITER_COUNT:
        dns_server_addr = dns_servers.pop()
        
        if dns_server_addr in visited_servers:
            continue

        visited_servers.add(dns_server_addr)

        dns_message = send_dns_request(dns_server_addr, domain_name, record_type)

        if dns_message is None:
            continue

        answer_records = dns_message.get("answers", [])
        if answer_records:
            return answer_records

        authority_records = dns_message.get("authority", [])
        additional_records = dns_message.get("additional", [])

        if not authority_records and not additional_records:
            continue

        next_dns_servers, new_visited_servers = get_next_dns_servers_ips(authority_records, additional_records, visited_servers, recursion_depth)

        visited_servers.update(new_visited_servers)
        dns_servers.append(server for server in next_dns_servers)
        curr_iter_number += 1

    return None

def send_dns_request(server_addr: str, domain_name: str, record_type: int) -> dict:
    """Посылает днс запросс серверу, получает ответ и возвращает распршенный ответ от сервера"""
    try:
        request_id = random.randrange(65536)
        questions = [{"name": domain_name, "type": record_type, "class": 1}]
        dns_request = create_dns_packet(request_id, FLAGS_INT_TO_REQUEST_WITHOT_RECURSION, questions)
        family, server = get_ip_family_and_server(server_addr)

        tcp_request = len(dns_request).to_bytes(2, "big") + dns_request
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(TIMEOUT)
            sock.connect(server)
            sock.sendall(tcp_request)
            
            response_len_bytes = sock.recv(2)
            if len(response_len_bytes) < 2:
                return None
            
            expected_len = int.from_bytes(response_len_bytes, "big")
            
            # Читаем сам DNS-ответ целиком (в цикле на случай фрагментации TCP)
            dns_response = b""
            while len(dns_response) < expected_len:
                chunk = sock.recv(expected_len - len(dns_response))
                if not chunk:
                    break
                dns_response += chunk

        if len(dns_response) < 12:
            return None

        response_id = int.from_bytes(dns_response[:2], "big")
        if response_id != request_id:
            return None
        
        dns_message = parse_dns_message(dns_response)

        return dns_message

    except (OSError, ValueError) as e:
        print(f"DNS server {server_addr} failed: {e}")
        return None

def get_ip_family_and_server(ip: str) -> tuple[socket.AddressFamily, tuple]:
    """По ip адресу возвращает семейство сети и сервер в правильном формате"""
    ip_version = ipaddress.ip_address(ip).version
    if ip_version == 6:
        family = socket.AF_INET6
        server = (ip, 53, 0, 0)
    else:
        family = socket.AF_INET
        server = (ip, 53)

    return family, server

def get_next_dns_servers_ips(authority_records: dict, additional_records: dict, visited_servers: set,recursion_depth: int,) -> tuple[list, set]:
    """Проходит по всем ns серверам из authority и получает их ip адреса"""
    # Получаем имена следующих NS-серверов
    name_servers = [record["data"] for record in authority_records if record["type"] == TYPE_NS and record["class"] == 1]
    normalized_ns_names = { name.rstrip(".").lower() for name in name_servers }
    next_dns_servers = []
    # Сначала ищем IP-адреса NS в additional
    for record in additional_records:
        if record["name"].rstrip(".").lower() in normalized_ns_names:
            if record["type"] == TYPE_A and record["class"] == 1:
                server_ip = record["data"]

                if server_ip not in visited_servers:
                    next_dns_servers.append(server_ip)

    for name_server in name_servers:
        if name_server.rstrip(".").lower() in normalized_ns_names:
            ns_ip_records = dns_iterator(name_server, TYPE_A,
                                        recursion_depth=recursion_depth + 1, visited_servers=visited_servers.copy(),)
            if ns_ip_records is None:
                continue

            for record in ns_ip_records:
                if record["type"] != TYPE_A:
                    continue
                server_ip = record["data"]
                if server_ip not in next_dns_servers and server_ip not in visited_servers:
                    next_dns_servers.append(server_ip)

    return next_dns_servers, visited_servers

#print(dns_iterator("google.com", 28))
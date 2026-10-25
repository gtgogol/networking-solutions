import socket
import struct
import random
import ipaddress
from parser import parse_dns_message

ROOT_DNS_SERVER = ("198.41.0.4", 53)  # a.root-servers.net
ITER_COUNT = 20
TIMEOUT = 5


DNS_TYPES = {
    1:   "A",       # IPv4-адрес
    2:   "NS",      # Авторитетный DNS-сервер
    5:   "CNAME",   # Псевдоним домена
    6:   "SOA",     # Информация об авторитетной зоне
    15:  "MX",      # Почтовый сервер
    16:  "TXT",     # Текстовые данные
    28:  "AAAA",    # IPv6-адрес
}
TYPE_A = 1
TYPE_NS = 2

def dns_iterator(domain_name: str, record_type: int,recursion_depth: int = 0, visited_queries: set | None = None,):
    if visited_queries is None:
        visited_queries = set()

    query_key = (domain_name.rstrip(".").lower(), record_type)

    if recursion_depth >= ITER_COUNT or query_key in visited_queries:
        return []

    visited_queries.add(query_key)

    dns_servers = [ROOT_DNS_SERVER]
    queried_servers = set()

    for _ in range(ITER_COUNT):
        next_dns_servers = []

        for dns_server in dns_servers:
            if dns_server in queried_servers:
                continue

            queried_servers.add(dns_server)

            try:
                request_id, dns_request = create_dns_query(domain_name, record_type)

                server_addr = dns_server[0]
                ip_version = ipaddress.ip_address(server_addr).version

                if ip_version == 6:
                    family = socket.AF_INET6
                    server = (server_addr, 53, 0, 0)
                else:
                    family = socket.AF_INET
                    server = (server_addr, 53)

                with socket.socket(family, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(TIMEOUT)
                    sock.sendto(dns_request, server)
                    dns_response, _ = sock.recvfrom(4096)

                if len(dns_response) < 12:
                    continue

                response_id = int.from_bytes(dns_response[:2], "big")
                if response_id != request_id:
                    continue

                dns_message = parse_dns_message(dns_response)
                print(dns_message)

            except (OSError, ValueError) as e:
                print(f"DNS server {dns_server} failed: {e}")
                continue

            answer_records = dns_message.get("answers", [])
            if answer_records:
                return answer_records

            authority_records = dns_message.get("authority", [])
            additional_records = dns_message.get("additional", [])

            # Получаем имена авторитетных NS-серверов
            name_servers = [record["data"] for record in authority_records if record["type"] == TYPE_NS and record["class"] == 1]

            normalized_ns_names = { name.rstrip(".").lower() for name in name_servers }

            # Сначала ищем IP-адреса NS в additional
            known_server_ips = set()

            for record in additional_records:
                if record["name"].rstrip(".").lower() in normalized_ns_names:
                    if record["type"] == TYPE_A and record["class"] == 1:
                        server_ip = record["data"]
                        next_server = (server_ip, 53)

                        if next_server not in queried_servers:
                            next_dns_servers.append(next_server)

                        known_server_ips.add(server_ip)

            # Если IP NS-сервера не найден, ищем его отдельным DNS-запросом
            if not known_server_ips:
                for name_server in name_servers:
                    if name_server.rstrip(".").lower() in normalized_ns_names:
                        ns_ip_records = dns_iterator(name_server, TYPE_A,
                                                    recursion_depth=recursion_depth + 1, visited_queries=visited_queries.copy(),)

                        for record in ns_ip_records:
                            if record["type"] != TYPE_A:
                                continue

                            server_ip = record["data"]

                            if server_ip not in known_server_ips:
                                next_dns_servers.append((server_ip, 53))
                                known_server_ips.add(server_ip)

        if not next_dns_servers:
            print(111)
            break

        dns_servers = next_dns_servers
    print(1111)
    return []

# def dns_iterator(domain_name: str, record_type: int, ):
#     server = ROOT_DNS_SERVER
#     for _ in range(ITER_COUNT):
#         request_id, dns_packet = create_dns_query(domain_name, record_type)
#         with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
#             sock.settimeout(TIMEOUT)
#             sock.sendto(dns_packet, server)
#             response, server_address = sock.recvfrom(4096)

#         response_id = int.from_bytes(response[:2], byteorder="big")

#         if response_id != request_id:
#             raise ValueError("ID ответа не совпадает с ID запроса")

#         dns_message = parse_dns_message(response)
#         if dns_message["answers"]:
#             return dns_message["answers"]

#         next_servers = []


        

def create_dns_query(domain_name: str, record_type: int) -> tuple[int, bytes]:

    request_id = random.randrange(65536)

    # RD=0: рекурсия выключена
    dns_header = struct.pack(
        "!HHHHHH",
        request_id,  # ID запроса
        0,           # Флаги
        1,           # Количество вопросов
        0,           # Количество ответов
        0,           # Количество записей Authority
        0            # Количество записей Additional
    )

    question_name = encode_domain_name(domain_name)

    # QTYPE=record_type (DNS_TYPES), QCLASS=1 (IN)
    question_details = struct.pack("!HH", record_type, 1)

    dns_question = question_name + question_details
    dns_packet = dns_header + dns_question

    return request_id, dns_packet

def encode_domain_name(domain_name: str) -> bytes:
    encoded_name = b""
    for label in domain_name.rstrip(".").split("."):
        label_bytes = label.encode("ascii")

        if len(label_bytes) > 63:
            raise ValueError("DNS-метка не может быть длиннее 63 байт")

        encoded_name += bytes([len(label_bytes)]) + label_bytes

    return encoded_name + b"\x00"

print(dns_iterator("github.com", 16))
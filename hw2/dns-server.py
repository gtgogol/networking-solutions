import socket
import struct
from parser import parse_dns_message, parse_mult_question
from dns_resolver import dns_iterator
from dns_packet_builder import create_dns_packet, FLAGS_INT_TO_RESPONSE
from diskcache import Cache


CACHE = Cache("./cache")
HOST, PORT = "127.0.0.1", 8000
BASE_TTL = 300


def tcp_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket:
        tcp_socket.bind((HOST, PORT))
        tcp_socket.listen()
        print("TCP запущен")

        while True:
            connection, address = tcp_socket.accept()
            print(f"Получен запрос от {connection}")
            try:
                length_request = connection.recv(2)
                length = struct.unpack("!H", length_request)[0]
                dns_request = connection.recv(length)
            except (OSError, ValueError) as exc:
                print(f"Запрос завершился с ошибкой: {exc}")

            parsed_request = parse_dns_message(dns_request)
        
            questions = parsed_request["questions"]
            answers = []
            for question in questions:
                answers_for_question = resolve(question["name"], question["type"])
                if answers_for_question is None:
                    continue
                for answer in answers_for_question:
                    answers.append(answer)

            dns_response = create_dns_packet(parsed_request["header"]["id"], FLAGS_INT_TO_RESPONSE, parsed_request["questions"],answers)
            response = struct.pack("!H", len(dns_response)) + dns_response
            try:
                connection.sendall(response)
                print("Ответ пользователю отправлен")
            except OSError as exc:
                print("Ошибка при отправлке данных")
            finally:
                connection.close()

            count_deleted = CACHE.expire()
            if count_deleted > 0:
                print(f"Удалено {count_deleted} устаревших ДНС записей")

def resolve(domain_name: str, record_type: int):
    cached_values = get_dns_record_from_cache(domain_name, record_type)
    if cached_values is not None:
        answer = []
        for cached_value in cached_values:
            answer.append({
                "name": f"{domain_name}",
                "type": record_type,
                "class": 1,
                "ttl": cached_value["ttl"],
                "length": 4,
                "data": cached_value["data"]
            })
        return answer
    if "multiply" in domain_name:
        last_part_ip4 = parse_mult_question(domain_name)
        add_dns_record_2_cache(domain_name, 1, f"127.0.0.{last_part_ip4}", BASE_TTL)
        return [{
            "name": f"{domain_name}",
            "type": 1,
            "class": 1,
            "ttl": BASE_TTL,
            "length": 4,
            "data": f"127.0.0.{last_part_ip4}"
        }]
    answers_dns_iterator = dns_iterator(domain_name, record_type)
    if answers_dns_iterator is not None:
        for answer in answers_dns_iterator:
            add_dns_record_2_cache(domain_name, record_type, answer["data"], answer["ttl"])
    return answers_dns_iterator

def add_dns_record_2_cache(domain_name: str, record_type: str, data, ttl: int):
    cache_key = f'{domain_name.lower()}:{record_type}'
    last_dns_records = get_dns_record_from_cache(domain_name, record_type)
    last_cached_values = last_dns_records if last_dns_records is not None else []
    last_cached_values.append({
        "data": data,
        "ttl": ttl
    })
    CACHE.set(cache_key, last_cached_values, expire=ttl)


def get_dns_record_from_cache(domain_name: str, record_type: str):
    cache_key = f'{domain_name.lower()}:{record_type}'
    return CACHE.get(cache_key)

if __name__ == "__main__":
    tcp_server()
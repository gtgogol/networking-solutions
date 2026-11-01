import socket
import struct
import threading
from parser import parse_dns_message, parse_mult_question
from dns_resolver import dns_iterator, encode_domain_name


HOST, PORT = "127.0.0.1", 8002
BASE_TTL = 300

def tcp_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket:
        #tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_socket.bind((HOST, PORT))
        tcp_socket.listen()
        print("TCP запущен")

        while True:
            connection, address = tcp_socket.accept()
            try:
                length_request = connection.recv(2)
                length = struct.unpack("!H", length_request)[0]
                dns_request = b""
                while len(dns_request) < length:
                    chunk = connection.recv(length - len(dns_request))
                    if not chunk:
                        break
                    dns_request += chunk
            except (OSError, ValueError) as exc:
                print(f"Запрос завершился с ошибкой: {exc}")

            parsed_request = parse_dns_message(dns_request)
            question = parsed_request["questions"][0]

            if "multiply" in question["name"]:
                last_part_ip4 = parse_mult_question(question["name"])
                answer = {
                    "answer": f"{question["name"]}",
                    "type": "1",
                    "class": f"{question["class"]}",
                    "ttl": f"{BASE_TTL}",
                    "length": "4",
                    "data": f"127.0.0.{last_part_ip4}"
                }
            answer = dns_iterator(question["name"], question["type"])
            dns_response = create_dns_answer(parsed_request, answer)
            try:
                connection.sendall(dns_response)
            except OSError as exc:
                print("Ошибка при отправлке данных")
            finally:
                connection.close()

            
def create_dns_answer(user_request: dict, answers: list) -> bytes:
    """Строит ответ днс ответ пользователю"""
    header = build_answer_header(user_request["header"]["id"], 1, len(answers))

    question_name = encode_domain_name(user_request["questions"][0]["name"])
    question_details = struct.pack("!HH", user_request["questions"][0]["type"], 1)
    question = question_name + question_details

    answers_section = build_answer_ans_section(answers, user_request)

    return header + question + answers_section
    
def build_answer_header(id: int, questions_count: int, answers_count: int) -> bytes:
    qr     = 1
    opcode = 0
    aa     = 1
    tc     = 0
    rd     = 1
    ra     = 1
    z      = 0
    rcode  = 0
    flags_int = (
        (qr     << 15) |
        (opcode << 11) |
        (aa     << 10) |
        (tc     << 9)  |
        (rd     << 8)  |
        (ra     << 7)  |
        (z      << 4)  |
        rcode
    )
    flags = struct.pack('!H', flags_int)

    return id.to_bytes(2, "big")+flags+questions_count.to_bytes(2, "big")+answers_count.to_bytes(2, "big")

def build_answer_ans_section(answers: dict, user_request: dict) -> bytes:
    answer_section = b""
    for answer in answers:
        ans_name = b'\xc0\x0c'
        ans_type_class = struct.pack('!HH', user_request["questions"][0]["type"], 1)
        ans_ttl = struct.pack('!I', answer["ttl"])
        ans_rdlength = struct.pack('!H', answer["length"])
        ans_rdata = build_rdata(answer["type"], answer["data"], answer["length"])
        answer_section += ans_name + ans_type_class + ans_ttl + ans_rdlength + ans_rdata

    return answer_section

def build_rdata(type: int, data: str | dict | bytes, length: int) -> bytes:
    if type == 1:
        ip_parts = [int(part) for part in data.split('.')]
        return bytes(ip_parts)
    elif type == 28:
        ip_parts = [int(part, 16) for part in data.split(':')]
        return bytes(ip_parts)
    elif type == 2:
        return encode_domain_name(data)
    elif type == 15:
        return struct.pack('!H', data["preference"]) + encode_domain_name(data["exchange"])
    elif type == 16:
        txt_bytes = data.encode('utf-8', errors='ignore')
        if len(txt_bytes) > 255:
            # Если текст очень длинный, бьем его на куски по 255 байт
            chunks = [txt_bytes[i:i+255] for i in range(0, len(txt_bytes), 255)]
            result = b""
            for chunk in chunks:
                result += struct.pack('B', len(chunk)) + chunk
            return result
        else:
            return struct.pack('B', len(txt_bytes)) + txt_bytes 
    else:
        return data

if __name__ == "__main__":
    tcp_server()
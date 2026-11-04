import socket
import struct
from parser import parse_dns_message, parse_mult_question
from dns_resolver import dns_iterator
from dns_packet_builder import create_dns_packet, FLAGS_INT_TO_RESPONSE


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
                if "multiply" in question["name"]:
                    last_part_ip4 = parse_mult_question(question["name"])
                    answer = {
                        "answer": f"{question["name"]}",
                        "type": 1,
                        "class": question["class"],
                        "ttl": BASE_TTL,
                        "length": 4,
                        "data": f"127.0.0.{last_part_ip4}"
                    }
                    answers.append(answer)
                else:
                    answers.append(answer for answer in dns_iterator(question["name"], question["type"]))
            print(answers)
            dns_response = create_dns_packet(parsed_request["id"], FLAGS_INT_TO_RESPONSE, parsed_request["questions"],answers)
            response = struct.pack("!H", len(dns_response)) + dns_response
            try:
                connection.sendall(response)
                print("Ответ пользователю отправлен")
            except OSError as exc:
                print("Ошибка при отправлке данных")
            finally:
                connection.close()

if __name__ == "__main__":
    tcp_server()
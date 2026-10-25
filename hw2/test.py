
import socket
import struct
import random
import time

ROOT_SERVER = "198.41.0.4"       # a.root-servers.net
GOOGLE_DNS = "8.8.8.8"           # Рекурсивный DNS Google
CLOUDFLARE_DNS = "1.1.1.1"       # Рекурсивный DNS Cloudflare

TEST_DOMAIN = "www.example.com"


def encode_name(domain):
    result = b""

    for label in domain.rstrip(".").split("."):
        encoded = label.encode("ascii")
        if not encoded or len(encoded) > 63:
            raise ValueError(f"Некорректная DNS-метка: {label!r}")
        result += bytes([len(encoded)]) + encoded

    return result + b"\x00"


def make_query(domain, record_type=1):
    request_id = random.randrange(65536)

    # RD=0: не просим рекурсивный поиск
    flags = 0

    header = struct.pack(
        "!HHHHHH",
        request_id, flags, 1, 0, 0, 0
    )

    question = encode_name(domain)
    question += struct.pack("!HH", record_type, 1)

    return request_id, header + question


def decode_name(packet, position):
    labels = []
    return_position = None
    visited = set()

    while True:
        if position >= len(packet):
            raise ValueError("Имя выходит за границы пакета")

        length = packet[position]

        if length == 0:
            position += 1
            break

        if length & 0xC0 == 0xC0:
            if position + 1 >= len(packet):
                raise ValueError("Обрезанный DNS pointer")

            pointer = ((length & 0x3F) << 8) | packet[position + 1]

            if pointer >= len(packet) or pointer in visited:
                raise ValueError("Некорректный DNS pointer")

            visited.add(pointer)

            if return_position is None:
                return_position = position + 2

            position = pointer
            continue

        if length & 0xC0:
            raise ValueError("Некорректный тип DNS-метки")

        position += 1

        if length > 63 or position + length > len(packet):
            raise ValueError("Некорректная длина DNS-метки")

        labels.append(
            packet[position:position + length].decode(
                "ascii", errors="replace"
            )
        )

        position += length

    return ".".join(labels), (
        return_position if return_position is not None else position
    )


def parse_response(packet):
    if len(packet) < 12:
        raise ValueError("DNS-пакет короче заголовка")

    response_id, flags, qd, an, ns, ar = struct.unpack(
        "!HHHHHH", packet[:12]
    )

    position = 12

    questions = []

    for _ in range(qd):
        name, position = decode_name(packet, position)

        if position + 4 > len(packet):
            raise ValueError("Обрезанный DNS-вопрос")

        qtype, qclass = struct.unpack(
            "!HH", packet[position:position + 4]
        )
        position += 4

        questions.append((name, qtype, qclass))

    sections = {
        "answers": [],
        "authority": [],
        "additional": []
    }

    for section_name, count in (
        ("answers", an),
        ("authority", ns),
        ("additional", ar)
    ):
        for _ in range(count):
            name, position = decode_name(packet, position)

            if position + 10 > len(packet):
                raise ValueError("Обрезанный заголовок DNS-записи")

            rtype, rclass, ttl, rdlength = struct.unpack(
                "!HHIH", packet[position:position + 10]
            )
            position += 10

            if position + rdlength > len(packet):
                raise ValueError("DNS-запись выходит за границы пакета")

            rdata_position = position
            rdata = packet[position:position + rdlength]
            position += rdlength

            value = None

            if rtype == 1 and rdlength == 4:
                value = socket.inet_ntoa(rdata)
            elif rtype == 2:
                value, _ = decode_name(packet, rdata_position)
            elif rtype == 5:
                value, _ = decode_name(packet, rdata_position)
            elif rtype == 28 and rdlength == 16:
                value = socket.inet_ntop(socket.AF_INET6, rdata)

            sections[section_name].append({
                "name": name,
                "type": rtype,
                "class": rclass,
                "ttl": ttl,
                "value": value,
                "data": rdata
            })

    return {
        "id": response_id,
        "flags": flags,
        "rcode": flags & 0x000F,
        "truncated": bool(flags & 0x0200),
        "recursion_available": bool(flags & 0x0080),
        "authoritative": bool(flags & 0x0400),
        "questions": questions,
        **sections
    }


def query_server(server_ip, domain, timeout=3):
    request_id, request_packet = make_query(domain)

    start = time.perf_counter()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(request_packet, (server_ip, 53))
        response_packet, remote_address = sock.recvfrom(4096)

    elapsed_ms = (time.perf_counter() - start) * 1000
    response = parse_response(response_packet)

    if response["id"] != request_id:
        raise ValueError("ID ответа не совпадает с ID запроса")

    if not (response["flags"] & 0x8000):
        raise ValueError("Полученный пакет не помечен как DNS-ответ")

    if remote_address[0] != server_ip:
        raise ValueError(
            f"Неожиданный адрес источника: {remote_address[0]}"
        )

    if response["questions"]:
        expected_question = (
            domain.rstrip(".").lower(), 1, 1
        )
        actual_question = response["questions"][0]

        if (
            actual_question[0].rstrip(".").lower(),
            actual_question[1],
            actual_question[2]
        ) != expected_question:
            raise ValueError(
                f"Вопрос в ответе не совпадает: {actual_question}"
            )

    response["elapsed_ms"] = elapsed_ms
    response["remote_address"] = remote_address[0]

    return response


def print_report(server_ip, domain):
    print("\n" + "=" * 65)
    print(f"Сервер: {server_ip}")
    print(f"Домен:  {domain}")

    try:
        result = query_server(server_ip, domain)

        print(f"Источник ответа: {result['remote_address']}")
        print(f"Время ответа:    {result['elapsed_ms']:.1f} мс")
        print(f"RCODE:           {result['rcode']}")
        print(f"Флаги:           0x{result['flags']:04x}")
        print(f"AA:              {result['authoritative']}")
        print(f"RA:              {result['recursion_available']}")
        print(f"TC:              {result['truncated']}")

        for section_name in (
            "answers", "authority", "additional"
        ):
            print(f"\n{section_name.upper()}:")

            for record in result[section_name]:
                print(
                    f"  {record['name']} "
                    f"type={record['type']} "
                    f"ttl={record['ttl']} "
                    f"value={record['value']}"
                )

            if not result[section_name]:
                print("  (пусто)")

    except Exception as error:
        print(f"ОШИБКА: {type(error).__name__}: {error}")


if __name__ == "__main__":
    for dns_server in (
        ROOT_SERVER,
        GOOGLE_DNS,
        CLOUDFLARE_DNS
    ):
        print_report(dns_server, TEST_DOMAIN)

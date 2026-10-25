"""
Вид ДНС запроса
{
"header": {
    "id":      ,  # Идентификатор DNS-сообщения для сопоставления запроса и ответа
    "qr":      ,  # Тип сообщения: 0 — запрос, 1 — ответ
    "opcode":  ,  # Тип операции: 0 — обычный DNS-запрос (QUERY)
    "aa":      ,  # Авторитетный ответ: 1 — ответ получен от авторитетного сервера
    "tc":      ,  # Усечение сообщения: 1 — сообщение обрезано
    "rd":      ,  # Желаемая рекурсия: 1 — клиент просит рекурсивное разрешение
    "ra":      ,  # Доступность рекурсии: 1 — сервер поддерживает рекурсию
    "z":       ,  # Поле зарезервированное для будущего использования
    "rcode":   ,  # Код результата: 0 — успешно, 3 — домен не существует (NXDOMAIN)
    "qdcount": ,  # Количество вопросов в секции Question
    "ancount": ,  # Количество ресурсных записей в секции Answer
    "nscount": ,  # Количество ресурсных записей в секции Authority
    "arcount": ,  # Количество ресурсных записей в секции Additional
},
"questions": [
    {
        "name": ,
        "type": ,
        "class": 
    }
],
"answers": [],
"authority": [],
"additional": []
}
"""

import struct
import ipaddress


def parse_dns_message(data: bytes) -> dict:
    """Возвращает распарсенный днс запрос"""
    header = parse_header(data)
    questions, offset = parse_qustions(data, header["qdcount"])
    sections = {}
    for name, count in [("answers", header["ancount"]), ("authority", header["nscount"]), ("additional", header["arcount"])]:
        section = []
        for _ in range(count):
            record, offset = parse_resource_record(data, offset)
            section.append(record)
        sections[name] = section

    return {
        "header": header,
        "questions": questions,
        "answers": sections["answers"],
        "authority": sections["authority"],
        "additional": sections["additional"]
    }

def parse_header(data: bytes) -> dict:
    if len(data) < 12:
            raise ValueError("DNS packet is too short")
    
    # ! означает Big Endian, H — unsigned short (2 байта)
    id, flags, qdcount, ancount, nscount, arcount = \
        struct.unpack("!6H", data[:12])

    header = {
        "id": id,

        "qr": (flags >> 15) & 0x1,
        "opcode": (flags >> 11) & 0xF,
        "aa": (flags >> 10) & 0x1,
        "tc": (flags >> 9) & 0x1,
        "rd": (flags >> 8) & 0x1,
        "ra": (flags >> 7) & 0x1,
        "z": (flags >> 4) & 0x7,
        "rcode": flags & 0xF,

        "qdcount":qdcount,
        "ancount": ancount,
        "nscount": nscount,
        "arcount": arcount,
    }
    return header

def decode_domain_name(data: bytes, offset: int) -> tuple[str, int]:
    """Декодирует доменное имя, включая compression pointers."""
    labels = []
    pos = offset
    next_offset = None
    visited = set()

    while True:
        if pos >= len(data):
            raise ValueError("Unexpected end of DNS packet")

        length = data[pos]

        # Конец имени
        if length == 0:
            pos += 1
            if next_offset is None:
                next_offset = pos
            break

        # Compression pointer: два старших бита равны 11
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                raise ValueError("Incomplete compression pointer")
            #берем оставшиеся 6 бит прибавляем к ним 8 бит и получаем смещение которое указывает на каком мест у нас находтся запись доменного имени
            pointer = ((length & 0x3F) << 8) | data[pos + 1]

            if pointer >= len(data):
                raise ValueError("Invalid compression pointer")

            if pointer in visited:
                raise ValueError("Compression pointer loop")

            visited.add(pointer)

            if next_offset is None:
                next_offset = pos + 2

            pos = pointer
            continue

        # 0xC0 = 11000000 проверка что старшие биты не используются
        if length & 0xC0:
            raise ValueError("Invalid DNS label")

        if length > 63:
            raise ValueError("DNS label too long")

        pos += 1

        if pos + length > len(data):
            raise ValueError("Incomplete DNS label")

        labels.append(data[pos:pos + length].decode("ascii"))
        pos += length

    return ".".join(labels), next_offset

def parse_qustions(data: bytes, qdcount: int) -> tuple[list, int]:
    """Возвращает распаршенные вопросы и смещение по байтам"""
    questions = []
    offset = 12

    for _ in range(qdcount):
        name, offset = decode_domain_name(data, offset)

        if offset + 4 > len(data):
            raise ValueError("Incomplete DNS question")

        qtype, qclass = struct.unpack(
            "!HH", data[offset:offset + 4]
        )
        offset += 4

        questions.append({
            "name": name,
            "type": qtype,
            "class": qclass,
        })

    return questions, offset


def parse_resource_record(data: bytes, offset: int) -> tuple[dict, int]:
    """Разбирает одну ресурсную запись."""
    name, offset = decode_domain_name(data, offset)

    if offset + 10 > len(data):
        raise ValueError("Incomplete resource record header")
    #I обозначает число размером 4 байта
    rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
    offset += 10

    if offset + rdlength > len(data):
        raise ValueError("Incomplete RDATA")

    
    rdata = data[offset:offset + rdlength]
    value = parse_rdata(rtype, rdlength, data, offset)
    offset += rdlength

    record = {
        "name": name,
        "type": rtype,
        "class": rclass,
        "ttl": ttl,
        "length": rdlength,
        "data": value,
    }

    return record, offset

def parse_rdata(rtype: int, length: int, data: bytes, offset: int) -> str | dict | bytes:
    # Декодируем данные в зависимости от типа записи
    # A
    if rtype == 1 and length == 4:
        value = str(ipaddress.IPv4Address(data[offset:offset+length]))
    # AAAA
    elif rtype == 28 and length == 16:
        value = str(ipaddress.IPv6Address(data[offset:offset+length]))
    # NS, CNAME
    elif rtype in (2, 5):
        value, _ = decode_domain_name(data, offset)
    #MX
    elif rtype == 15 and length >= 3:
        preference = struct.unpack("!H", data[offset:offset+2])[0]
        exchange, _ = decode_domain_name(data, offset + 2)
        value = {
            "preference": preference,
            "exchange": exchange,
        }
    #TXT
    elif rtype == 16:
        value = []
        pos = offset

        while pos < length:
            length = data[pos]
            pos += 1

            if pos + length > length:
                raise ValueError("Invalid TXT record")

            value.append(
                data[pos:pos + length].decode("utf-8", errors="replace")
            )
            pos += length

    else:
        # Неизвестные типы пока оставляем в сыром виде
        value = data

    return value
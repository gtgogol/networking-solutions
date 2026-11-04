import struct

FLAGS_INT_TO_RESPONSE = (
        (1 << 15) | # qr
        (0 << 11) | # opcode
        (1 << 10) | # aa
        (0 << 9)  | # tc
        (1 << 8)  | # rd
        (1 << 7)  | # ra
        (0 << 4)  | # z
        0 # rcode
    )

FLAGS_INT_TO_REQUEST_WITHOT_RECURSION = 0

def encode_domain_name(domain_name: str) -> bytes:
    encoded_name = b""
    for label in domain_name.rstrip(".").split("."):
        label_bytes = label.encode("ascii")

        if len(label_bytes) > 63:
            raise ValueError("DNS-метка не может быть длиннее 63 байт")

        encoded_name += bytes([len(label_bytes)]) + label_bytes

    return encoded_name + b"\x00"

def create_dns_packet(id: int, header_flags_int: int, questions: list, answers: list = None) -> bytes:
    """Строит днс пакет"""
    len_answers = len(answers) if answers is not None else 0 
    header = build_header(id, header_flags_int, len(questions), len_answers)
    questions_section = build_questions_section(questions)
    answers_section = build_answers_section(answers)

    return header + questions_section + answers_section
    
def build_header(id: int, flags_int: int, questions_count: int, answers_count: int) -> bytes:
    return struct.pack('!6H', id, flags_int, questions_count, answers_count, 0, 0)

def build_questions_section(questions: list[dict]) -> bytes:
    if questions is None or len(questions) == 0:
            raise ValueError("Введен неправильный тип данных")
    
    questions_section = b""
    for question in questions:
        question_name = encode_domain_name(question["name"])
        question_details = struct.pack("!HH", question["type"], 1)
        questions_section += question_name + question_details

    return questions_section

def build_answers_section(answers: dict) -> bytes:
    answers_section = b""

    if answers is None:
        return answers_section
    
    for answer in answers:
        ans_name = encode_domain_name(answer["name"])
        ans_type_class = struct.pack('!HH', answer["type"], 1)
        ans_ttl = struct.pack('!I', answer["ttl"])
        ans_rdata = build_rdata(answer["type"], answer["data"], answer["length"])
        ans_rdlength = struct.pack('!H', len(ans_rdata))
        answers_section += ans_name + ans_type_class + ans_ttl + ans_rdlength + ans_rdata

    return answers_section

def build_rdata(type: int, data: str | dict | bytes, length: int) -> bytes:
    if type == 1:
        ip_parts = [int(part) for part in data.split('.')]
        return struct.pack('!4B', *ip_parts)
    elif type == 28:
        ip_parts = [int(part, 16) for part in data.split(':')]
        return struct.pack('!8H', *ip_parts)
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


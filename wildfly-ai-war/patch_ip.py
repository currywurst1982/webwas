#!/usr/bin/env python3
"""
Java class file patcher: replace IP address in constant pool UTF8 strings
Old IP: 3.36.46.114  (12 bytes)
New IP: 43.203.167.24 (13 bytes)
"""
import struct, sys

OLD_IP = b'3.36.46.114'
NEW_IP = b'43.203.167.24'

def parse_cp_entry(data, pos):
    tag = data[pos]
    if tag == 1:   # CONSTANT_Utf8
        length = struct.unpack_from('>H', data, pos + 1)[0]
        return pos + 3 + length, tag, data[pos+3:pos+3+length]
    elif tag in (3, 4):   # Integer, Float
        return pos + 5, tag, None
    elif tag in (5, 6):   # Long, Double (2 slots)
        return pos + 9, tag, None
    elif tag in (7, 8, 16, 19, 20):
        return pos + 3, tag, None
    elif tag == 15:
        return pos + 4, tag, None
    elif tag in (9, 10, 11, 12, 17, 18):
        return pos + 5, tag, None
    else:
        raise ValueError(f"Unknown constant pool tag {tag} at pos {pos}")

def patch_file(src, dst):
    with open(src, 'rb') as f:
        data = bytearray(f.read())

    assert data[:4] == b'\xca\xfe\xba\xbe', "Not a valid class file!"

    cp_count = struct.unpack_from('>H', data, 8)[0]
    pos = 10
    patched = 0

    i = 1
    while i < cp_count:
        tag = data[pos]
        next_pos, _, value = parse_cp_entry(data, pos)

        if tag == 1 and value and OLD_IP in value:
            new_value = value.replace(OLD_IP, NEW_IP)
            new_entry = bytes([1]) + struct.pack('>H', len(new_value)) + new_value
            old_size = 3 + len(value)
            data = data[:pos] + bytearray(new_entry) + data[pos + old_size:]
            delta = len(new_value) - len(value)
            next_pos = pos + 3 + len(new_value)
            print(f"  [#{i}] 패치: {value.decode('utf-8', errors='replace')[:60]}...")
            patched += 1

        pos = next_pos
        if tag in (5, 6):
            i += 2
        else:
            i += 1

    with open(dst, 'wb') as f:
        f.write(data)

    print(f"  → {patched}개 상수 패치 완료: {src}")
    return patched

if __name__ == '__main__':
    files = [
        ('WEB-INF/classes/com/example/ai/tools/WildFlyManagementTool.class',
         'WEB-INF/classes/com/example/ai/tools/WildFlyManagementTool.class'),
        ('WEB-INF/classes/com/example/ai/WildFlyAiService.class',
         'WEB-INF/classes/com/example/ai/WildFlyAiService.class'),
    ]
    total = 0
    for src, dst in files:
        print(f"\n패칭: {src}")
        tmp = src + '.tmp'
        n = patch_file(src, tmp)
        import os; os.replace(tmp, dst)
        total += n
    print(f"\n총 {total}개 상수 패치 완료.")
    print(f"IP 변경: {OLD_IP.decode()} → {NEW_IP.decode()}")

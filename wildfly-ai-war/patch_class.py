#!/usr/bin/env python3
"""
Java class file patcher: "bash" -> "/bin/bash" in constant pool
"""
import struct, shutil, sys

def parse_cp_entry(data, pos):
    tag = data[pos]
    if tag == 1:   # CONSTANT_Utf8
        length = struct.unpack_from('>H', data, pos + 1)[0]
        return pos + 3 + length, tag, data[pos+3:pos+3+length]
    elif tag in (3, 4):   # Integer, Float
        return pos + 5, tag, None
    elif tag in (5, 6):   # Long, Double (takes 2 slots)
        return pos + 9, tag, None
    elif tag in (7, 8, 16, 19, 20):  # Class, String, MethodType, Module, Package
        return pos + 3, tag, None
    elif tag == 15:  # MethodHandle
        return pos + 4, tag, None
    elif tag in (9, 10, 11, 12, 17, 18):  # Fieldref, Methodref, etc.
        return pos + 5, tag, None
    else:
        raise ValueError(f"Unknown constant pool tag {tag} at pos {pos}")

def patch(src, dst):
    with open(src, 'rb') as f:
        data = bytearray(f.read())

    # Java class file header
    magic = data[:4]
    assert magic == b'\xca\xfe\xba\xbe', "Not a valid class file!"

    cp_count = struct.unpack_from('>H', data, 8)[0]
    pos = 10  # start of constant pool

    found = False
    i = 1
    while i < cp_count:
        tag = data[pos]
        next_pos, _, value = parse_cp_entry(data, pos)

        if tag == 1 and value == b'bash':
            print(f"  Found Utf8 'bash' at constant #{i}, byte offset {pos}")
            new_str = b'/bin/bash'
            # Build new entry: tag(1) + length(2) + bytes
            new_entry = bytes([1]) + struct.pack('>H', len(new_str)) + new_str
            old_size = 3 + len(value)       # 3 + 4 = 7
            new_size = 3 + len(new_str)     # 3 + 9 = 12
            data = data[:pos] + bytearray(new_entry) + data[pos + old_size:]
            print(f"  Replaced 'bash' -> '/bin/bash' (+{new_size - old_size} bytes)")
            found = True
            break

        pos = next_pos
        if tag in (5, 6):   # Long/Double occupy 2 slots
            i += 2
        else:
            i += 1

    if not found:
        print("ERROR: Could not find Utf8 constant 'bash' in class file!")
        sys.exit(1)

    with open(dst, 'wb') as f:
        f.write(data)
    print(f"  Patched class written to: {dst}")

if __name__ == '__main__':
    src = 'WEB-INF/classes/com/example/ai/tools/WildFlyManagementTool.class'
    dst = src + '.patched'
    print(f"Patching {src} ...")
    patch(src, dst)
    # Verify patch
    with open(dst, 'rb') as f:
        raw = f.read()
    if b'/bin/bash' in raw:
        print("  Verification OK: '/bin/bash' found in patched file.")
    if b'\x00\x04bash' not in raw:
        print("  Verification OK: old 'bash' (4-byte) string removed.")
    print("Done.")

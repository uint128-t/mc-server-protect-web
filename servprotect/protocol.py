import struct
import threading

# -- VarInt helpers --
def read_varint(sock):
    num_read = 0
    result = 0
    while True:
        byte = sock.recv(1)
        if not byte:
            raise IOError("Connection closed")
        value = byte[0]
        result |= (value & 0x7F) << (7 * num_read)
        num_read += 1
        if num_read > 5:
            raise ValueError("VarInt too big")
        if (value & 0x80) == 0:
            break
    return result

def write_varint(value):
    out = bytearray()
    while True:
        temp = value & 0x7F
        value >>= 7
        if value != 0:
            temp |= 0x80
        out.append(temp)
        if value == 0:
            break
    return out

# -- Packet helpers --
def read_fully(sock, length):
    data = b""
    while len(data) < length:
        more = sock.recv(length - len(data))
        if not more:
            raise IOError("Connection closed while reading")
        data += more
    return data

def read_string(sock):
    length = read_varint(sock)
    data = read_fully(sock, length)
    return data.decode("utf-8")

def write_string(s):
    b = s.encode("utf-8")
    return write_varint(len(b)) + b

def write_boolean(b):
    return b"\x01" if b else b"\x00"

def write_long(value):
    return struct.pack(">q", value)

def write_int(value):
    return struct.pack(">i", value)

def write_short(value):
    return struct.pack(">h", value)

def write_float(value):
    return struct.pack(">f", value)

def write_double(value):
    return struct.pack(">d", value)

def write_position(x, y, z):
    # position is a single long:
    # (x & 0x3FFFFFF) << 38 | (y & 0xFFF) << 26 | (z & 0x3FFFFFF)
    val = ((x & 0x3FFFFFF) << 38) | ((y & 0xFFF) << 26) | (z & 0x3FFFFFF)
    return write_long(val)

def send_packet(sock, packet_id, data_bytes):
    packet_data = write_varint(packet_id) + data_bytes
    packet_length = write_varint(len(packet_data))
    sock.sendall(packet_length + packet_data)

def wait_for_packet_id(conn,eid):
    packlen = read_varint(conn)
    packid = read_varint(conn)
    while packid!=eid:
        ct=read_fully(conn,packlen-len(write_varint(packid)))
        packlen = read_varint(conn)
        packid = read_varint(conn)

PACKET_LOCK = threading.Lock()
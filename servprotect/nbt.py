import struct

# NBT type IDs
TAG_End       = 0
TAG_Byte      = 1
TAG_Short     = 2
TAG_Int       = 3
TAG_Long      = 4
TAG_Float     = 5
TAG_Double    = 6
TAG_ByteArray = 7
TAG_String    = 8
TAG_List      = 9
TAG_Compound  = 10
TAG_IntArray  = 11
TAG_LongArray = 12

# ---- basic writers ----
def w_u8(v):     return struct.pack(">B", v)
def w_i8(v):     return struct.pack(">b", v)
def w_i16(v):    return struct.pack(">h", v)
def w_u16(v):    return struct.pack(">H", v)   # NBT string lengths are UNSIGNED
def w_i32(v):    return struct.pack(">i", v)
def w_i64(v):    return struct.pack(">q", v)
def w_f32(v):    return struct.pack(">f", v)
def w_f64(v):    return struct.pack(">d", v)

def w_nbt_string_bytes(s: str) -> bytes:
    b = s.encode("utf-8")         # NBT uses (modified) UTF-8; plain UTF-8 works for normal text
    return w_u16(len(b)) + b

# ---- tag writers with key ----
def nbt_byte(key, value):
    return w_u8(TAG_Byte) + w_nbt_string_bytes(key) + w_i8(value)

def nbt_short(key, value):
    return w_u8(TAG_Short) + w_nbt_string_bytes(key) + w_i16(value)

def nbt_int(key, value):
    return w_u8(TAG_Int) + w_nbt_string_bytes(key) + w_i32(value)

def nbt_long(key, value):
    return w_u8(TAG_Long) + w_nbt_string_bytes(key) + w_i64(value)

def nbt_float(key, value):
    return w_u8(TAG_Float) + w_nbt_string_bytes(key) + w_f32(value)

def nbt_double(key, value):
    return w_u8(TAG_Double) + w_nbt_string_bytes(key) + w_f64(value)

def nbt_string(key, value: str):
    return w_u8(TAG_String) + w_nbt_string_bytes(key) + w_nbt_string_bytes(value)

def nbt_compound_start(key=""):
    return w_u8(TAG_Compound) + w_nbt_string_bytes(key)

def nbt_compound_end():
    return w_u8(TAG_End)

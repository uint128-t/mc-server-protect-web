from . import webserv

from .protocol import *
from . import login
from .nbt import *
import socket

with open("statusping.json","r") as r:
    status_ping = r.read()

def answer_serverping(conn):
    pklen = read_varint(conn)
    pkid = read_varint(conn)
    if pkid==0x00:
        send_packet(conn,0x00,write_string(status_ping))
        wait_for_packet_id(conn,0x01)
    send_packet(conn,0x01,read_fully(conn,8))

def client2serv(client,server):
    try:
        packlen = read_varint(client)
        packid = read_varint(client)
        assert packid==0x00
        protocol_version = read_varint(client)
        server_address = read_string(client)
        server_port = struct.unpack(">H", read_fully(client, 2))[0]
        next_state = read_varint(client)
        response = (
            write_varint(protocol_version) +
            write_string(server_address) +
            struct.pack(">H", server_port) +
            write_varint(2) # Force login even if transferring
        )
        if next_state == 1: # Server Ping
            print("Proxy server ping")
            send_packet(server,0x00,write_varint(protocol_version)+write_string(server_address)+struct.pack(">H", server_port)+write_varint(1))
            return unidirectional_proxy(client,server)
        send_packet(server,packid,response)
        packlen = read_varint(client)
        packid = read_varint(client)
        username = read_string(client)
        ct=read_fully(client,packlen-len(write_varint(packid))-len(write_string(username)))
        if login.user_logged_in(client.getpeername()[0],username):
            send_packet(server,packid,write_string(username)+ct)
            print(f"Proxying {username}")
            unidirectional_proxy(client,server)
        else:
            print("ERROR: USERNAME CHANGED")
            raise Exception
    except:
        client.close()
        server.close()
        return

def unidirectional_proxy(src,dst):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except:
        src.close()
        dst.close()
        return
    
def proxy_client(conn):
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy.connect(("127.0.0.1",25564))
    proxy.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    threading.Thread(target=client2serv,args=(conn,proxy),daemon=True).start()
    threading.Thread(target=unidirectional_proxy,args=(proxy,conn),daemon=True).start()

conn_ips = set()

def handle_client(conn, addr):
    try:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # Read handshake
        length = read_varint(conn)
        packet_id = read_varint(conn)
        if packet_id != 0x00:
            conn.close()
            return
        # handshake packet structure: protocol version, server addr, port, next state
        protocol_version = read_varint(conn)
        server_address = read_string(conn)
        server_port = struct.unpack(">H", read_fully(conn, 2))[0]
        next_state = read_varint(conn)
        if next_state == 1: # Server Ping
            answer_serverping(conn)
            raise Exception
        print(f"Handshake: version={protocol_version}, address={server_address}, port={server_port}, state={next_state}")
        
        # Read Login Start packet
        length = read_varint(conn)
        packet_id = read_varint(conn)
        if packet_id != 0x00:
            raise Exception
        username = read_string(conn)
        # Get Client UUID
        cuuid = read_fully(conn,16)
        # Offline mode: create UUID from username
        offline_uuid = b"\x01"*16
        print(f"Login as: {username}")

        # Send Login Success (packet 0x02)
        # UUID and username as strings
        login_success_data = offline_uuid + write_string(username) + write_varint(0)
        if protocol_version==767:
            # Field "Strict Error Handling"
            login_success_data += write_boolean(False)
        send_packet(conn, 0x02, login_success_data)

        # Read Login Acknowledgement
        wait_for_packet_id(conn,0x03)

        # Disconnect client to require login
        disconnect_packet = (
            w_u8(TAG_Compound) +
            nbt_string("text","Login failed: Please login with the web interface")+
            nbt_string("color","red")+
            w_u8(TAG_End)
        )
        send_packet(conn,0x02, disconnect_packet)
    except:
        conn_ips.discard(addr[0])
        conn.close()

def runx(port):
    HOST = "0.0.0.0"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, port))
        s.listen()
        print(f"Server listening on port {HOST}:{port}")
        while True:
            conn, addr = s.accept()
            print(f"Request from {addr}")
            if login.ip_logged_in(addr[0]):
                proxy_client(conn)
            elif (addr[0] not in conn_ips) and len(conn_ips)<10: # Limit 10 connections in total to prevent DoS
                conn_ips.add(addr[0])
                # Anti slow-loris: only allow one connection per IP
                threading.Thread(target=handle_client,args=(conn,addr),daemon=True).start()

# threading.Thread(target=webserv.app.run,kwargs={"host":"0.0.0.0","port":10003},daemon=True).start()
threading.Thread(target=runx,args=(25565,),daemon=True).start()
app = webserv.app
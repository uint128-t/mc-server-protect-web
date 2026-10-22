from . import webserv

from .protocol import *
from . import login
from .nbt import *
import socket
import shell

with open("statusping.json","r") as r:
    status_ping = r.read()

def client2serv(client,server):
    try:
        # Read the handshake
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
            # Send ping handshake
            send_packet(server,0x00,write_varint(protocol_version)+write_string(server_address)+struct.pack(">H", server_port)+write_varint(1))
            # Read status request
            pl = read_varint(client)
            pid = read_varint(client)
            assert pid==0x00
            send_packet(server,0x00,b"")
            # Read ping request
            pl = read_varint(client)
            pid = read_varint(client)
            assert pid==0x01
            ts = read_fully(client,8)
            send_packet(server,0x01,ts)
            raise Exception("Ping handled")
        send_packet(server,packid,response)

        # Read login packet
        packlen = read_varint(client)
        packid = read_varint(client)
        username = read_string(client)
        ct=read_fully(client,packlen-len(write_varint(packid))-len(write_string(username)))
        if login.user_logged_in(client.getpeername()[0],username):
            send_packet(server,packid,write_string(username)+ct)
            print(f"Proxying {username}")
            unidirectional_proxy(client,server)
            print(f"Connection closed for {username}")
        else:
            disconnect_packet = (
                w_u8(TAG_Compound) +
                nbt_string("text","Login failed: Please login with the web interface")+
                nbt_string("color","red")+
                w_u8(TAG_End)
            )
            send_packet(server,0x02, disconnect_packet)
            raise Exception
    except:
        client.close()
        server.close()
        return

def unidirectional_proxy(src,dst):
    src.settimeout(120)
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

def runx(port):
    HOST = "0.0.0.0"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, port))
        s.listen()
        print(f"Server listening on port {HOST}:{port}")
        while True:
            conn, addr = s.accept()
            conn.settimeout(5)
            print(f"Request from {addr}")
            proxy_client(conn)

# threading.Thread(target=webserv.app.run,kwargs={"host":"0.0.0.0","port":10003},daemon=True).start()
threading.Thread(target=runx,args=(25565,),daemon=True).start()
threading.Thread(target=shell.shell,daemon=True).start()
app = webserv.app

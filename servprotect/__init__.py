import os
import socket
import threading

from .protocol import *
from .nbt import *
from . import console, login,webserv,config

with open("statusping.json","r") as r:
    status_ping = r.read()

connection_lock = threading.Lock()
connection_count = {} # address: count
connections=0

def client2serv(client,server,addr):
    global connections
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
            console.log("Proxy server ping")
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
        if login.user_logged_in(addr,username):
            send_packet(server,packid,write_string(username)+ct)
            console.log(f"Proxying {username}")
            unidirectional_proxy(client,server)
            console.log(f"Connection closed for {username}")
        else:
            disconnect_packet = (
                w_u8(TAG_Compound) +
                nbt_string("text",f"Login failed: Please login at http://{server_address}:{config.WEB_PORT}")+
                nbt_string("color","red")+
                w_u8(TAG_End)
            )
            disconnect_packet = write_string("\"r\"")
            send_packet(server,0x00, disconnect_packet)
            console.log(f"Login failed for {username}")
    except:
        pass
    finally:
        client.close()
        server.close()
        with connection_lock:
            connection_count[addr]-=1
            if connection_count[addr]==0:
                del connection_count[addr]
            connections-=1

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
    
def proxy_client(conn,addr):
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy.connect(("127.0.0.1",config.GAME_PORT))
    proxy.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    threading.Thread(target=client2serv,args=(conn,proxy,addr),daemon=True).start()
    threading.Thread(target=unidirectional_proxy,args=(proxy,conn),daemon=True).start()

def runx(port):
    global connections
    HOST = "0.0.0.0"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, port))
        s.listen()
        while True:
            conn, addr = s.accept()
            addr = addr[0]
            with connection_lock:
                if connections >= config.MAX_CONNECTIONS or connection_count.get(addr,0) >= config.MAX_IP_CONNECTIONS:
                    console.log(f"Too many connections from {addr}")
                    conn.close()
                    continue
                connection_count[addr] = connection_count.get(addr,0) + 1
                connections+=1
            conn.settimeout(5)
            console.log(f"Proxy Request from {addr}")
            proxy_client(conn,addr)

# threading.Thread(target=webserv.app.run,kwargs={"host":"0.0.0.0","port":10003},daemon=True).start()
PORT = config.PROXY_PORT
print(f"Proxy listening on port {PORT}")
threading.Thread(target=runx,args=(PORT,),daemon=True).start()
threading.Thread(target=console.prompt,daemon=True).start()
app = webserv.app

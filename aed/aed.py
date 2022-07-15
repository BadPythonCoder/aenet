import yaml, socket, json, threading
f = open("config.yaml")
config = yaml.load(f,yaml.Loader)
print(config)
PORT = config["port"]
HOST = config["host"]
PROTOCOLMAP = config["protocols"]
connections = {}
AEVER = 1
ROUTER = config["router"]

def upstream(client, real):
        while True:
                data = client.recv(2048)
                real.send(data)
def downstream(client,real):
        while True:
                data = real.recv(2048)
                client.send(data)

def handler(addr):
        global connections, protocolmap
        conn = connections[addr]
        if addr == "ROUTER":
                print("ROUTER CONNECTION")
                print(conn.recv(4096))
        try:
                handshakelen = int.from_bytes(conn.recv(3),"little")
                handshake = json.loads(conn.recv(handshakelen).decode('utf-8'))
                if handshake["encrypted"]:
                        conn.send(b'\x03ENCRYPTION NOT SUPPORTED')
                elif not handshake["version"] == AEVER:
                        conn.send(b'\x01VERSION NOT SUPPORTED')
                elif not handshake["protocol"] in PROTOCOLMAP:
                        conn.send(b'\x01PROTOCOL NOT FOUND')
                conn.send(b'\x02')
                real = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                real.connect(("127.0.0.1",PROTOCOLMAP[handshake["protocol"]]))
                up = threading.Thread(target=upstream,args=(conn,real,),daemon=True)
                down = threading.Thread(target=downstream,args=(conn,real,),daemon=True)
                up.start()
                down.start()
        except Exception as e:
                print("Error in handler with",addr)
                print(str(type(e)),e)
                connections[addr].close()
                del connections[addr]

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST,PORT))
s.listen()
print("listening")
while True:
        conn, addr = s.accept()
        connections[addr] = conn
        t = threading.Thread(target=handler,args=(addr,),daemon=True)
        t.start()

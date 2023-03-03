import socket, websocket, yaml, json, threading

f = open("config.yaml")
config = yaml.load(f, yaml.Loader)
print(config)

aeddr = config["addr"]
host = config["ip"]
port = config["port"]
ael = config["aeluri"]

connections = {}
tcp = {}
pingthreads = {}
handlerthreads = {}
###############################################
ws = None
connected = False
def on_open(_ws):
	global ws
	print("Connected to the server")
	ws = _ws
	ws.send(json.dumps({"addr":aeddr}))
def on_close(ws, status, msg):
	print("Disconnected from the aether link")
	print(f"{status}: {msg}")

def on_error(ws, error):
	print(f"ERROR ON WS: {error}")

def on_message(ws, data):
	global connected
	data = json.loads(data)
	if data["message"] == "Connected":
		connected = True
		aeddr = data["addr"]
		print(f"Connected to the aether link as {aeddr}")

def run():
	ws = websocket.WebSocketApp(ael,
                              on_open=on_open,
                              on_message=on_message,
                              on_error=on_error,
                              on_close=on_close)
	ws.run_forever()
threading.Thread(target=run,daemon=True).start()
#############################################
def bytes2ipv4(b):
	numbrs = []
	for i in range(4):
		numbrs.append(str(b[i]))
	return ".".join(numbrs)

def bytes2ae(b):
	hexnumbrs = []
	for i in range(4):
		numbrs.append((lambda x: ["","0",""][len(hex(x).split("x")[1])]+hex(x).split("x")[1])(b[i]))
	return "-".join(hexnumbrs)

def handler(conn, addr):
	tcp[addr] = conn
	ip = bytes2ipv4(conn.recv(4))
	addr = bytes2ae(conn.recv(4))
	conn.setblocking(0)
	conn.send(b'\x01')
	start = time.time()
	while time.time()-start < 30:
		data = conn.recv(4096)
		if data == b'\x01\x01':
			conn.send(b'\x01\x01\x01')
			start = time.time()
		elif data == b'\xff':
			break
		elif data[0] == b'\x88':
			# insert sending data stuff
			pass
	# insert disconnection stuff
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.bind((host,port))
s.listen(5)

while True:
	conn, addr = s.accept()
	print(addr)
	conn.close()

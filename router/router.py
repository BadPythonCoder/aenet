import yaml, socket, websocket, rel, json
f = open("config.yaml")
raw = f.read()
f.close()
config = yaml.load(raw, yaml.Loader)



class ael:
	def __init__(self, URL):
		self.ws = websocket.WebSocketApp(URL,
			on_open=self.on_open,
			on_message=self.on_message,
			on_error=self.on_error,
			on_close=self.on_close)
		self.ws.run_forever(dispatcher=rel)
		rel.signal(2, rel.abort)
		rel.dispatch()
		self.addr = "NONE"
	def on_message(self, ws, msg):
		if type(msg) == str:
			msg = json.loads(msg)
		if "message" in msg:
			if msg["message"] == "Connected":
				print("Connection established with ae link")
				print(f"AElink address of aether network {msg['addr']}")
				self.addr = msg["addr"]
	def on_error(self, ws, error):
		print(f"ERROR {error}")
	def on_close(self, ws, code, msg):
		print(f"CLOSE {code} {msg}")
	def on_open(self, ws):
		global config
		print("Establishing connection with ae link...")
		handshake = {"addr":config["addr"]}
		ws.send(json.dumps(handshake))


link = ael(config["aelurl"])


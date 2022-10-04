import threading, socket, re, aenet, yaml, json, os
path = __file__.replace(os.path.basename(__file__),"")+"config.yaml"
f = open("config.yaml")
obj = yaml.load(f,yaml.Loader)

class Proxy:
  def __init__(self):
    self.host = "0.0.0.0"
    self.port = obj["proxyport"]
    self.PROXVER = b'\x05' 
    self.IPV4REGEX = "\d+\.\d+\.\d+\.\d+"
    self.IPV6REGEX = "([abcdef0-9]{4}:){7}[abcdef0-9]{4}"
  def upstream(self, conn, other):
    try:
      while True:
        data = conn.recv(2048)
        if not data == b'':
          print("[UPSTREAM]",data)
          other.send(data)
    except Exception as e:
      print("ERROR IN UPSTREAM")
      print(str(e))
      other.close()
      conn.close()
  def downstream(self, conn, other):
    try:
      while True:
        data = other.recv(2048)
        if not data == b'':
          print("[DOWNSTREAM]",data)
          conn.send(data)
    except Exception as e:
      print("ERROR IN DOWNSTREAM")
      print(str(e))
      other.close()
      conn.close()
  def handler(self, conn):
    ver = conn.recv(1)
    if not ver == self.PROXVER:
      conn.close()
      return False
    nauth = int.from_bytes(conn.recv(1),"little")
    auth = conn.recv(nauth)
    if b'\x00' in auth:
      conn.send(self.PROXVER+b'\x00')
    else:
      conn.send(self.PROXVER+b'\xff')
      conn.close()
      return False
    print("auth passed")
    ver = conn.recv(1)
    cmd = conn.recv(1)
    _ = conn.recv(1)
    addr, _ = self.get_address(conn)
    port = int.from_bytes(conn.recv(2),"big")
    try:
      if addr.endswith(".ae"):
        cmd = b'\x69'
        print("aether detected")
      if cmd == b'\x01':
        other = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        other.connect((addr,port))
        # print(binded_addr)
        binded_addr, binded_port = other.getsockname()
        # print(socket.inet_aton(binded_addr))
        # binded_addr = b'\x01'+socket.inet_aton(binded_addr)
        # print(binded_addr)
        if re.search(self.IPV4REGEX,binded_addr):
          binded_addr = b'\x01'+socket.inet_aton(binded_addr)
        elif re.search(self.IPV6REGEX,binded_addr):
          binded_addr = b'\x04'+socket.inet_aton(binded_addr)
        else:
          binded_addr = b'\x03'+int.to_bytes(len(binded_addr),"little")+binded_addr.encode("utf-8")
        binded_port = int.to_bytes(binded_port,2,"big")
        # print(self.PROXVER+b'\x00\x00'+binded_addr+int.to_bytes(binded_addr[1],2,"big"))
        conn.send(self.PROXVER+b'\x00\x00'+binded_addr+binded_port)
        upstreamT = threading.Thread(target=self.upstream,args=(conn,other,),daemon=True)
        downstreamT = threading.Thread(target=self.downstream,args=(conn, other),daemon=True)
        upstreamT.start()
        downstreamT.start()
      elif cmd == b'\x69':
        protocol = "test"
        binded_addr = b'\x03'+int.to_bytes(len(addr),1,"little")+addr.encode("utf-8")
        binded_port = int.to_bytes(port,2,"big")
        conn.send(self.PROXVER+b'\x00\x00'+binded_addr+binded_port)
        for k, v in obj["protocols"].items():
          if v["local"] == port:
            protocol = k
        print(protocol)
        if not addr.split(".")[-2] == "local":
          aetheraddr = addr.split(".")[-2]
          data = json.dumps({"ip":".".join(addr.split(".")[:-2]),"port":obj["protocols"][protocol]["ae"],"aedress":aetheraddr}).encode("utf-8") 
          other = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
          other.connect((obj["router"]["ip"],obj["router"]["port"]))
          other.send(data)
          handshake = json.dumps({"version": obj["version"],"encrypted":False,"protocol":protocol}).encode("utf-8")
          other.send(int.to_bytes(len(handshake),3,"little"))
          other.send(handshake)
          if not other.recv(4096).startswith(b"\x02"):
            return
        else:
          other = aenet.AEConn()
          actualaddr = ".".join(addr.split(".")[:-2])
          print(actualaddr)
          status, reason = other.connect(actualaddr,protocol)
          if not status:
            print("Connection with server failed: ",reason)
            return False
          print("Connection with server established")
          # print(addr.split(".")[:-2])
        upstreamT = threading.Thread(target=self.upstream,args=(conn,other,),daemon=True)
        downstreamT = threading.Thread(target=self.downstream,args=(conn, other),daemon=True)
        upstreamT.start()
        downstreamT.start()
          
      else:
        print("duc")
        conn.close()
        return False
    except Exception as e:
      print(str(e))

  def get_address(self, conn):
    addrtype = conn.recv(1)
    final = ""
    fbytes = addrtype
    if addrtype == b'\x01':
      for i in range(4):
        fbytes += conn.recv(1)
        final += str(fbytes[-1]) + "."
      final = final[:-1]
    elif addrtype == b'\x03':
      length = conn.recv(1)
      data = conn.recv(int.from_bytes(length,"big"))
      fbytes += length + data
      final = data.decode('utf-8')
    elif addrtype == b'\x04':
      for i in range(8):
        a = conn.recv(1)
        b = conn.recv(1)
        fbytes += a
        fbytes += b
        first = str(hex(a))[2:]
        second = str(hex(b))[2:]
        final += first + second + ":"
      final = final[:-1]
    return final, fbytes
  def startproxy(self):
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.bind((self.host,self.port))
    s.listen(5)
    print("[AETHERPROX] SOCKS5 Proxy server started!")
    while True:
      conn, addr = s.accept()
      print("[AETHERPROX] New connection, ",addr)
      t = threading.Thread(target=self.handler,args=(conn,),daemon=True)
      t.start()
  def start(self):
    threading.Thread(target=self.startproxy,daemon=True).start()
    try:
      while True:
        pass
    except:
      print("halting")
      quit()

proxy = Proxy()
proxy.start()

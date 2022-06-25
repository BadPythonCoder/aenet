import threading, socket, re, aenet, yaml, json

f = open("prox5conf.yml")
obj = yaml.load(f,yaml.CLoader)

class Proxy:
  def __init__(self):
    self.username = "CoderlolAEPROX"
    self.password = "AENETPROX"
    self.host = "0.0.0.0"
    self.port = 7121
    self.PROXVER = b'\x05' 
    self.IPV4REGEX = "\d+\.\d+\.\d+\.\d+"
    self.IPV6REGEX = "([abcdef0-9]{4}:){7}[abcdef0-9]{4}"
  # def convIPv4(self,ip):
  #   final = b''
  #   for n in ip.split("."):
  #     final += int.to_bytes(int(n), 1, "big")
  #   return final
  # def convIPv6(self, ip):
  #   final = b''
  #   for 
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
      print("OHNO!")
      print(ver)
      print(self.PROXVER)
      conn.close()
      return False
    nauth = int.from_bytes(conn.recv(1),"little")
    auth = conn.recv(nauth)
    print(auth)
    if b'\x02' in auth:
      conn.send(self.PROXVER+b'\x02')
      ver = conn.recv(1)
      NUSR = int.from_bytes(conn.recv(1),"little")
      USR = conn.recv(NUSR).decode("utf-8")
      NPAS = int.from_bytes(conn.recv(1),"little")
      PAS = conn.recv(NPAS).decode("utf-8")
      if USR == self.username and PAS == self.password:
        conn.send(self.PROXVER+b'\x00')
      else:
        print(USR)
        print(self.username)
        print(PAS)
        print(self.password)
        conn.send(self.PROXVER+b'\xff')
        conn.close()
        return False
    elif b'\x00' in auth:
      conn.send(self.PROXVER+b'\x00')
    else:
      print("NO CONNECTION")
      conn.send(self.PROXVER+b'\xff')
      conn.close()
      return False
    print("auth passed")
    ver = conn.recv(1)
    cmd = conn.recv(1)
    _ = conn.recv(1)
    addr, _ = self.get_address(conn)
    print(addr)
    port = int.from_bytes(conn.recv(2),"big")
    print(port)
    try:
      if addr.endswith(".ae"):
        print("AETHER!!!!!!")
        cmd = b'\x69'
      print("cmd",cmd)
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
        print(binded_addr)
        binded_port = int.to_bytes(binded_port,2,"big")
        # print(self.PROXVER+b'\x00\x00'+binded_addr+int.to_bytes(binded_addr[1],2,"big"))
        conn.send(self.PROXVER+b'\x00\x00'+binded_addr+binded_port)
        print(self.PROXVER+b'\x00\x00'+binded_addr+binded_port)
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
        if not addr.split(".")[-2] == "local":
          aetheraddr = addr.split(".")[-2]
          print(aetheraddr)
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
          # print(addr.split(".")[:-2])
        print(".".join(addr.split(".")[:-2]))
        print(other.connect(".".join(addr.split(".")[:-2]), protocol))
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
    print(addrtype)
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
  def start(self):
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.bind((self.host,self.port))
    s.listen(5)
    print("[AETHERPROX] SOCKS5 Proxy server started!")
    while True:
      conn, addr = s.accept()
      print("[AETHERPROX] New connection, ",addr)
      t = threading.Thread(target=self.handler,args=(conn,),daemon=True)
      t.start()

proxy = Proxy()
proxy.start()

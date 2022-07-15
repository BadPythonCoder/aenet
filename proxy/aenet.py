import socket, json, rsa

class AEConn:
  def __init__(self, AEVER=1):
    self.s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    self.AEVER = AEVER
    self.encryption = False
  def connect(self, addr, protocol, encryption=False, port=4162):
    self.encryption = rsa.newkeys(1024)
    try:
      self.handshake = json.dumps({"version": self.AEVER,"encrypted":encryption,"protocol":protocol}).encode("utf-8")
      self.handshakelength = int.to_bytes(len(self.handshake),3,"little")
      self.s.connect((addr, port))
      self.s.send(self.handshakelength)
      self.s.send(self.handshake)
      if encryption:
        serverpub = rsa.PublicKey.load_pkcs1(self.s.recv(4096))
        self.s.send(rsa.encrypt(int.to_bytes(self.encryption[1].p,128,"little")))
        self.s.send(rsa.encrypt(int.to_bytes(self.encryption[1].q,128,"little")))
        self.s.send(rsa.encrypt(int.to_bytes(self.encryption[1].n,128,"little")))
        self.s.send(rsa.encrypt(int.to_bytes(self.encryption[1].e,128,"little")))
        self.s.send(rsa.encrypt(int.to_bytes(self.encryption[1].d,128,"little")))

      resp = self.s.recv(1024)
      if resp.startswith(b'\x01'):
        return False, resp[1:].decode('utf-8')
      else:
        return True, "CONNECTION_ESTABLISHED"
    except Exception as e:
      return False, str(e)
  def send(self, data):
    self.s.send(data)
  def recv(self, buffer=1024):
    return self.s.recv(buffer)

import socket
from ip import IP

class TCP_Handler:
    def __init__(self, ip: IP = IP("127.0.0.1:25565", True)):
        self.open_connections = {}
        self.ip = ip
        self.bufferSize = 2048
        self.gen_socket()

    def gen_socket(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(self.ip.ip_value_tuple())
        self.socket.listen()

    def wait_for_con(self):
        con, senderIp = self.socket.accept()
        senderIp = IP(f"{senderIp[0]}{senderIp[1]}")
        self.open_connections[senderIp] = (con, True)
        return senderIp

    def receive_message(self, sender: IP):
        bytes = b''
        con, _ = self.open_connections[sender]
        while True:
            data = con.recv(self.bufferSize)
            if not data:
                break
            bytes += data
        return bytes
    
    def connect(self, destiny: IP):
        self.socket.connect(destiny.ip_value_tuple())    
    
    #very threadable function
    def send(self, message, destiny: IP = None):
            if destiny == None:
                self.socket.connect(message)
            else:
                con = self.open_connections[destiny]
                con.sendall(message)

    def close_connection(self, destiny: IP = None):
        if destiny:
            self.open_connections[destiny].close()
            self.open_connections.pop(destiny)
        else:
            self.socket.close()
            self.gen_socket()
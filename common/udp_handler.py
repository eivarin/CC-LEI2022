import socket
from ip import IP

#funciona com mensagens ate 2048
#mensagens maiores que 2048 so recebe 2048 bytes
#falta calcular overhead de headers
class UDP_Handler:
    def __init__(self, ip: IP = IP("127.0.0.1:25565", True)):
        self.ip = ip
        self.bufferSize = 2048
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(self.ip.ip_value_tuple())

    def receive(self):
        return self.socket.recvfrom(self.bufferSize)
    
    def send(self, message, destiny: IP):
        self.socket.sendto(message, destiny.ip_value_tuple())

    def close(self):
        self.socket.close()

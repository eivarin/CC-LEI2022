import socket


class tcpHandler:
    def __init__(self, ip):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(ip)
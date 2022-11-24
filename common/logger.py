from datetime import datetime
import sys
from threading import local
from common.parser import Parser

class Logger:
    def __init__(self, configs: Parser, is_debug: bool) -> None:
        self.allLogs = []
        self.domain_log_files = {}
        for domain, value in configs.result["LG"]:
            if not domain in self.domain_log_files:    
                self.domain_log_files[domain] = []
            self.domain_log_files[domain].append(value)
        if is_debug:
            self.domain_log_files["all"].append("debug")
    
    def write_log(self, domain, type, ip, entry_data, port = None):
        now = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        parsed_ip = f"{ip}" if port == None else f"{ip}:{port}"
        nline = f"{now} {type} {parsed_ip} {entry_data}\n"
        if domain != "all":
            for fname in self.domain_log_files[domain]:
                self.__write_log_aux(fname,nline)
        
        for fname in self.domain_log_files["all"]:
            if fname == "debug":
                sys.stdout.write(nline)
            else:
                self.__write_log_aux(fname,nline)

    def __write_log_aux(self, fname, line):
        f = open(fname, 'a')
        f.write(line)
        f.close()


    def log_qr(self, domain, ip, PDU, port = None):
        #parse pdu?
        self.write_log(domain, "QR", ip, PDU, port)

    def log_qe(self, domain, ip, PDU, port = None):
        #parse pdu?
        self.write_log(domain, "QE", ip, PDU, port)

    def log_rr(self, domain, ip, PDU, port = None):
        #parse pdu?
        self.write_log(domain, "RR", ip, PDU, port)

    def log_rp(self, domain, ip, PDU, port = None):
        #parse pdu?
        self.write_log(domain, "RP", ip, PDU, port)

    #Log de ZoneTransfer
    #ip = ip do outro servidor
    #entry_data = ("Se e SS ou SP", "duracao da transferencia de zona", "# de bytes transferidos")
    def log_zt(self, domain, ip, entry_data, port = None):
        parsed_data = f"{entry_data[0]} {entry_data[1]} {entry_data[2]}"
        self.write_log(domain, "ZT", ip, parsed_data, port)


    def log_ev(self, domain, event):
        #parse pdu?
        self.write_log(domain, "EV", "localhost", event)

    def log_er(self, domain, ip, reason, port = None):
        #parse pdu?
        self.write_log(domain, "ER", ip, reason, port)

    def log_ez(self, domain, ip, local_server_type, port = None):
        #parse pdu?
        self.write_log(domain, "EZ", ip, local_server_type, port)

    def log_fl(self, domain, reason):
        #parse pdu?
        self.write_log(domain, "FL", "localhost", reason)

    def log_to(self, domain, ip, reason, port = None):
        #parse pdu?
        self.write_log(domain, "TO", ip, reason, port)

    def log_sp(self, domain, reason):
        #parse pdu?
        self.write_log(domain, "SP", "localhost", reason)


    #data = ("porta de atendimento", "timeout", "shy/debug")
    def log_st(self, domain, data):
        port = data["port"]
        timeout = data["timeout"]
        debug = "debug" if data["debug"] else "shy"
        parsed_data = f"{port} {timeout} {debug}"
        self.write_log(domain, "ST", "localhost", parsed_data)

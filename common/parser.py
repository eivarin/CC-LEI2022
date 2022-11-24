from common import ip

class Config():
    def __init__(self, parameter, type, value):
        self.parameter = str(parameter)
        self.type      = str(type)
        self.value     = str(value)
    def __str__(self) -> str:
        return f"{self.parameter} {self.type} {self.value}"
    def __repr__(self) -> str:
        return f"{self.parameter} {self.type} {self.value}"

class Parser():
    def __init__(self,filename):
        self.filename = filename
        self.parse()

    def parse(self):
        f = open(self.filename, 'r')
        lns = f.read().splitlines()
        result = {}
        for l in lns:
            if l != "" and l[0] != '#' and l != "\n":
                values = l.split()
                if len(values) <= 5:
                    if values[1] not in result:
                        result[values[1]] = []
                    result[values[1]] += [[values[0]] + values[2:]]
        f.close()
        self.result = result
    

def ArgsParser(argv, minimum_args: int):
    """_summary_

    Args:
        argv (List de argumentos): _description_
        minimum_args (int): _description_

    Returns:
        Lista de parametros: _description_
    """
    l = []
    d = {"port": 53, "timeout": 20000,"debug": False}
    if len(argv) >= minimum_args:
        i = 1
        while len(argv) > i:
            isFlag = False
            match argv[i]:
                case "--port":
                    d["port"] = int(argv[i+1])
                case "--timeout":
                    d["timeout"] = int(argv[i+1])
                case "--mode":
                    d["debug"] = argv[i+1] == "debug"
                case "--ip":
                    x = argv[i+1]
                    is_ip, has_port = ip.check_ip(x)
                    if not has_port:
                        x += f":{d['port']}"
                    if is_ip:
                        d["ip"] = ip.IP(x, has_port=True)
                case _:
                    l.append(argv[1])
            if isFlag:
                i+=2
            else:
                i+=1
        return l, d
    else:
        print("kabum")
        exit()



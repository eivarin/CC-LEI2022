class Config():
    def __init__(self, parameter, type, value):
        self.parameter = str(parameter)
        self.type      = str(type)
        self.value     = str(value)
    def __str__(self) -> str:
        return f"{self.parameter} {self.type} {self.value}"
    def __repr__(self) -> str:
        return f"{self.parameter} {self.type} {self.value}"

class Configs():
    def __init__(self,filename):
        self.filename = filename
        self.parse()

    def parse(self):
        f = open(self.filename, 'r')
        lns = f.readlines()
        result = {}
        for l in lns:
            if l[0] != '#' and l != "\n":
                values = l.split()
                result[values[1]] = (values[0], values[2])
        f.close()
        self.configs = result
    

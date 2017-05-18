import socket

class Client():
    def __init__(self, args=None, **kwargs):
        self.IP, self.host = self.get_connection_information()
        self.args = args
        self.kwargs = kwargs

    def get_connection_information(self):
        testIP = "8.8.8.8"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((testIP, 0))
        ipaddr = s.getsockname()[0]
        host = socket.gethostname()
        return ipaddr, host

client = Client()
print(client.IP, client.host)

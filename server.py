import socket
import socketserver


class Server(socketserver.ForkingTCPServer):

    def __init__(self, server_address, RequestHandlerClass):
        socketserver.BaseServer.__init__(self, server_address, RequestHandlerClass)
        if socket.has_dualstack_ipv6():
            self.socket = socket.create_server(server_address, family=socket.AF_INET6, dualstack_ipv6=True)
        else:
            self.socket = socket.create_server(server_address)

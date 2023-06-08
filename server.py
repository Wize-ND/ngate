import os
import socket
import socketserver as s


class Server(s.ForkingTCPServer if hasattr(os, "fork") else s.ThreadingTCPServer):
    def __init__(self, server_address, RequestHandlerClass):
        s.BaseServer.__init__(self, server_address, RequestHandlerClass)
        if socket.has_dualstack_ipv6():
            self.socket = socket.create_server(server_address, family=socket.AF_INET6, dualstack_ipv6=True)
        else:
            self.socket = socket.create_server(server_address)

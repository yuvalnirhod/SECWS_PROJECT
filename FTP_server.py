#!/usr/bin/env python3

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

authorizer = DummyAuthorizer()
authorizer.add_user("fw", "fw", "/home/fw", perm="elradfmw")

handler = FTPHandler
handler.authorizer = authorizer

server = FTPServer(("10.1.2.2", 21), handler)
server.serve_forever()

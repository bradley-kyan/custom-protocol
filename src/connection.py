import socket
import time
import selectors
from selectors import *
import types
from scapy.all import (
    AsyncSniffer,
    StreamSocket,
    sniff,
)

from scapy.layers.inet import IP, TCP, UDP


class socket_server:
    """Create a connection to a given host and port for enabling two way communication."""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.socket = None
        self.sel = selectors.DefaultSelector()
    
    def run_server(self):
        """Run the server to listen for incoming connections."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        print(f"Server listening on {self.host}:{self.port}")

        self.sel.register(self.socket, selectors.EVENT_READ, data=None)

        start_time = int(time.time())
        try:
            while True:
                current_time = int(time.time())
                events = self.sel.select(timeout=1)
                
                for key, mask in events:
                    if key.data is None:
                        self.accept_wrapper(key.fileobj)
                    else:
                        selector_open = True
                        
                        if start_time != current_time:
                            selector_open = self.check_connection_lifetime(key)
                        if selector_open:
                            self.service_connection(key, mask)
                start_time = current_time
                
        except KeyboardInterrupt:
            print("Caught keyboard interrupt, exiting")
        finally:
            self.sel.close()

    def accept_wrapper(self, sock):
        conn, addr = sock.accept()  # Should be ready to read
        print(f"Accepted connection from {addr}")
        conn.setblocking(False)
        data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"", conn_time=int(time.time()))
        events = selectors.EVENT_READ | selectors.EVENT_WRITE
        print(f"Data: {data}")
        self.sel.register(conn, events, data=data)

    def check_connection_lifetime(self, key: SelectorKey) -> bool:
        """Check if the connection has been active for too long."""
        sock = key.fileobj
        data = key.data
        
        if data and int(time.time()) - data.conn_time > 5:
            print(f"Closing connection to {data.addr} as it has been active for too long.")
            self.sel.unregister(sock)
            sock.close()
            return False
                    
        return True
        
    def service_connection(self, key: SelectorKey, mask):
        """Service the connection based on the events."""
        sock = key.fileobj
        data = key.data
        if mask & selectors.EVENT_READ:
            recv_data = sock.recv(1024)  # Should be ready to read
            if recv_data:
                data.outb += recv_data
                data.conn_time = int(time.time())  # Update connection time 
            else:
                print(f"Closing connection to {data.addr}")
                self.sel.unregister(sock)
                sock.close()
        if mask & selectors.EVENT_WRITE:
            if data.outb:
                print(f"Echoing {data.outb!r} to {data.addr}")
                sent = sock.send(data.outb)  # Should be ready to write
                data.outb = data.outb[sent:]
                print(f"Data: {data}")

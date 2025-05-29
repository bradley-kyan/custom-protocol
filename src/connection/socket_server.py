import socket
import time
import selectors
from selectors import *
import types
from src.connection.socket_buffer import socket_buffer
from scapy.all import *


class socket_server:
    """Create a connection to a given host and port for enabling two way communication."""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.socket = None
        self.sel = (
            selectors.PollSelector()
        )  # Using PollSelector for better performance with many connections

    def run_server(self):
        """Run the server to listen for incoming connections."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.host, self.port))
        self.socket.listen()
        print(f"Server listening on {self.host}:{self.port}")

        self.sel.register(self.socket, selectors.EVENT_READ, data=None)

        try:
            while True:
                events = self.sel.select(timeout=None)

                for key, mask in events:
                    if key.data is None:
                        self.accept_connection(key.fileobj)
                    else:
                        selector_open = self.check_connection_lifetime(key)
                        if selector_open:
                            self.service_connection(key, mask)

        except KeyboardInterrupt:
            print("Caught keyboard interrupt, exiting")
        finally:
            self.sel.close()

    def accept_connection(self, sock):
        conn, addr = sock.accept()  # Should be ready to read

        print(f"Accepted connection from {addr}")
        conn.setblocking(False)

        data = types.SimpleNamespace(
            addr=addr, socket_buffer=socket_buffer(), conn_time=int(time.time())
        )

        events = selectors.EVENT_READ | selectors.EVENT_WRITE
        print(f"Data: {data}")
        self.sel.register(conn, events, data=data)

    def check_connection_lifetime(self, key: SelectorKey) -> bool:
        """Check if the connection has been active for too long."""
        sock = key.fileobj
        data = key.data

        if data and int(time.time()) - data.conn_time >= 128:
            print(
                f"Closing connection to {data.addr} as it has been active for too long."
            )
            self.sel.unregister(sock)
            sock.close()
            return False

        return True

    def service_connection(self, key: SelectorKey, mask, protocol):
        """Service the connection based on the events."""
        sock = key.fileobj
        data = key.data

        if mask & selectors.EVENT_READ:
            recv_data = sock.recv(1024)  # Should be ready to read

            if recv_data:
                data.socket_buffer.in_buffer += recv_data
                data.conn_time = int(time.time())  # Update connection time
            else:
                print(f"Closing connection to {data.addr}")
                self.sel.unregister(sock)
                sock.close()

        # The client has finished sending its data so now we can process it
        if mask & selectors.EVENT_WRITE:
            if data.socket_buffer.in_buffer:
                # Need to add logic to process the in_buffer following the protocol specs

                # Write to the out buffer the message response

                sent = sock.send(
                    data.socket_buffer.out_buffer
                )  # Should be ready to write

                # Clear our in_buffer and out_buffer after sending
                data.socket_buffer.in_buffer = data.socket_buffer.in_buffer[sent:]
                data.socket_buffer.out_buffer = data.socket_buffer.out_buffer[sent:]

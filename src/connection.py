import socket


class connection_handler:
    """
    Create a connection to a given host and port for enabling two way communication.
    """

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.socket = None

    def __init__(self, socket: socket.socket):
        self.socket = socket
        self.host = socket.getpeername()[0]
        self.port = socket.getpeername()[1]

    async def start_connection(self):
        """
        Check if the client trying to establish the connection is sending a valid connection packet.
        """

from src.connection.socket_server import socket_server


class connection_handler(socket_server):
    """Handles the connection lifecycle and events for the socket server."""

    def __init__(self, host: str, port: int):
        super().__init__(host, port, verify_function=self.verify_connection)

    def run_server(self):
        """Run the server to listen for incoming connections."""
        super().run_server()  # Call the parent method to set up the server

    def verify_connection(self, conn):
        """Verify the connection and handle authentication."""
        # Placeholder for connection verification logic
        print(f"Verifying connection from {conn.getpeername()}")
        # Here you would typically check credentials or perform TOTP verification
        return True

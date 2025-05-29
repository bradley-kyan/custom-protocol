class socket_buffer:
    """Buffer for incoming and outgoing data in a socket connection."""
    def __init__(self, in_buffer: bytes = b"", out_buffer: bytes = b""):
        self.in_buffer = in_buffer
        self.out_buffer = out_buffer

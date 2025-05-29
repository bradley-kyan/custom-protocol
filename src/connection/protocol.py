import time
import zlib

class totp_protocol:
    """
    Define our protocol with the following properties:
    > Header: WIll contain our type of message:
        > Preable (8 bytes)
            -> Protocol Name - TOTPv1 - 0x54 0x4F 0x54 0x50 0x76 0x31 (6 bytes)
            -> padding (1 bytes)
            
        > MessageType (1 byte)
            1 -> Auth Request - client to server with identifier
            2 -> Auth Challenge - server to client with challenge string (random string)
            3 -> Auth Response - client to server with string encrypted by TOTP code
            4 -> Auth Retry - server to client with retry message since TOTP code was not valid from send time field.
            
            5 -> Auth Success - server to client with success message, include message encrypt key -> client will use this key to encrypt future messages in this session.
                    Also include new shared secret key for future use. Both keys will be encrypted with TOTP code.
            6 -> Auth Update - client respons with new shared secret key, encrypted with TOTP code.
            
            7 -> Auth Failure - server to client with failure message -> secret keys do not change, connection closed.
            
            8 -> Payload - client to server with encrypted data using session key -> server will disconnect if not authenticated

        > Send Time EPOCH Seconds (8 bytes) -> For checking if the totp code are in the correct time window during authentication.
        
        > CRC32 Payload Checksum (4 bytes)
        > Keep Alive (1 byte)
            0x01 -> Keep Alive
            0x00 -> Close Connection
            
        > Payload Length (8 bytes)

            
    > Payload: Will contain the data depending on the type of message.
        -> Auth Request: Client Identifier
        -> Auth Challenge: Random string
        -> Auth Response: Encrypted string
        -> Message Payload: Encrypted data with TOTP code
        
    """
    
    PREAMBLE = b'TOTPv1\x00'  # 8 bytes
    MESSAGE_TYPES = {
        'AUTH_REQUEST': 1,
        'AUTH_CHALLENGE': 2,
        'AUTH_RESPONSE': 3,
        'AUTH_RETRY': 4,
        'AUTH_SUCCESS': 5,
        'AUTH_UPDATE': 6,
        'AUTH_FAILURE': 7,
        'PAYLOAD': 8
    }
    
    EPOCH_SECONDS = 0  # 8 bytes for EPOCH seconds
    
    KEEP_ALIVE = {
        'KEEP_ALIVE': 0x01,
        'CLOSE_CONNECTION': 0x00
    }
    
    def __init__(self):
        pass
    
    @staticmethod
    def create_header(message_type: int, payload_checksum: int, payload_length: int, keep_alive: int) -> bytes:
        """Create the protocol header."""
        header = (
            totp_protocol.PREAMBLE +
            message_type.to_bytes(1, 'big') +
            int(time.time()).to_bytes(8, 'big') +
            payload_checksum.to_bytes(4, 'big') +
            keep_alive.to_bytes(1, 'big') +
            payload_length.to_bytes(8, 'big')
        )
        return header
    
    @staticmethod
    def create_message(message_type: int, payload: bytes) -> bytes:
        """Create a complete message with header and payload."""
        payload_checksum = zlib.crc32(payload)
        keep_alive = totp_protocol.KEEP_ALIVE['KEEP_ALIVE']
        
        header = totp_protocol.create_header(
            message_type=message_type,
            payload_checksum=payload_checksum,
            payload_length=len(payload),
            keep_alive=keep_alive
        )
        
        return header + payload

    
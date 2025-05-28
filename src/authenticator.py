from totp import *

class totp_authenticator(totp_instance):
    """
    Authenticator class that extends the TOTP functionality.
    It can generate a secret and TOTP codes, and also verify them.
    """
    
    def __init__(self, identifier: str = None):
        super().__init__(identifier)
    
    def verify_totp(self, totp_code: str, secret: str, identifier: str) -> bool:
        """
        Verify the provided TOTP code against the generated code using the secret.
        """
        generated_code = self.generate_totp(secret=secret)
        return totp_code == generated_code
from src.totp import *

class totp_authenticator(totp_instance):
    """
    Authenticator class that extends the TOTP functionality.
    It can generate a secret and TOTP codes, and also verify them.
    """
    
    def __init__(self, identifier: str = None, secret: str = None):
        super().__init__(identifier=identifier, secret=secret)
    
    def verify_totp(self, totp_code: str, secret: str, identifier: str) -> bool:
        """
        Verify the provided TOTP code against the generated code using the secret.
        """
        generated_code = self.generate_totp(secret=secret)
        return totp_code == generated_code
    
class totp_auth_factory():
    """
    Factory for creating and managing TOTP instances.
    """
    
    def __init__(self, totp_storeage_filename: str = None):
        self.storage = totp_storage(totp_storeage_filename)
        
        
    def create_totp_instance(self, identifier: str) -> totp_authenticator:
        """
        Create a new TOTP instance for the given identifier.
        If an instance already exists, return the existing one.
        """
        totp_auth = totp_authenticator(identifier=identifier)
        
        created = self.storage.save_totp(totp_instance=totp_auth)
        if not created:
            print(f"TOTP instance already exists for identifier: {identifier}. Not creating a new one.")
            return self.get_totp_authenticator(identifier)
        
        self.storage.save_to_disk()
        return totp_auth
    
    
    def update_totp_instance(self, identifier: str, secret: str) -> totp_authenticator:
        """
        Update an existing TOTP instance with a new secret.
        If the instance does not exist, create a new one.
        """
        
        totp_authenticator = self.get_totp_authenticator(identifier)
        
        if totp_authenticator is None:
            print(f"No TOTP instance found for identifier: {identifier}. Creating a new one.")
            totp_authenticator = self.create_totp_instance(identifier)
        
        totp_authenticator.secret = secret
        self.storage.update_totp(totp_instance=totp_authenticator)
        self.storage.save_to_disk()
        
        return totp_authenticator
    
    
    def get_totp_authenticator(self, identifier: str) -> totp_authenticator:
        """
        Retrieve an existing TOTP instance by identifier.
        """
        
        secret = self.storage.restore_backup(identifier)
        
        if secret is None:
            print(f"No TOTP instance found for identifier: {identifier}")
            return None
        
        return totp_authenticator(identifier=identifier, secret=secret)
    
import random
import time
import hmac

class totp:  
    def generate_secret(self):
        """
        Generate a random secret key for TOTP.
        The secret is a base32 encoded string.
        """
        
        self.secret = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', k=64))
        return self.secret
    
    def generate_totp(self, secret: str, byte_len: int = 32, digits: int = 64):
        """
        Implement HOTP (HMAC-based One-Time Password) algorithm to generate a TOTP code.
        """
        time_step = 30 # TOTP time step in seconds
        
        counter = int(time.time()) / time_step
        counter_bytes = int(counter).to_bytes(8, 'big')
        
        hmac_key = hmac.new(secret.encode(), counter_bytes, "sha512")
        hmac_digest = hmac_key.digest()
        
        # Get our offset from the last byte of the HMAC digest
        offset = hmac_digest[-1] & 0x0F
        if offset + byte_len > len(hmac_digest):
            raise ValueError("Truncation length exceeds digest bounds")

        truncated_hash = 0
        for i in range(byte_len):
            truncated_hash = (truncated_hash << 8) | (hmac_digest[offset + i] & 0xFF)
        
        totp_code = truncated_hash % int(10.0 ** digits)
        return str(totp_code)
    
class totp_instance(totp):
    def __init__(self, identifier: str, secret: str = None):
        self.identifier = identifier
        self.secret = secret
        
        if not self.secret:
            self.secret = self.generate_secret()
        
    def generate_secret(self):
        self.secret = super().generate_secret()
    
    def generate_totp(self):
        if not self.secret:
            raise ValueError("Secret not generated. Call generate_secret() first.")
        return super().generate_totp(secret=self.secret)
    
    
class totp_storage:
    """
    Save and restore generated TOTP secrets and codes.
    """   
    def __init__(self, backup_file: str = None):
        self.instances = {}
        self.backup_file = backup_file if backup_file else "totp_backup.txt"
    
    def save_totp(self, totp_instance: totp_instance):
        """
        Save the TOTP secret for a given identifier.
        """
        self.instances[totp_instance.identifier] = totp_instance.secret
    
    def restore_backup(self, identifier: str) -> str:
        """
        Restore the TOTP secret for a given identifier.
        """
        return self.instances.get(identifier, None)
    
    def save_to_disk(self):
        """
        Save the instances to a file.
        """
        with open(self.backup_file, 'w') as f:
            for identifier, secret in self.instances.items():
                f.write(f"{identifier}:{secret}\n")
                
    def load_from_disk(self):
        """
        Load the instances from a file.
        """
        try:
            with open(self.backup_file, 'r') as f:
                for line in f:
                    identifier, secret = line.strip().split(':')
                    self.instances[identifier] = secret
        except FileNotFoundError:
            print(f"Backup file {self.backup_file} not found.")
        except Exception as e:
            print(f"An error occurred while loading backup: {e}")
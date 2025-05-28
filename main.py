from src.totp import (
    totp_instance as totpi,
    totp_storage as totps   
)
import time

totp_instance = totpi("connection_1", "JFAYYXHEMEIMMATA2TCN4EFC5H3WJP2QF4RAQVOHLVFV2TL5WX7WUCRZABJCIPIB")
totp_storage = totps(backup_file="totp_backup.txt")

totp_storage.save_totp(totp_instance)
totp_storage.save_to_disk()

def run_totp_cycle():
    while True:
        totp_code = totp_instance.generate_totp()
        print(f"Current TOTP Code: {totp_code}")
        time.sleep(10)
        
run_totp_cycle()
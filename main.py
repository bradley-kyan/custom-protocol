import time
import asyncio
from scapy.all import *
from src.connection.connection_handler import connection_handler as conn

from src.authenticator import (
    totp_auth_factory as totp_factory,
)

totp_auth_factory = totp_factory(totp_storeage_filename="totp_backup.txt")

example_auth = totp_auth_factory.create_totp_instance(identifier="example_user")


# def run_totp_cycle():
#     while True:
#         print("Generating TOTP code...")
#         totp_code = example_auth.generate_totp()
#         print(f"TOTP Code: {totp_code}")

#         time.sleep(10)


# run_totp_cycle()

server = conn(host="127.0.0.1", port=45425)


def run_server():
    server.run_server()
    print("Server is running and waiting for connections...")


run_server()

while True:
    pass

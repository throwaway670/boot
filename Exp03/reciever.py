import socket
import threading
import json
import os
from utils import rsa_keygen, rsa_decrypt_to_bytes, sym_decrypt, pubkey_to_dict


TP_HOST = '10.10.113.175'
TP_PORT = 4444
RECV_HOST = '10.10.119.228'
RECV_PORT = 3333


NAME = None
PUBKEY = None
PRIVKEY = None


def tp_request(payload: dict) -> dict:
   with socket.create_connection((TP_HOST, TP_PORT)) as c:
       c.sendall((json.dumps(payload) + "\n").encode('utf-8'))
       return json.loads(c.recv(1_000_000).decode('utf-8'))


def register(name: str):
   global NAME, PUBKEY, PRIVKEY
   PUBKEY, PRIVKEY = rsa_keygen(1024)
   NAME = name
   print(f"[Receiver] Generated PUBLIC KEY: {PUBKEY}")
   print(f"[Receiver] Generated PRIVATE KEY: {PRIVKEY}")
   res = tp_request({
       "action": "REGISTER",
       "name": NAME,
       "pubkey": pubkey_to_dict(PUBKEY)
   })
   print("[Receiver] Registration response:", res)


def handle_incoming(conn, addr):
   try:
       data = conn.recv(1_000_000)
       if not data:
           return
       pkt = json.loads(data.decode('utf-8'))
       enc_key_int = int(pkt['enc_key'])
       ciphertext = bytes.fromhex(pkt['ciphertext'])


       print(f"[Receiver] Encrypted symmetric key (RSA-wrapped): {enc_key_int}")
       print(f"[Receiver] Encrypted message (hex): {pkt['ciphertext']}")
       # print(f"[Receiver] PUBLIC KEY: {PUBKEY}")
       # print(f"[Receiver] PRIVATE KEY: {PRIVKEY}")


       key = rsa_decrypt_to_bytes(PRIVKEY, enc_key_int) # type: ignore
       message = sym_decrypt(key, ciphertext).decode('utf-8', errors='replace')


       print(f"[Receiver] Decrypted symmetric key: {key.hex()}")
       print(f"[Receiver] Decrypted MESSAGE: {message}")
   except Exception as e:
       print("[Receiver Error]", e)
   finally:
       conn.close()


def listener():
   print(f"[Receiver] Listening on {RECV_HOST}:{RECV_PORT}")
   with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
       s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
       s.bind((RECV_HOST, RECV_PORT))
       s.listen()
       while True:
           conn, addr = s.accept()
           threading.Thread(target=handle_incoming, args=(conn, addr), daemon=True).start()


def main():
   threading.Thread(target=listener, daemon=True).start()
   while True:
       print("\n=== Receiver Menu ===")
       print("1) Register my public key with Third Party")
       print("2) Exit")
       choice = input("> ").strip()
       if choice == '1':
           name = input("Enter your identity (e.g., bob): ").strip()
           register(name)
       elif choice == '2':
           print("Bye.")
           os._exit(0)
       else:
           print("Invalid option.")


if __name__ == '__main__':
   main()

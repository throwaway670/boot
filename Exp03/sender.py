import socket
import json
import os
from utils import rsa_keygen, rsa_encrypt_bytes, sym_encrypt, pubkey_to_dict, dict_to_pubkey


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
   print(f"[Sender] Generated PUBLIC KEY: {PUBKEY}")
   print(f"[Sender] Generated PRIVATE KEY: {PRIVKEY}")
   res = tp_request({
       "action": "REGISTER",
       "name": NAME,
       "pubkey": pubkey_to_dict(PUBKEY)
   })
   print("[Sender] Registration response from Third Party:", res)


def get_pubkey(identity: str):
   res = tp_request({"action": "GET_KEY", "name": identity})
   if not res.get('ok'):
       raise RuntimeError("Third Party: " + res.get('error', 'unknown error'))
   return dict_to_pubkey(res['pubkey'])


def send_message(to_identity: str, message: str):
   recv_pub = get_pubkey(to_identity)
   #print(f"[Sender] Receiver PUBLIC KEY (from Third Party): {recv_pub}")


   sym_key = os.urandom(32)
   enc_key_int = rsa_encrypt_bytes(recv_pub, sym_key)
   ciphertext = sym_encrypt(sym_key, message.encode('utf-8')).hex()


   print(f"[Sender] Symmetric KEY (random): {sym_key.hex()}")
  # print(f"[Sender] Encrypted symmetric key (RSA-wrapped): {enc_key_int}")
   print(f"[Sender] Encrypted MESSAGE (hex): {ciphertext}")


   pkt = {
       "from": NAME,
       "enc_key": str(enc_key_int),
       "ciphertext": ciphertext
   }


   with socket.create_connection((RECV_HOST, RECV_PORT)) as c:
       c.sendall(json.dumps(pkt).encode('utf-8'))


   print("[Sender] Message sent successfully.")


def menu():
   while True:
       print("\n=== Sender Menu ===")
       print("1) Register my public key with Third Party")
       print("2) Send message")
       print("3) Exit")
       choice = input("> ").strip()
       if choice == '1':
           name = input("Enter your identity (e.g., alice): ").strip()
           register(name)
       elif choice == '2':
           to_identity = input("Send to identity (e.g., bob): ").strip()
           msg = input("Enter message: ").strip()
           try:
               send_message(to_identity, msg)
           except Exception as e:
               print("[Error]", e)
       elif choice == '3':
           print("Bye.")
           break
       else:
           print("Invalid option.")


if __name__ == '__main__':
   menu()

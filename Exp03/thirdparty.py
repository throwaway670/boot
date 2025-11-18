import socket
import threading
import json


REGISTRY = {}  # name -> {n: str, e: int}
HOST = '0.0.0.0'
PORT = 4444


def handle(conn, addr):
   try:
       data = conn.recv(1_000_000).decode('utf-8').strip()
       if not data:
           return
       req = json.loads(data)
       action = req.get('action')


       if action == 'REGISTER':
           name = req['name']
           pub = req['pubkey']
           REGISTRY[name] = pub
           print(f"[Third Party] Registered: {name}")
           print(f"[Third Party] PUBLIC KEY stored: {pub}")
           res = {"ok": True, "msg": f"Registered {name}"}


       elif action == 'GET_KEY':
           target = req['name']
           pub = REGISTRY.get(target)
           if pub:
               print(f"[Third Party] Sending PUBLIC KEY for {target}: {pub}")
               res = {"ok": True, "pubkey": pub}
           else:
               print(f"[Third Party] PUBLIC KEY not found for {target}")
               res = {"ok": False, "error": "Not found"}
       else:
           res = {"ok": False, "error": "Unknown action"}


       conn.sendall((json.dumps(res) + "\n").encode('utf-8'))
   except Exception as e:
       print("[Third Party Error]", e)
   finally:
       conn.close()


def main():
   print(f"[ThirdParty] Listening on {HOST}:{PORT}")
   with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
       s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
       s.bind((HOST, PORT))
       s.listen()
       while True:
           conn, addr = s.accept()
           threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == '__main__':
   main()

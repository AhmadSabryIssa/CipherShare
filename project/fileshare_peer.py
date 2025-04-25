#!/usr/bin/env python3
import socket, threading, sys, os, pathlib, json
from pathlib import Path
from crypto_utils import hash_password, verify_password

CHUNK = 64 * 1024
HOST  = "0.0.0.0"
SHARE_DIR = Path("shared"); SHARE_DIR.mkdir(exist_ok=True)
USER_FILE = Path("users.json")

class FileSharePeer:
    def __init__(self, port: int):
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.users = self._load_users()
        self.shared = {}
        self.sessions = {}  # {conn: username}

    def _load_users(self):
        if USER_FILE.exists():
            with USER_FILE.open("r") as f:
                return json.load(f)
        return {}

    def _save_users(self):
        with USER_FILE.open("w") as f:
            json.dump(self.users, f)

    def start_peer(self):
        self.sock.bind((HOST, self.port)); self.sock.listen(5)
        print(f"[PEER] listening on {HOST}:{self.port}")
        while True:
            c, a = self.sock.accept()
            threading.Thread(target=self._handle, args=(c, a), daemon=True).start()

    def _handle(self, conn, addr):
        with conn:
            try:
                self.sessions[conn] = None
                while True:
                    cmd = self._readline(conn)
                    if cmd is None: break
                    parts = cmd.split()
                    if not parts: continue
                    match parts[0].upper():
                        case "REGISTER": self._register(conn, parts)
                        case "LOGIN":    self._login(conn, parts)
                        case "LIST":     self._list(conn)
                        case "UPLOAD":   self._upload(conn, parts)
                        case "DOWNLOAD": self._download(conn, parts)
                        case "LISTFILES":self._listfiles(conn)
                        case "GET":      self._sendfile(conn, parts)
                        case _:           conn.sendall(b"ERR unknown\n")
            except Exception as e:
                print(f"[PEER] {addr} error: {e}")
            finally:
                self.sessions.pop(conn, None)

    @staticmethod
    def _readline(sock):
        buf = bytearray()
        while (b := sock.recv(1)):
            if b == b'\n': return buf.decode().strip()
            buf.extend(b)
        return None

    def _register(self, c, p):
        if len(p)!=3: c.sendall(b"ERR format\n"); return
        u, pw = p[1], p[2]
        if u in self.users: c.sendall(b"ERR exists\n"); return
        h, s = hash_password(pw)
        self.users[u] = [h.hex(), s.hex()]
        self._save_users()
        c.sendall(b"OK registered\n")

    def _login(self, c, p):
        if len(p)!=3: c.sendall(b"ERR format\n"); return
        u, pw = p[1], p[2]
        if u not in self.users: c.sendall(b"ERR no_user\n"); return
        h, s = bytes.fromhex(self.users[u][0]), bytes.fromhex(self.users[u][1])
        if verify_password(pw, h, s):
            self.sessions[c] = u
            c.sendall(b"OK welcome\n")
        else:
            c.sendall(b"ERR bad_pwd\n")

    def _check_login(self, c):
        if self.sessions.get(c): return True
        c.sendall(b"ERR login_required\n"); return False

    def _list(self, c):
        if not self._check_login(c): return
        c.sendall(("OK " + " ".join(self.shared.keys()) + "\n").encode())

    def _upload(self, c, p):
        if not self._check_login(c): return
        if len(p)!=3: c.sendall(b"ERR format\n"); return
        name, size = p[1], int(p[2])
        dest = SHARE_DIR / name
        left = size
        with dest.open("wb") as f:
            while left:
                chunk = c.recv(min(CHUNK, left))
                if not chunk: raise IOError("lost conn")
                f.write(chunk); left -= len(chunk)
        self.shared[name] = dest.resolve()
        c.sendall(b"OK stored\n")

    def _download(self, c, p):
        if not self._check_login(c): return
        if len(p)!=2: c.sendall(b"ERR format\n"); return
        name = p[1]; path = self.shared.get(name)
        if not path or not path.exists(): c.sendall(b"ERR no_file\n"); return
        size = path.stat().st_size
        c.sendall(f"OK {size}\n".encode())
        with path.open("rb") as f:
            while (chunk := f.read(CHUNK)): c.sendall(chunk)

    def _listfiles(self, c):
        c.sendall(("OK " + " ".join(self.shared.keys()) + "\n").encode())

    def _sendfile(self, c, p):
        if len(p)!=2: c.sendall(b"ERR format\n"); return
        name = p[1]; path = self.shared.get(name)
        if not path or not path.exists(): c.sendall(b"ERR no_file\n"); return
        size = path.stat().st_size
        c.sendall(f"OK {size}\n".encode())
        with path.open("rb") as f:
            while (chunk := f.read(CHUNK)): c.sendall(chunk)

if __name__=="__main__":
    if len(sys.argv)!=2:
        print("Use: python fileshare_peer.py <port>"); sys.exit(1)
    FileSharePeer(int(sys.argv[1])).start_peer()




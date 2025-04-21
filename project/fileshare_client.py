#!/usr/bin/env python3
import socket, shlex, sys, os, pathlib, time
from pathlib import Path

sys.path.insert(0, os.path.dirname(pathlib.Path(__file__).resolve()))
CHUNK = 64 * 1024
DOWNLOAD_DIR = Path("downloads"); DOWNLOAD_DIR.mkdir(exist_ok=True)

class FileShareClient:
    def __init__(self):
        self.sock: socket.socket | None = None

    # -------- low‑level --------
    @staticmethod
    def _readline(sock):
        data = bytearray()
        while (b := sock.recv(1)):
            if b==b'\n': return data.decode().strip()
            data.extend(b)
        raise IOError("connection closed")

    # -------- session‑based ----
    def connect_to_peer(self, host, port):
        self.sock = socket.create_connection((host, port))
        print(f"[CLIENT] connected to {host}:{port}")

    def register_user(self, u, pw):
        self.sock.sendall(f"REGISTER {u} {pw}\n".encode()); print(self._readline(self.sock))

    def login_user(self, u, pw):
        self.sock.sendall(f"LOGIN {u} {pw}\n".encode()); print(self._readline(self.sock))

    def list_shared_files(self):
        self.sock.sendall(b"LIST\n"); r=self._readline(self.sock); print("Files:", r[3:].strip() or "(none)")

    def upload_file(self, path: Path):
        if not path.is_file(): print("Not a file"); return
        size=path.stat().st_size
        self.sock.sendall(f"UPLOAD {path.name} {size}\n".encode())
        with path.open("rb") as f:
            while (chunk:=f.read(CHUNK)): self.sock.sendall(chunk)
        print(self._readline(self.sock))

    def download_file(self, name):
        self.sock.sendall(f"DOWNLOAD {name}\n".encode())
        r=self._readline(self.sock)
        if not r.startswith("OK"): print(r); return
        size=int(r.split()[1]); dest=DOWNLOAD_DIR/name
        with dest.open("wb") as f:
            left=size
            while left:
                chunk=self.sock.recv(min(CHUNK,left)); f.write(chunk); left-=len(chunk)
        print(f"Saved to {dest.resolve()} ({size} bytes)")

    # -------- stateless helpers ----
    def list_from_peer(self, host, port):
        with socket.create_connection((host, port)) as s:
            s.sendall(b"LISTFILES\n"); r=self._readline(s)
            print(r[3:].strip() if r.startswith("OK") else r or "(none)")

    def download_from_peer(self, host, port, name):
        with socket.create_connection((host, port)) as s:
            s.sendall(f"GET {name}\n".encode()); r=self._readline(s)
            if not r.startswith("OK"): print(r); return
            size=int(r.split()[1]); dest=DOWNLOAD_DIR/name; left=size
            with dest.open("wb") as f:
                while left:
                    chunk=s.recv(min(CHUNK,left)); f.write(chunk); left-=len(chunk)
            print(f"Saved to {dest.resolve()} ({size} bytes)")

    def share_to_peer(self, host, port, path: Path):
        if not path.is_file(): print("Not a file"); return
        size=path.stat().st_size
        with socket.create_connection((host, port)) as s:
            s.sendall(f"UPLOAD {path.name} {size}\n".encode())
            with path.open("rb") as f:
                while (chunk:=f.read(CHUNK)): s.sendall(chunk)
            print(self._readline(s))

    # -------- live polling --------
    def watch_peer(self, host, port, interval=5):
        known=set()
        print(f"Watching {host}:{port} every {interval}s – Ctrl‑C to stop")
        try:
            while True:
                try:
                    with socket.create_connection((host, port), timeout=3) as s:
                        s.sendall(b"LISTFILES\n")
                        r=self._readline(s)
                        if r.startswith("OK"):
                            current=set(r[3:].strip().split()) if r[3:].strip() else set()
                            for f in current-known: print(f"[NEW] {f}")
                            known=current
                except Exception: pass
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\nStopped watching.")

# -------- interactive shell --------
def main():
    cli=FileShareClient()
    while True:
        try: line=input("p2p> ")
        except (EOFError,KeyboardInterrupt): print(); break
        parts=shlex.split(line,posix=False);  # keep Windows paths intact
        if not parts: continue
        cmd,*a=parts
        if cmd=="quit": break
        try:
            match cmd:
                case "connect":  cli.connect_to_peer(a[0],int(a[1]))
                case "register": cli.register_user(*a)
                case "login":    cli.login_user(*a)
                case "list":     cli.list_shared_files()
                case "upload"|"share": cli.upload_file(Path(a[0]))
                case "download": cli.download_file(a[0])
                case "peerlist": cli.list_from_peer(a[0],int(a[1]))
                case "peerdl":   cli.download_from_peer(a[0],int(a[1]),a[2])
                case "shareto":  cli.share_to_peer(a[0],int(a[1]),Path(a[2]))
                case "watchpeer":cli.watch_peer(a[0],int(a[1]))
                case _:          print("commands: connect, register, login, list, share, shareto, download, peerlist, peerdl, watchpeer, quit")
        except Exception as e:
            print("error:", e)

if __name__=="__main__": main()

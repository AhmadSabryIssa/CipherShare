import socket, threading, sys, json
from pathlib import Path
import time
from crypto_utils import (
    hash_password,
    verify_password,
    load_access_requests,
    save_access_requests,
)

CHUNK = 64 * 1024
HOST = "0.0.0.0"
PEER_TIMEOUT = 20
SHARE_DIR = Path("shared"); SHARE_DIR.mkdir(exist_ok=True)
USER_FILE = Path("users.json")

class FileSharePeer:
    def __init__(self, port: int):
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.users = self._load_users()
        self.shared = {}
        self.sessions = {}
        self.pending_login = {}

    def _load_users(self):
        return json.loads(USER_FILE.read_text()) if USER_FILE.exists() else {}

    def _save_users(self):
        USER_FILE.write_text(json.dumps(self.users))

    def _readline(self, sock):
        buf = bytearray()
        while (b := sock.recv(1)):
            if b == b"\n":
                return buf.decode().strip()
            buf.extend(b)
        return None

    def _notify(self, msg: str):
        print(f"[NOTIFY] {msg}", flush=True)

    def _send_to_user(self, user: str, text: str):
        for conn, u in list(self.sessions.items()):
            if u == user:
                try:
                    conn.sendall(f"NOTICE {text}\n".encode())
                except OSError:
                    pass

    def _is_forwarded_download(self, conn):
        try:
            peer_ip, _ = conn.getpeername()
            return peer_ip.startswith("127.") or peer_ip == "localhost"
        except:
            return False

    def start_peer(self):
        self.sock.bind((HOST, self.port))
        self.sock.listen(5)
        print(f"[PEER] listening on {HOST}:{self.port}")
        while True:
            conn, addr = self.sock.accept()
            threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()

    def _handle(self, conn, addr):
        with conn:
            try:
                self.sessions[conn] = None
                while True:
                    line = self._readline(conn)
                    if not line:
                        break
                    parts = line.split()
                    if not parts:
                        continue
                    cmd = parts[0].upper()
                    if cmd == "REGISTER":        self._register(conn, parts)
                    elif cmd == "LOGIN":         self._login_user(conn, parts)
                    elif cmd == "PASS":          self._login_pass(conn, parts)
                    elif cmd == "LIST":          self._list(conn)
                    elif cmd == "UPLOAD":        self._upload(conn, parts)
                    elif cmd == "DOWNLOAD":      self._download(conn, parts, addr)
                    elif cmd == "REQUEST_REMOTE":self._remote_request(conn, parts)
                    elif cmd == "GRANT":         self._grant_access(conn, parts)
                    elif cmd == "PROXY_REQUEST": self._proxy_request(parts, addr)
                    elif cmd == "PROXY_NOTICE":  self._proxy_notice(parts)
                    elif cmd == "PEERLIST":      self._peerlist(conn)
                    else: conn.sendall(b"ERR unknown\n")
            finally:
                self.sessions.pop(conn, None)
                self.pending_login.pop(conn, None)

    def _check_login(self, conn):
        return bool(self.sessions.get(conn))

    def _register(self, conn, p):
        if len(p) != 3:
            return conn.sendall(b"ERR format\n")
        user, pw = p[1], p[2]
        if user in self.users:
            return conn.sendall(b"ERR exists\n")
        h, s = hash_password(pw)
        self.users[user] = [h.hex(), s.hex()]
        self._save_users()
        conn.sendall(b"OK registered\n")

    def _login_user(self, conn, p):
        if len(p) != 2:
            return conn.sendall(b"ERR format\n")
        user = p[1]
        if user not in self.users:
            return conn.sendall(b"ERR no_user\n")
        self.pending_login[conn] = user
        conn.sendall(b"OK password_required\n")

    def _login_pass(self, conn, p):
        if len(p) != 2:
            return conn.sendall(b"ERR format\n")
        user = self.pending_login.get(conn)
        if not user:
            return conn.sendall(b"ERR login_step\n")
        h, s = self.users[user]
        if verify_password(p[1], bytes.fromhex(h), bytes.fromhex(s)):
            self.sessions[conn] = user
            del self.pending_login[conn]
            conn.sendall(b"OK welcome\n")
        else:
            conn.sendall(b"ERR bad_pwd\n")

    def _list(self, conn):
        if not self._check_login(conn):
            return conn.sendall(b"ERR login_required\n")
        user = self.sessions[conn]
        acc = load_access_requests()
        visible = []

        for fname, meta in self.shared.items():
            if meta["owner"] == user:
                visible.append(fname)

        for fname in acc.get("grant", {}):
            if user in acc["grant"][fname]:
                visible.append(fname)

        conn.sendall(f"OK {' '.join(visible)}\n".encode())

    def _upload(self, conn, p):
        if not self._check_login(conn):
            return conn.sendall(b"ERR login_required\n")
        if len(p) != 3:
            return conn.sendall(b"ERR format\n")
        fname, size = p[1], int(p[2])
        dest = SHARE_DIR / fname
        with open(dest, "wb") as f:
            left = size
            while left:
                chunk = conn.recv(min(CHUNK, left))
                if not chunk:
                    break
                f.write(chunk)
                left -= len(chunk)
        self.shared[fname] = {"path": str(dest.resolve()), "owner": self.sessions[conn]}
        conn.sendall(b"OK stored\n")

    def _download(self, conn, p, addr):
        if not self._check_login(conn) and not self._is_forwarded_download(conn):
            return conn.sendall(b"ERR login_required\n")
        if len(p) != 2:
            return conn.sendall(b"ERR format\n")

        fname = p[1]
        meta = self.shared.get(fname)
        user = self.sessions.get(conn, "unknown")
        peer_ip = addr[0]
        acc = load_access_requests()

        if meta:
            try:
                with open(meta["path"], "rb") as file:
                    data = file.read()
                    conn.sendall(f"OK {len(data)}\n".encode())
                    conn.sendall(data)
            except Exception as e:
                return conn.sendall(f"ERR file_read_failed {e}\n".encode())
        elif fname in acc.get("grant", {}) and user in acc["grant"][fname]:
            rec = acc["grant"][fname][user]
            ip, port = rec["ip"], rec["port"]
            try:
                with socket.create_connection((ip, port), timeout=20) as s:
                    s.sendall(f"DOWNLOAD {fname}\n".encode())
                    header = b""
                    while not header.endswith(b"\n"):
                        chunk = s.recv(1)
                        if not chunk:
                            raise IOError("Connection closed during header read")
                        header += chunk
                    head = header.decode().strip()
                    if not head.startswith("OK "):
                        return conn.sendall(head.encode())
                    size = int(head.split()[1])
                    data = bytearray()
                    while len(data) < size:
                        data.extend(s.recv(min(CHUNK, size - len(data))))
                    conn.sendall(f"OK {len(data)}\n".encode())
                    conn.sendall(data)
            except Exception as e:
                conn.sendall(f"ERR remote_fail {e}\n".encode())
        else:
            conn.sendall(b"ERR no_file\n")

    def _remote_request(self, conn, p):
        if not self._check_login(conn):
            return conn.sendall(b"ERR login_required\n")
        if len(p) != 5:
            return conn.sendall(b"ERR format\n")

        fname, host, port_s, owner = p[1:]
        requester = self.sessions[conn]
        acc = load_access_requests()
        if fname in acc.get("grant", {}) and requester in acc["grant"][fname]:
            return conn.sendall(b"OK already_granted\n")
        try:
            with socket.create_connection((host, int(port_s)), timeout=PEER_TIMEOUT) as s:
                s.sendall(f"PROXY_REQUEST {fname} {requester} {self.port}\n".encode())
                _ = s.recv(32)
        except Exception as e:
            pass
        time.sleep(10)
        conn.sendall(b"ready\n")

    def _proxy_request(self, p, addr):
        if len(p) != 4:
            return
        fname, requester, prt = p[1], p[2], int(p[3])
        ip = addr[0]
        acc = load_access_requests()
        acc.setdefault("request", {}).setdefault(fname, {})[requester] = {
            "ip": ip,
            "port": prt
        }
        save_access_requests(acc)
        owner = self.shared.get(fname, {}).get("owner")
        if owner:
            msg = f"user '{requester}' requested '{fname}' from you ({ip}:{prt})"
            self._notify(msg)
            self._send_to_user(owner, msg)

    def _proxy_notice(self, p):
        if len(p) < 3:
            return
        target = p[1]
        msg = " ".join(p[2:])
        self._send_to_user(target, msg)

    def _grant_access(self, conn, p):
        if not self._check_login(conn):
            return conn.sendall(b"ERR login_required\n")
        if len(p) != 3:
            return conn.sendall(b"ERR format\n")
        fname, requester = p[1], p[2]
        acc = load_access_requests()
        if "request" not in acc or fname not in acc["request"] or requester not in acc["request"][fname]:
            return conn.sendall(b"ERR no_request_found\n")
        acc.setdefault("grant", {}).setdefault(fname, {})[requester] = {
            "ip": "127.0.0.1",
            "port": self.port
        }
        bob_info = acc["request"][fname][requester]
        del acc["request"][fname][requester]
        if not acc["request"][fname]:
            del acc["request"][fname]
        save_access_requests(acc)
        conn.sendall(b"OK granted\n")
        try:
            with socket.create_connection((bob_info["ip"], bob_info["port"]), timeout=20) as s:
                s.sendall(f"PROXY_NOTICE {requester} your request for '{fname}' has been granted\n".encode())
        except Exception as e:
            print(f"[DEBUG] Failed to notify {requester} at {bob_info['ip']}:{bob_info['port']} — {e}")
            pass

    def _peerlist(self, conn):
        if not self._check_login(conn):
            return conn.sendall(b"ERR login_required\n")
        conn.sendall(f"OK {' '.join(self.shared.keys())}\n".encode())

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python fileshare_peer.py <port>")
        sys.exit(1)
    FileSharePeer(int(sys.argv[1])).start_peer()

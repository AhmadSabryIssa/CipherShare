import socket, shlex, sys, getpass, threading, queue, select, json, time
from pathlib import Path
from crypto_utils import encrypt_file, decrypt_file

CHUNK        = 64 * 1024
DOWNLOAD_DIR = Path("downloads"); DOWNLOAD_DIR.mkdir(exist_ok=True)

class FileShareClient:
    def __init__(self):
        self.sock      = None
        self.username  = None
        self._resp_q   = queue.Queue()
        self._closed   = threading.Event()
        self._busy     = threading.Lock()

    def _readline_raw(self):
        buf = bytearray()
        while True:
            b = self.sock.recv(1)
            if not b:
                raise IOError("socket closed")
            if b == b"\n":
                return buf.decode().strip()
            buf.extend(b)

    def _reader(self):
        buf = bytearray()
        while not self._closed.is_set():
            if not self._busy.acquire(blocking=False):
                time.sleep(0.02); continue
            try:
                r,_,_ = select.select([self.sock], [], [], 0.1)
                if not r:
                    continue
                b = self.sock.recv(1)
            except OSError:
                break
            finally:
                self._busy.release()
            if not b:
                break
            if b == b"\n":
                line = buf.decode().strip(); buf.clear()
                if line.startswith("NOTICE "):
                    print(f"\n[NOTIFY] {line[7:]}")
                    print("p2p> ", end="", flush=True)
                else:
                    self._resp_q.put(line)
            else:
                buf.extend(b)
        self._closed.set()

    def _resp(self):
        if self._closed.is_set(): raise IOError("connection closed")
        return self._resp_q.get()

    def connect(self, host, port):
        if self.sock:
            self._closed.set(); self.sock.close()
        self.sock = socket.create_connection((host, port))
        print(f"[CLIENT] connected to {host}:{port}")
        self._closed.clear()
        threading.Thread(target=self._reader, daemon=True).start()

    def register(self):
        if not self.sock: return print("[CLIENT] connect first")
        u = input("Username: "); p = getpass.getpass("Password: ")
        self.sock.sendall(f"REGISTER {u} {p}\n".encode())
        print("[CLIENT]", self._resp())

    def login(self):
        if not self.sock: return print("[CLIENT] connect first")
        u = input("Username: "); self.sock.sendall(f"LOGIN {u}\n".encode())
        if not self._resp().startswith("OK"):
            return
        p = getpass.getpass("Password: ")
        self.sock.sendall(f"PASS {p}\n".encode())
        print("[CLIENT]", self._resp())
        self.username = u

    def list(self):
        if not self.sock: return print("[CLIENT] connect first")
        self.sock.sendall(b"LIST\n")
        print("[CLIENT] files:", self._resp()[3:] or "(none)")

    def upload(self, path: Path):
        if not self.sock: return print("[CLIENT] connect first")
        if not path.is_file(): return print("[CLIENT] not a file")
        nonce, blob = encrypt_file(path.read_bytes())
        payload = nonce + blob
        with self._busy:
            self.sock.sendall(f"UPLOAD {path.name} {len(payload)}\n".encode())
            self.sock.sendall(payload)
            reply = self._readline_raw()
        print("[CLIENT]", reply)

    def download(self, name):
        if not self.sock:
            return print("[CLIENT] connect first")
        if not self.username:
            return print("[CLIENT] ERR login_required")

        with self._busy:
            self.sock.sendall(f"DOWNLOAD {name}\n".encode())
            head = self._readline_raw()
            if head.startswith("OK "):
                size = int(head.split()[1])
                data = bytearray()
                while len(data) < size:
                    data.extend(self.sock.recv(min(CHUNK, size - len(data))))
            elif "no_file" in head:
                try:
                    with open("access_requests.json", "r") as f:
                        access = json.load(f)
                    rec = access.get("grant", {}).get(name, {}).get(self.username)
                    if not rec:
                        return print("[CLIENT] ERR not granted access")
                    ip, port = rec["ip"], rec["port"]
                    print(f"[CLIENT] Fetching from remote peer at {ip}:{port}")
                    with socket.create_connection((ip, port), timeout=10) as s:
                        s.sendall(f"DOWNLOAD {name}\n".encode())

                        header = b""
                        while not header.endswith(b"\n"):
                            chunk = s.recv(1)
                            if not chunk:
                                raise IOError("Connection closed during header read")
                            header += chunk

                        header = header.decode().strip()
                        if not header.startswith("OK "):
                            return print("[CLIENT]", header)

                        size = int(header.split()[1])
                        data = bytearray()
                        while len(data) < size:
                            chunk = s.recv(min(CHUNK, size - len(data)))
                            if not chunk:
                                break
                            data.extend(chunk)
                except Exception as e:
                    return print(f"[CLIENT ERROR] failed remote fetch: {e}")
            else:
                return print("[CLIENT]", head)

        # Try decrypting (AES-GCM), or fallback to plaintext
        try:
            nonce, blob = data[:12], data[12:]
            plain = decrypt_file(nonce, blob)
            (DOWNLOAD_DIR / name).write_bytes(plain)
            print(f"[CLIENT] saved {name} (decrypted, {len(plain)} bytes)")
        except Exception:
            (DOWNLOAD_DIR / name).write_bytes(data)
            print(f"[CLIENT] saved {name} (plaintext, {len(data)} bytes)")

    def request(self, f, host, port, owner):
        if not self.sock: return print("[CLIENT] connect first")
        self.sock.sendall(f"REQUEST_REMOTE {f} {host} {port} {owner}\n".encode())
        print("[CLIENT]", self._resp())

    def grant(self, f, requester):
        if not self.sock: return print("[CLIENT] connect first")
        self.sock.sendall(f"GRANT {f} {requester}\n".encode())
        print("[CLIENT]", self._resp())

    def peerlist(self):
        if not self.sock: return print("[CLIENT] connect first")
        self.sock.sendall(b"PEERLIST\n")
        print("[CLIENT] peer files:", self._resp()[3:] or "(none)")

HELP = (
    "commands:\n"
    "  connect  <host> <port>\n"
    "  register | login\n"
    "  list | upload <file> | download <name>\n"
    "  request  <file> <ownerHost> <ownerPort> <ownerUser>\n"
    "  grant    <file> <requester>\n"
    "  peerlist | quit"
)

def main():
    cli = FileShareClient()
    while True:
        try:
            parts = shlex.split(input("p2p> "), posix=False)
        except (EOFError, KeyboardInterrupt):
            print(); break
        if not parts: continue
        cmd, *a = parts
        try:
            match cmd:
                case "connect":   cli.connect(a[0], int(a[1]))
                case "register":  cli.register()
                case "login":     cli.login()
                case "list":      cli.list()
                case "upload":    cli.upload(Path(a[0]))
                case "download":  cli.download(a[0])
                case "request":   cli.request(a[0], a[1], int(a[2]), a[3])
                case "grant":     cli.grant(a[0], a[1])
                case "peerlist":  cli.peerlist()
                case "quit":      break
                case _:           print(HELP)
        except Exception as e:
            print("[CLIENT ERROR]", e); print(HELP)

if __name__ == "__main__":
    main()

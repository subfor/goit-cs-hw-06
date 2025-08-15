import json
import logging
import mimetypes
import os
import pathlib
import socket
import sys
import urllib.parse
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from multiprocessing import Process

from pymongo import MongoClient, errors

# from pymongo.errors import ConnectionFailure

HTML_ROOT = pathlib.Path(__file__).parent / "html"
ROOT_RESOLVED = HTML_ROOT.resolve()
LOG_FILE = HTML_ROOT / "server.log"
# для великого контенту
CHUNK = 64 * 1024  # 64KB

HTTP_HOST = os.getenv("HTTP_HOST", "0.0.0.0")
HTTP_PORT = int(os.getenv("HTTP_PORT", "3000"))

SOCKET_HOST = os.getenv("SOCKET_HOST", "127.0.0.1")
SOCKET_PORT = int(os.getenv("SOCKET_PORT", "5000"))

MONGO_USER = os.getenv("MONGO_INITDB_ROOT_USERNAME")
MONGO_PASS = os.getenv("MONGO_INITDB_ROOT_PASSWORD")
MONGO_HOST = os.getenv("MONGO_HOST", "localhost")
MONGO_PORT = int(os.getenv("MONGO_PORT", 27017))
MONGO_DB = os.getenv("MONGO_DB", "db_messages")
MONGO_COL = os.getenv("MONGO_COLLECTION", "messages")


def setup_logger():
    """Створює і повертає налаштований логгер."""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(LOG_FILE, delay=True)
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)

    if not logger.handlers:
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    return logger


def safe_join(root: pathlib.Path, rel_url_path: str) -> pathlib.Path | None:
    """Безпечне приєднання шляху всередині кореневої директорії."""
    rel = urllib.parse.unquote(rel_url_path.lstrip("/"))
    # проста перевірка від дуже хитрих
    if "\x00" in rel:
        return None

    candidate = (root / rel).resolve()
    if not str(candidate).startswith(str(ROOT_RESOLVED)):
        return None

    if candidate.is_dir():
        candidate = (candidate / "index.html").resolve()
        if not str(candidate).startswith(str(ROOT_RESOLVED)):
            return None

    if candidate.exists() and candidate.is_file():
        return candidate
    return None


class HttpHandler(BaseHTTPRequestHandler):
    # Увімкнути HTTP/1.1 (keep-alive)
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        data = self.rfile.read(length)
        data_parse = urllib.parse.unquote_plus(data.decode())
        data_dict = {
            k: v
            for k, v in (
                pair.split("=", 1) for pair in data_parse.split("&") if "=" in pair
            )
        }

        logging.info(f"POST {self.path} from {self.client_address} DATA: {data_dict}")

        # відправка на сокет-сервер
        try:
            payload = json.dumps(data_dict).encode("utf-8")
            # спочатку 4 байти довжини big-endian, потім тіло
            with socket.create_connection((SOCKET_HOST, SOCKET_PORT), timeout=3) as s:
                s.sendall(len(payload).to_bytes(4, "big"))
                s.sendall(payload)
        except Exception as e:
            logging.error(f"Failed to send to socket server: {e}")

        self.send_response(302)
        self.send_header("Location", "/")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

    def do_GET(self):
        pr_url = urllib.parse.urlparse(self.path)
        logging.info(f"GET {self.path} from {self.client_address}")

        if pr_url.path == "/":
            return self.send_html_file("index.html")

        file_path = safe_join(HTML_ROOT, pr_url.path)
        if file_path is None:
            return self.send_html_file("error.html", status=404)

        return self.send_static(file_path)

    def send_html_file(self, filename: str, status: int = 200):
        file_path = (HTML_ROOT / filename).resolve()
        if not str(file_path).startswith(str(ROOT_RESOLVED)) or not file_path.exists():
            status = 404
            file_path = (HTML_ROOT / "error.html").resolve()

        try:
            size = os.path.getsize(file_path)
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(size))
            self.send_header("Connection", "keep-alive")
            self.end_headers()

            with open(file_path, "rb") as fd:
                while True:
                    chunk = fd.read(CHUNK)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True

    def send_static(self, file_path: pathlib.Path):
        try:
            ctype, _ = mimetypes.guess_type(str(file_path))
            ctype = ctype or "application/octet-stream"
            size = os.path.getsize(file_path)

            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(size))
            self.send_header("Connection", "keep-alive")
            self.end_headers()

            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(CHUNK)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True

    # Перевизначимо  BaseHTTPRequestHandler.log_message щоб не було дублювання і був тільки наш логер
    def log_message(self, fmt, *args):
        logging.info(
            "%s - - [%s] %s",
            self.client_address[0],
            self.log_date_time_string(),
            fmt % args,
        )


def run_http_server():
    server_address = (HTTP_HOST, HTTP_PORT)
    http = ThreadingHTTPServer(server_address, HttpHandler)
    logging.info(f"HTTP server started on {HTTP_HOST}:{HTTP_PORT} (threaded)")
    try:
        http.serve_forever()
    except KeyboardInterrupt:
        logging.info("HTTP server stopped")
        http.server_close()


class MongoSession:
    def __init__(self):
        self.client = None
        self.db = None
        self.collection = None

    def __enter__(self):
        try:
            uri = f"mongodb://{MONGO_USER}:{MONGO_PASS}@{MONGO_HOST}:{MONGO_PORT}/"
            self.client = MongoClient(uri, serverSelectionTimeoutMS=3000)
            self.client.admin.command("ping")  # Перевірка з'єднання
            self.db = self.client[MONGO_DB]
            self.collection = self.db[MONGO_COL]
            logging.info("MongoDB connected OK: %s -> %s.%s", uri, MONGO_DB, MONGO_COL)
            return self
        except errors.ConnectionFailure as e:
            logging.error("MongoDB connection failed: %s", e)
            raise
        except Exception as e:
            logging.exception("MongoSession init error: %s", e)
            raise

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.client:
            self.client.close()
            logging.info("MongoDB connection closed.")


def run_socket_server():
    """
    TCP Socket-сервер на SOCKET_HOST:SOCKET_PORT.
    Протокол: 4 байти довжини (big-endian) + JSON.
    Зберігає у MongoDB документ виду:
    {
      "date": "YYYY-MM-DD HH:MM:SS.mmmmmm",
      "username": "...",
      "message": "..."
    }
    """
    try:
        with MongoSession() as ms:
            col = ms.collection
            logging.info("Socket server connected to Mongo.")

            # TCP сервер
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind((SOCKET_HOST, SOCKET_PORT))
                srv.listen(5)
                logging.info(
                    "Socket server listening on %s:%s", SOCKET_HOST, SOCKET_PORT
                )

                while True:
                    conn, addr = srv.accept()
                    with conn:
                        try:
                            # читаємо довжину
                            hdr = conn.recv(4)
                            if len(hdr) < 4:
                                continue
                            length = int.from_bytes(hdr, "big")

                            # читаємо payload
                            buf = bytearray()
                            while len(buf) < length:
                                chunk = conn.recv(min(65536, length - len(buf)))
                                if not chunk:
                                    break
                                buf.extend(chunk)

                            if len(buf) != length:
                                logging.warning("Incomplete payload from %s", addr)
                                continue

                            data = json.loads(buf.decode("utf-8"))
                            username = str(data.get("username", "")).strip()
                            message = str(data.get("message", "")).strip()

                            doc = {
                                "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
                                "username": username,
                                "message": message,
                            }
                            col.insert_one(doc)
                            logging.info("Saved message from %s: %s", addr, doc)

                        except json.JSONDecodeError:
                            logging.warning("Bad JSON from %s", addr)
                        except Exception as e:
                            logging.exception(
                                "Socket handler error from %s: %s", addr, e
                            )
    except Exception:
        # помилки вже залоговані у MongoSession
        return


if __name__ == "__main__":

    setup_logger()

    http_process = Process(target=run_http_server)
    socket_process = Process(target=run_socket_server)

    http_process.start()
    socket_process.start()

    logging.info("Main started. HTTP and Socket servers running in separate processes.")
    try:
        socket_process.join()
        http_process.join()
    except KeyboardInterrupt:
        socket_process.terminate()
        http_process.terminate()
        logging.info("Main process stopped")

import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


@dataclass(slots=True)
class RequestCount:
    value: int = 0


@dataclass(frozen=True, slots=True)
class LocalJWKS:
    jwks: dict[str, Any]
    url: str
    request_count: RequestCount


@contextmanager
def jwks_server(jwks: dict[str, Any]) -> Iterator[LocalJWKS]:
    request_count = RequestCount()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path != "/jwks.json":
                self.send_response(404)
                self.end_headers()
                return

            request_count.value += 1
            body = json.dumps(jwks).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        host, port = server.server_address
        yield LocalJWKS(
            jwks=jwks,
            url=f"http://{host}:{port}/jwks.json",
            request_count=request_count,
        )
    finally:
        server.shutdown()
        server.server_close()

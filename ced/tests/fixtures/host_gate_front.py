"""Host 门禁前置：有 Host 头的请求原样转发，没有的回 400。

用于链路自适应测试：验证引擎对「被前置拒绝」的用例会自动补上部署性缺失
（Host 头）重试，并在观测里如实标记 ``front_adapted``。

    python host_gate_front.py <port> <probe_data_port>

协议与 standin_front.py 相同：一条连接一条请求，读尽即转发（透传半关闭）。
"""
from __future__ import annotations

import socket
import sys


def has_host(buf: bytes) -> bool:
    head = buf.partition(b"\r\n\r\n")[0]
    return any(line.lower().startswith(b"host:")
               for line in head.split(b"\r\n")[1:])


def handle(conn: socket.socket, upstream: tuple[str, int]) -> None:
    conn.settimeout(5.0)
    buf = b""
    try:
        while len(buf) < (1 << 20):
            try:
                chunk = conn.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            if b"\r\n\r\n" in buf:
                break
        if not buf:
            return
        if has_host(buf):
            with socket.create_connection(upstream, timeout=5) as up:
                up.sendall(buf)
                up.shutdown(socket.SHUT_WR)
                reply = b""
                while True:
                    chunk = up.recv(65536)
                    if not chunk:
                        break
                    reply += chunk
            if reply:
                conn.sendall(reply)
        else:
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\n"
                         b"Content-Length: 0\r\nConnection: close\r\n\r\n")
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main() -> int:
    port, probe_data = int(sys.argv[1]), int(sys.argv[2])
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)
    while True:
        conn, _ = srv.accept()
        handle(conn, ("127.0.0.1", probe_data))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

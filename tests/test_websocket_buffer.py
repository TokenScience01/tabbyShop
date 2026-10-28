"""Buffered WebSocket handshake regression tests using an in-memory socket."""
import base64
import hashlib
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "game_client"))
from wss_tester import MiniWebSocket, WsError


KEY_BYTES = b"x" * 16
KEY = base64.b64encode(KEY_BYTES).decode()
ACCEPT = base64.b64encode(hashlib.sha1((KEY + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
HEAD = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + ACCEPT + b"\r\n\r\n"


class MemorySocket:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.reads = 0
        self.sent = []

    def recv(self, count):
        self.reads += 1
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        if len(chunk) > count:
            self.chunks.insert(0, chunk[count:])
        return chunk[:count]

    def sendall(self, data):
        self.sent.append(data)

    def settimeout(self, _timeout):
        pass

    def shutdown(self, _how):
        pass

    def close(self):
        pass


class WebSocketBufferTests(unittest.TestCase):
    def connect(self, chunks):
        socket = MemorySocket(chunks)
        ws = MiniWebSocket("ws://example.test/realtime", {}, [])
        with patch("wss_tester.socket.create_connection", return_value=socket), \
                patch("wss_tester.os.urandom", return_value=KEY_BYTES):
            ws.connect()
        return ws, socket

    def test_handshake_and_first_frame_share_one_socket_read(self):
        ws, socket = self.connect([HEAD + b"\x81\x02ok"])
        self.assertEqual(ws.recv_message(), (1, b"ok"))
        self.assertEqual(socket.reads, 1)

    def test_split_handshake_preserves_bytes_from_following_frame(self):
        ws, _socket = self.connect([HEAD[:30], HEAD[30:] + b"\x81", b"\x02ok"])
        self.assertEqual(ws.recv_message(), (1, b"ok"))

    def test_multiple_frames_buffered_after_handshake(self):
        ws, socket = self.connect([HEAD + b"\x81\x01a\x82\x01b"])
        self.assertEqual(ws.recv_message(), (1, b"a"))
        self.assertEqual(ws.recv_message(), (2, b"b"))
        self.assertEqual(socket.reads, 1)

    def test_fragmented_message_with_interleaved_ping(self):
        ws, socket = self.connect([HEAD + b"\x01\x03hel\x89\x01!\x80\x02lo"])
        self.assertEqual(ws.recv_message(), (1, b"hello"))
        self.assertEqual(socket.sent[-1][0], 0x8A)

    def test_oversized_handshake_still_rejected(self):
        with self.assertRaisesRegex(WsError, "64 KB"):
            self.connect([b"H" * 65537])

    def test_reconnect_does_not_reuse_buffer_or_headers(self):
        ws, _socket = self.connect([HEAD + b"\x81\x03old"])
        ws.response_headers["old-session"] = "stale"
        socket = MemorySocket([HEAD + b"\x81\x03new"])
        with patch("wss_tester.socket.create_connection", return_value=socket), \
                patch("wss_tester.os.urandom", return_value=KEY_BYTES):
            ws.connect()
        self.assertNotIn("old-session", ws.response_headers)
        self.assertEqual(ws.recv_message(), (1, b"new"))
        ws.close()
        self.assertEqual(ws._recv_buffer, bytearray())


if __name__ == "__main__":
    unittest.main()

"""
tls_sni.py
-----------
Pulls the *website name* out of the first packet of an HTTPS connection.

Analogy: HTTPS encrypts the letter inside the envelope, but when you
first knock on the server's door (the TLS "ClientHello") you still say
out loud which house you want: "I'd like www.youtube.com please". That
spoken name is called SNI (Server Name Indication). We read only that
name. We never see, decrypt, or store the encrypted content itself.

For plain HTTP (port 80) the same idea applies to the "Host:" header.

Everything here is best-effort: if the packet is truncated, fragmented
across several TCP segments, or uses a newer privacy feature (like
Encrypted Client Hello), we simply return None.
"""


def extract_sni(data: bytes):
    """Return the server name from a TLS ClientHello, or None."""
    try:
        # Record header: type(1)=0x16 handshake, version(2), length(2)
        if len(data) < 12 or data[0] != 0x16 or data[1] != 0x03:
            return None
        # Handshake header: type(1)=0x01 ClientHello, length(3)
        if data[5] != 0x01:
            return None

        pos = 5 + 4           # skip handshake header
        pos += 2 + 32         # skip client version + 32 random bytes
        pos += 1 + data[pos]  # skip session id
        cipher_len = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2 + cipher_len  # skip cipher suites
        pos += 1 + data[pos]   # skip compression methods

        if pos + 2 > len(data):
            return None
        ext_total = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2
        end = min(len(data), pos + ext_total)

        while pos + 4 <= end:
            ext_type = int.from_bytes(data[pos:pos + 2], "big")
            ext_len = int.from_bytes(data[pos + 2:pos + 4], "big")
            pos += 4
            if ext_type == 0x0000:  # server_name extension
                # list length(2), name type(1), name length(2), name
                if pos + 5 > len(data):
                    return None
                name_len = int.from_bytes(data[pos + 3:pos + 5], "big")
                name = data[pos + 5:pos + 5 + name_len]
                if len(name) != name_len or name_len == 0:
                    return None
                return name.decode("ascii").lower()
            pos += ext_len
    except (IndexError, UnicodeDecodeError):
        return None
    return None


_HTTP_METHODS = (b"GET ", b"POST", b"HEAD", b"PUT ", b"OPTI", b"DELE", b"PATC", b"CONN")


def extract_http_host(data: bytes):
    """Return the Host header from a plain-HTTP request, or None."""
    try:
        if data[:4] not in _HTTP_METHODS:
            return None
        head = data[:1500]
        idx = head.lower().find(b"\r\nhost:")
        if idx == -1:
            return None
        start = idx + len(b"\r\nhost:")
        end = head.find(b"\r\n", start)
        if end == -1:
            end = len(head)
        host = head[start:end].decode("ascii", errors="ignore").strip().lower()
        host = host.split(":")[0]  # drop :port
        return host or None
    except Exception:
        return None

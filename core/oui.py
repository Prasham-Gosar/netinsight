"""
oui.py
-------
MAC address -> manufacturer. The first 3 bytes of a MAC (the OUI) identify
the company that made the network chip.

IMPORTANT: this is a small built-in sample table so the project works with
zero downloads. For full accuracy, put the official IEEE list in
data/oui.csv (one "AABBCC,Vendor Name" per line) and it is loaded
automatically.

Modern phones also use *randomised* "private" MAC addresses, which have no
real manufacturer. We detect those via the 'locally administered' bit.
"""

import os

_BUILTIN = {
    "3C970E": "Intel", "001B21": "Intel", "0013E8": "Intel",
    "000393": "Apple", "3C0754": "Apple", "A483E7": "Apple", "F01898": "Apple",
    "001247": "Samsung", "001599": "Samsung", "8C7712": "Samsung", "5C0A5B": "Samsung",
    "001422": "Dell", "180373": "Dell", "B8CA3A": "Dell",
    "3CD92B": "HP", "0017A4": "HP",
    "50C7BF": "TP-Link",
    "34CE00": "Xiaomi", "F8A45F": "Xiaomi",
    "00E0FC": "Huawei",
    "3C5AB4": "Google", "F4F5D8": "Google",
    "44650D": "Amazon", "F0272D": "Amazon",
    "0003FF": "Microsoft", "281878": "Microsoft",
    "00E04C": "Realtek",
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
    "A4CF12": "Espressif", "30AEA4": "Espressif",
    "00000C": "Cisco",
    "005056": "VMware", "000C29": "VMware", "080027": "VirtualBox",
}

_loaded = None


def _table():
    global _loaded
    if _loaded is None:
        table = dict(_BUILTIN)
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "data", "oui.csv")
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as fh:
                    for line in fh:
                        code, _, name = line.strip().partition(",")
                        if len(code) == 6 and name:
                            table[code.upper()] = name
            except OSError:
                pass
        _loaded = table
    return _loaded


def is_randomized(mac):
    """Locally-administered bit set -> private/randomised MAC (typical for phones)."""
    try:
        return bool(int(mac[:2], 16) & 0b10)
    except (ValueError, TypeError):
        return False


def lookup_vendor(mac):
    if not mac:
        return None
    if is_randomized(mac):
        return None
    return _table().get(mac.replace(":", "").upper()[:6])

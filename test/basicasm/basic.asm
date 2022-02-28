        global  _start
        section .text
_start:
        mov     rbx, message
        add     rbx, [ind]
        mov BYTE[rbx],71
        mov     rax, 1
        mov     rdi, 1
        mov     rsi, rbx
        mov     rdx, 13
        syscall
        mov     eax, 60
        xor     rdi, rdi
        syscall
        
        section .data
message:
        db      "Hello, World", 10
    ind:
        dd      8
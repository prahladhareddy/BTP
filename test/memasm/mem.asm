        global  _start
        section .text
_start:
        mov     rax, [a]
        mov     rbx, [b]
        mov     rsp, [c]
        mov     rbp, [d]
        mov     rcx, message
        cmp     rax, rbx
        jge     else
if:     
        add     rcx,rsp
        jmp     endifelse
else:
        add     rbp,rcx
        mov     [c],rbp
        mov     rcx,[c]
endifelse:
        mov     rax, 1
        mov     rdi, 1
        mov     rsi, rcx
        mov     rdx, 6
        syscall 
        mov     rax, 1
        mov     rdi, 1
        mov     eax, 60
        xor     rdi, rdi
        syscall

        
        section .data
a:
        dd      10,0
b:
        dd      2,0
c:
        dd      4,0
d:
        dd      6,0
message:
        db      "abcdefghijklmnopqrstuvwxyz",10
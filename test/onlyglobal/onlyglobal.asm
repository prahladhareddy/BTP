        global  _start
        section .text
_start:
        mov     rax, [a]
        mov     rbx, [b]
        mov     rsp, [c]
        mov     rbp, [d]
        mov     rcx, message
        add     [b],rsp
        cmp     rax, rbx
        jge     else
if:     
        add     rcx, [b]
        jmp     endifelse
else:
        add     rcx,2
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
        dd      4,0
c:
        dd      4,0
d:
        dd      5,0
message:
        db      "hello world hello world",10
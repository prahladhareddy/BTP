        global  _start
        section .text
_start:
        mov     rax, [a]
        mov     rbx, [b]
        mov     rcx, message
loop:
        cmp     rax, 10
        jge     end
        add     rax, rbx
        add     rbx, 1
        jmp     loop
end: 
        add     rcx, rax
        mov     rax, 1
        mov     rdi, 1
        mov     rsi, rcx
        mov     rdx, 1
        syscall 
        mov     rax, 1
        mov     rdi, 1
        mov     eax, 60
        xor     rdi, rdi
        syscall

        
        section .data
a:
        dd      5,0
b:
        dd      4,0
message:
        db      "hello world hello world",10
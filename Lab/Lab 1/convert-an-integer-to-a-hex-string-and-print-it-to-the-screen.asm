section .bss
    buffer resb 8         

section .data
    number dd 64200 
    prefix db "0x"         
    newline db 10          

section .text
    global _start

_start:
    mov ecx, 8                
    mov edx, [number]         

convert:
    mov eax, edx
    and eax, 0x0F               

    cmp al, 9
    jle is_digit
    add al, 'A' - 10            
    jmp main

is_digit:
    add al, '0'                 

main:
    mov [buffer + ecx - 1], al  
    shr edx, 4                
    loop convert         

    mov eax, 4                  
    mov ebx, 1                  
    mov ecx, prefix
    mov edx, 2                  
    int 0x80

    mov eax, 4                  
    mov ebx, 1                  
    mov ecx, buffer
    mov edx, 8                  
    int 0x80

    mov eax, 4                  
    mov ebx, 1                  
    mov ecx, newline
    mov edx, 1                  
    int 0x80

    mov eax, 1                  
    xor ebx, ebx                
    int 0x80
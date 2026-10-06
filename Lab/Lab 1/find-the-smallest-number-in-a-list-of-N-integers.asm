section .data
    numbers dd 6, 8, 9, 1, 2
    n dd 5
    min_result dd 0
    newline db 10

section .text
    global _start

_start:
    mov ecx, [n]                ; ecx = N
    mov esi, 0                  ; esi = 0
    mov eax, [numbers]          ; eax = numbers[0]

find_min:
    cmp [numbers + esi * 4], eax
    jge skip
    mov eax, [numbers + esi * 4]

; find_max:
;     cmp [numbers + esi * 4], eax
;     jle skip
;     mov eax, [numbers + esi * 4]

skip:
    inc esi
    loop find_min

    add eax, '0'
    mov [min_result], eax

    mov eax, 4
    mov ebx, 1
    mov ecx, min_result
    mov edx, 1
    int 0x80

    mov eax, 4
    mov ebx, 1
    mov ecx, newline
    mov edx, 1
    int 0x80

    mov eax, 1                  
    xor ebx, ebx
    int 0x80

; section .data
;     numbers dd 6, 8, 9, 1, 2      
;     n dd 5                        
;     min_result dd 0
;     newline db 10
; 
; section .text
;     global _start
; 
; _start:
;     mov ecx, [n]                ; ecx = N
;     mov esi, 0                  ; esi = 0
;     mov eax, [numbers]          ; eax = numbers[0]
; 
; loop:
;     cmp ecx, 2                  
;     jl remainder         
; 
;     cmp [numbers + esi * 4], eax
;     jge skip_1
;     mov eax, [numbers + esi * 4]
;
; skip_1:
;     cmp [numbers + esi * 4 + 4], eax
;     jge skip_2
;     mov eax, [numbers + esi * 4 + 4]
;
; skip_2:
;     add esi, 2                  
;     sub ecx, 2                  
;     jnz loop             
;     jmp done
; 
; remainder:
;     cmp ecx, 0
;     je done
;     cmp [numbers + esi * 4], eax
;     jge done
;     mov eax, [numbers + esi * 4]
; 
; done:
;     mov [min_result], eax
;     add eax, '0'
;     mov [min_result], eax
; 
;     mov eax, 4                  ; sys_write
;     mov ebx, 1                  ; stdout
;     mov ecx, min_result
;     mov edx, 1
;     int 0x80
; 
;     mov eax, 4
;     mov ebx, 1
;     mov ecx, newline
;     mov edx, 1
;     int 0x80
; 
;     mov eax, 1                  ; sys_exit
;     xor ebx, ebx
;     int 0x80
section .bss
    buffer resb 100

section .data
    key db 0x5A
    newline db 10

section .text
    global _start

_start:
    mov eax, 3
    mov ebx, 0
    mov ecx, buffer
    mov edx, 100
    int 0x80

    cmp eax, 1
    jle exit

    dec eax
    mov esi, eax

    mov edi, 0

encode:
    cmp edi, esi
    jge encode_done

    mov al, [buffer + edi]
    xor al, [key]
    mov [buffer + edi], al

    inc edi
    jmp encode

encode_done:
    mov eax, 4
    mov ebx, 1
    mov ecx, buffer
    mov edx, esi
    int 0x80

    mov eax, 4
    mov ebx, 1
    mov ecx, newline
    mov edx, 1
    int 0x80

    mov edi, 0

decode:
    cmp edi, esi
    jge decode_done

    mov al, [buffer + edi]
    xor al, [key]
    mov [buffer + edi], al

    inc edi
    jmp decode

decode_done:
    mov eax, 4
    mov ebx, 1
    mov ecx, buffer
    mov edx, esi
    int 0x80

    mov eax, 4
    mov ebx, 1
    mov ecx, newline
    mov edx, 1
    int 0x80

exit:
    mov eax, 1
    xor ebx, ebx
    int 0x80
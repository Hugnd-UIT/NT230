section .data
    number dd 1234
    result_yes db "YES", 10
    result_no db "NO", 10

section .text
    global _start

_start:
    mov eax, [number]
    xor ebx, ebx
    mov ecx, 10

reverse:
    xor edx, edx
    div ecx

    imul ebx, 10
    add ebx, edx

    cmp eax, 0
    jnz reverse

    cmp ebx, [number]
    je is_palindrome

not_palindrome:
    mov eax, 4
    mov ebx, 1
    mov ecx, result_no
    mov edx, 3
    int 0x80
    jmp exit

is_palindrome:
    mov eax, 4
    mov ebx, 1
    mov ecx, result_yes
    mov edx, 4
    int 0x80

exit:
    mov eax, 1
    xor ebx, ebx
    int 0x80
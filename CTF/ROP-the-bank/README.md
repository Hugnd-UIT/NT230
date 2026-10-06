# Writeup: ROP-the-bank

**Difficulty**: Hard  
**Category**: Pwn  
**Techniques**: Stack Over-read, Ret2Libc, ROP, Bypassing PTY Canonical Mode Escaping

## 1. Phân tích sơ bộ (Recon)
Đầu tiên, ta kiểm tra các cơ chế bảo vệ của file thực thi (checksec):
- **Canary**: Enabled (Chống Buffer Overflow cơ bản)
- **NX**: Enabled (Không thể thực thi shellcode trên stack)
- **PIE**: Enabled (Bộ nhớ bị random địa chỉ, cần phải leak PIE base)
- **RELRO**: Full RELRO (Không thể ghi đè GOT)

Chương trình là một ứng dụng quản lý tài khoản ngân hàng đơn giản.

## 2. Truy tìm lỗ hổng (Vulnerability Analysis)

### 2.1. Lỗ hổng Stack Over-read (Leak Information)
Trong hàm `show_statement()`:
```c
char history[64];
// ...
write(STDOUT_FILENO, history, 128);
```
Chương trình khai báo mảng `history` độ dài 64 byte trên stack, nhưng lại dùng `write` để in ra tận 128 byte. Lỗi này cho phép chúng ta đọc vượt giới hạn mảng (Over-read) và xem được các dữ liệu nhạy cảm nằm trên stack đằng sau mảng `history`. Các dữ liệu này bao gồm giá trị **Stack Canary** và **Return Address** (từ đó tính được **PIE base**).

### 2.2. Lỗ hổng Buffer Overflow
Trong hàm `deposit()`:
```c
char buf[64];
// ...
ssize_t n = read(STDIN_FILENO, buf, 512);
```
Biến `buf` có kích thước 64 byte nhưng lệnh `read` lại cho phép nhập vào tối đa 512 byte. Đây là lỗi Buffer Overflow siêu cơ bản. Kết hợp với Canary và PIE đã leak được ở trên, ta hoàn toàn có thể ghi đè Return Address để chuyển hướng luồng thực thi (ROP).

## 3. Quá trình khai thác (Exploitation)

### Bước 1: Vượt qua vòng Login
Hàm `login()` so sánh mã PIN với chuỗi cứng `"1337\n"`. Ta chỉ cần nhập Username bất kỳ và PIN là `1337` để đăng nhập.

### Bước 2: Leak Canary và PIE
Truy cập tính năng `2. View Statement`. Chương trình sẽ in ra 128 byte từ stack.
Dựa vào offset, ta có thể trích xuất được Canary và địa chỉ trả về (Return Address) lưu trên stack:
- **Canary**: Nằm ở byte 72 đến 80 của dữ liệu rò rỉ.
- **Saved RIP (Return Address)**: Nằm ở byte 88 đến 96. Từ đây trừ đi offset `0x18b6` (khoảng cách từ lệnh call đến PIE base) để lấy ra `PIE base`.

### Bước 3: ROP Chain 1 - Leak địa chỉ Libc
Do không được cung cấp file thư viện `libc.so.6`, ta phải lợi dụng các ROP gadget có sẵn trong file thực thi để rò rỉ (leak) địa chỉ thực của libc trên server.
Sử dụng lỗi Buffer Overflow trong `deposit()`, ta xây dựng ROP Chain để gọi hàm `puts(printf@GOT)` nhằm in ra địa chỉ của hàm `printf` trong libc:
1. `pop rdi; ret` gadget
2. Địa chỉ `printf@GOT` (đưa vào `rdi`)
3. Địa chỉ `puts@PLT` (thực thi `puts`)
4. Địa chỉ hàm `deposit()` (để quay lại nhập ROP chain 2)

**Vấn đề cực khoai - Cơ chế PTY (Canonical Mode):**
Do server chạy qua `socat` với tuỳ chọn `pty` (pseudo-terminal), nó sẽ xử lý các ký tự đặc biệt (như `\x7f` - Backspace/DEL, `\x1a` - SUSP, `\x13` - XOFF). Các byte ngẫu nhiên của RAM thường chứa các giá trị này (ví dụ: `saved_rbp` luôn chứa `\x7f`), khiến payload bị PTY "gọt" mất trước khi đến được hàm `read()`.
**Cách bypass:** Thêm byte `\x16` (LNEXT) vào trước *từng byte* của payload để báo cho PTY biết "hãy coi ký tự tiếp theo là chuỗi thô (literal), đừng xử lý nó". Đồng thời, ghi đè `saved_rbp` bằng một chuỗi an toàn như `b"B" * 8`.

*(Lưu ý: Có tỉ lệ 1/256 địa chỉ `printf` bị rơi vào trường hợp byte thứ hai là `\x00`, khiến `puts` không in ra được. Nếu gặp lỗi `struct.error` do ra số âm, chỉ cần chạy lại script).*

### Bước 4: ROP Chain 2 - Ret2Libc (Pop Shell)
Sau khi có được địa chỉ `printf`, ta copy đưa lên trang [libc.rip](https://libc.rip) để tìm kiếm phiên bản libc và lấy được các offset của `system` và chuỗi `/bin/sh`.
Lần này, ta gửi lại payload vào hàm `deposit()` để gọi `system("/bin/sh")`.

Lưu ý: Tuân thủ theo chuẩn x64 ABI, hàm `system` yêu cầu stack (`rsp`) phải chia hết cho 16 byte (16-byte alignment). ROP chain cần được căn chỉnh số lượng lệnh `ret` sao cho phù hợp trước khi gọi `system`.
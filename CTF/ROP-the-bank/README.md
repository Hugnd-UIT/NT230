# Writeup: ROP-the-bank

**Difficulty**: Hard  
**Category**: Pwn  
**Techniques**: Stack Over-read, Ret2Libc, ROP
**Description**: Bypass the state-of-the-art memory mitigations of this secure ATM and walk away with a shell

## 1. Phân tích

Đầu tiên, ta kiểm tra các cơ chế bảo vệ của file thực thi bằng checksec:

![alt text](images/image-1.png)

Chương trình là một ứng dụng quản lý tài khoản ngân hàng đơn giản.

## 2. Truy tìm lỗ hổng

### 2.1. Lỗ hổng Stack Over-read

Trong hàm `sub_138E()`:

![alt text](images/image-2.png)

Dựa vào mã giả từ IDA Pro, chương trình khai báo mảng `v4` trên stack với kích thước 64 byte, nhưng sau đó lại dùng hàm `write` để in ra tận 128 byte. Lỗi này cho phép chúng ta Over-read và xem được các dữ liệu nhạy cảm nằm trên stack đằng sau mảng `v4`. Các dữ liệu này bao gồm giá trị **Stack Canary** và **Return Address** từ đó tính được **PIE base**.

### 2.2. Lỗ hổng Buffer Overflow

Trong hàm `sub_1448()`:

![alt text](images/image-3.png)

Biến `v6` có kích thước 64 byte nhưng lệnh `read` cho phép nhập vào tối đa 512 byte. Đây là lỗi Buffer Overflow siêu cơ bản. Kết hợp với Canary và PIE đã leak được ở trên, ta hoàn toàn có thể ghi đè Return Address để chuyển hướng luồng thực thi (ROP).

## 3. Quá trình khai thác

### Bước 1: Login

Hàm `login()` so sánh mã PIN với chuỗi cứng `"1337\n"`. Ta chỉ cần nhập Username bất kỳ và PIN là `1337` để đăng nhập.

### Bước 2: Leak Canary và PIE

Truy cập tính năng `2. View Statement`. Chương trình sẽ in ra 128 byte từ stack.
Dựa vào offset, ta có thể trích xuất được Canary và địa chỉ trả về lưu trên stack:
- **Canary**: Nằm ở byte 72 đến 80 của dữ liệu rò rỉ.
- **Saved RIP**: Nằm ở byte 88 đến 96. Từ đây trừ đi offset `0x18b6` khoảng cách từ lệnh call đến PIE base để lấy ra `PIE base`.

### Bước 3: ROP Chain 1

Do không được cung cấp file thư viện, ta phải lợi dụng các ROP gadget có sẵn trong file thực thi để rò rỉ (leak) địa chỉ thực của libc trên server.

Sử dụng lỗi Buffer Overflow trong `sub_1448()`, ta xây dựng ROP Chain để gọi hàm `puts` nhằm in ra địa chỉ của 2 hàm `printf` và `read` trong libc:

1. `pop rdi; ret` gadget
2. Địa chỉ `printf@GOT` đưa vào `rdi`
3. Gọi `puts@PLT` thực thi `puts`
4. Tiếp tục `pop rdi; ret` gadget
5. Địa chỉ `read@GOT` đưa vào `rdi`
6. Gọi `puts@PLT`
7. Địa chỉ hàm `sub_1448()` để quay lại nhập ROP chain 2

### Bước 4: ROP Chain 2

Sau khi có được 2 địa chỉ của `printf` và `read`, ta copy 3 số cuối (offset) của cả 2 đưa lên trang [libc.rip](https://libc.rip) để tìm kiếm và xác định được chính xác 100% phiên bản libc. Từ đó lấy được các offset của `system` và chuỗi `/bin/sh`.

Lần này, ta gửi lại payload vào hàm `sub_1448()` để gọi `system("/bin/sh")`.

Lưu ý: Tuân thủ theo chuẩn x64 ABI, hàm `system` yêu cầu stack (`rsp`) phải chia hết cho 16 byte. ROP chain cần được căn chỉnh số lượng lệnh `ret` sao cho phù hợp trước khi gọi `system`.
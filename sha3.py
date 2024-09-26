def pad_message(message, rate):
    byte_data = bytearray(message) #Chuyển đổi thông điệp thành 1 mảng byte để dễ dàng thêm các byte đệm sau này

    byte_data.append(0x01) #Thêm 1 bit có giá trị 1 vào cuối byte_data để bắt đầu quá trình đệm để phân biệt giữa dữ liệu gốc và dữ liệu đệm khi giải mã
    # cũng như để đảm bảo tính toàn vẹn, đảm bảo dữ liệu gốc không bị thay đổi

    padding_length = rate // 8 - (len(byte_data) % (rate // 8)) #chia rate (kích thước khối tính bằng bit) sang byte để đảm bảo tính nhất quán
    # để xác định kích thước khối mà chúng ta sẽ sử dụng cho quá trình đệm.
    # Tính phần dư của độ dài hiện tại của byte_data khi chia cho kích thước khối để biết bao nhiêu byte còn thiếu để đạt được kích thước khối
    # Số byte đệm cần thêm vào để byte_data đạt được kích thước khối
    # Điều này đảm bảo rằng dữ liệu có độ dài là bội số của kích thước khối, giúp các thuật toán mã hóa xử lý dữ liệu một cách hiệu quả và chính xác
    # Ví dụ: byte_data hiện tại có độ dài là 10 byte và kích thước khối là 8 byte, chúng ta cần thêm 6 byte đệm để đạt được tổng độ dài là 16 byte (bội số của 8).

    byte_data.extend([0] * (padding_length - 1))
    byte_data.append(0x80) #Đánh dấu kết thúc phần đệm

    return byte_data


def keccak_f(state):
    num_rounds = 24 #Chỉ ra số vòng hàm sẽ thực hiện. 24 là đủ để đảm bảo mức độ khuếch tán và phi tuyến cao, 
    #giúp chống lại các cuộc tấn công mật mã như tấn công phân tích vi sai và tấn công phân tích tuyến tính
    # số vòng to còn đảm bảo rằng bất kì thay đổi nhỏ nào ở đầu vào sẽ thay đổi toàn bộ đầu ra
    RC = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
        0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
    ] # một mảng các hằng số vòng được sử dụng trong bước iota để thêm tính ngẫu nhiên và đảm bảo rằng mỗi vòng biến đổi là duy nhất

    def theta(state): #  khuếch tán thông tin trong trạng thái, đảm bảo rằng mỗi bit của đầu vào ảnh hưởng đến nhiều bit của đầu ra. 
        #Điều này giúp tăng cường tính bảo mật của thuật toán bằng cách làm cho việc dự đoán hoặc đảo ngược hàm băm trở nên cực kỳ khó khăn
        C = [0] * 5 #một mảng gồm 5 phần tử, mỗi phần tử đại diện cho giá trị parity của một cột trong trạng thái
        for x in range(5):
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] #tính toán XOR của tất cả các phần tử trong cùng một cột
            # XOR hoạt động trên hai bit và cho kết quả là 1 nếu hai bit khác nhau, và kết quả là 0 nếu hai bit giống nhau
        # Kết quả là giá trị parity của cột đó.

        D = [0] * 5 # là một mảng gồm 5 phần tử, mỗi phần tử đại diện cho một giá trị sẽ được XOR với các phần tử trong trạng thái
        for x in range(5):
            D[x] = C[(x - 1) % 5] ^ ((C[(x + 1) % 5] << 1) | (C[(x + 1) % 5] >> (64 - 1))) & 0xFFFFFFFFFFFFFFFF 
            # lấy giá trị parity của cột trước đó (với phép toán modulo để đảm bảo chỉ số nằm trong khoảng từ 0 đến 4).
        # dịch trái giá trị parity của cột kế tiếp một bit và thực hiện phép XOR với giá trị parity của cột trước đó. Kết quả là giá trị D[x]
        for x in range(5): # Cập nhật mỗi phần tử trong trạng thái bằng cách XOR với giá trị tương ứng của D
            for y in range(5):
                state[x + 5 * y] ^= D[x] #Cập nhật mỗi phần tử trong trạng thái bằng cách XOR với giá trị tương ứng của D
                state[x + 5 * y] &= 0xFFFFFFFFFFFFFFFF #đảm bảo rằng phần tử trạng thái vẫn là số nguyên 64-bit.
        return state

    def rho(state):
        # thực hiện bước xoay trái (left rotation) các phần tử trong trạng thái để khuếch tán thông tin, làm cho hàm băm trở nên khó dự đoán và khó đảo ngược. 
        # Điều này giúp đảm bảo rằng mỗi bit của đầu vào ảnh hưởng đến nhiều bit của đầu ra, tăng cường tính bảo mật của hàm băm.
        R = [
            [0, 36, 3, 41, 18],
            [1, 44, 10, 45, 2],
            [62, 6, 43, 15, 61],
            [28, 55, 25, 21, 56],
            [27, 20, 39, 8, 14]
        ]
        # một mảng 2D chứa các độ lệch xoay trái cho từng phần tử trong trạng thái. 
        # Mỗi phần tử R[x][y] xác định số bit mà phần tử state[x + 5 * y] sẽ được xoay trái

        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = ((state[x + 5 * y] << R[x][y]) | (state[x + 5 * y] >> (64 - R[x][y]))) & 0xFFFFFFFFFFFFFFFF
        return state
        """
        state[x + 5 * y] << R[x][y]: Dịch chuyển các bit của phần tử state[x + 5 * y] sang trái R[x][y] bit.
        state[x + 5 * y] >> (64 - R[x][y]): Dịch chuyển các bit của phần tử state[x + 5 * y] sang phải (64 - R[x][y]) bit.
        Phép toán OR (|): Kết hợp hai kết quả dịch chuyển để tạo ra kết quả xoay trái hoàn chỉnh.
        Phép toán AND (& 0xFFFFFFFFFFFFFFFF): Đảm bảo rằng kết quả là một số nguyên 64-bit.
        """

    def pi(state): #bước hoán vị (permutation) các phần tử trong trạng thái. 
        #Mục đích của bước này là để khuếch tán thông tin, đảm bảo rằng mỗi bit của đầu vào ảnh hưởng đến nhiều bit của đầu ra
        new_state = [0] * 25 #  Đây là một mảng mới gồm 25 phần tử, ban đầu được khởi tạo với giá trị 0. Mảng này sẽ lưu trữ trạng thái sau khi hoán vị.
        for x in range(5):
            for y in range(5):
                new_state[y + 5 * ((2 * x + 3 * y) % 5)] = state[x + 5 * y]
            """
            state[x + 5 * y]: Lấy phần tử tại vị trí (x, y) trong trạng thái ban đầu.
new_state[y + 5 * ((2 * x + 3 * y) % 5)]: Đặt phần tử này vào vị trí mới trong new_state theo công thức hoán vị y + 5 * ((2 * x + 3 * y) % 5).
Công thức hoán vị: y + 5 * ((2 * x + 3 * y) % 5) đảm bảo rằng các phần tử được sắp xếp lại một cách ngẫu nhiên nhưng có hệ thống, 
giúp khuếch tán thông tin hiệu quả.
"""
        return new_state

    def chi(state):
"""
bước biến đổi phi tuyến (non-linear transformation) trên trạng thái. 
Mục đích của bước này là để khuếch tán thông tin và tăng cường tính bảo mật của hàm băm bằng cách làm cho mỗi b
it của đầu ra phụ thuộc vào nhiều bit của đầu vào theo một cách phi tuyến
"""
        for y in range(5):
            temp = [state[x + 5 * y] for x in range(5)] # Đây là một mảng tạm thời chứa các phần tử của hàng y trong trạng thái
            # Sao chép các phần tử của hàng hiện tại để sử dụng trong các phép toán tiếp theo mà không làm thay đổi trực tiếp trạng thái ban đầu.
            for x in range(5):
                state[x + 5 * y] ^= (~temp[(x + 1) % 5] & temp[(x + 2) % 5])
                state[x + 5 * y] &= 0xFFFFFFFFFFFFFFFF
                """
                Phép toán NOT và AND:
~temp[(x + 1) % 5]: Thực hiện phép toán NOT (phủ định) trên phần tử temp[(x + 1) % 5].
temp[(x + 2) % 5]: Lấy phần tử temp[(x + 2) % 5].
~temp[(x + 1) % 5] & temp[(x + 2) % 5]: Thực hiện phép toán AND giữa kết quả của phép toán NOT và phần tử temp[(x + 2) % 5].
Phép toán XOR:
state[x + 5 * y] ^= (~temp[(x + 1) % 5] & temp[(x + 2) % 5]): Thực hiện phép toán XOR giữa phần tử state[x + 5 * y] và kết quả của phép toán AND.
Giới hạn giá trị trong 64 bit:
state[x + 5 * y] &= 0xFFFFFFFFFFFFFFFF
"""
        return state
"""
 khuếch tán thông tin từ mỗi bit của đầu vào ra toàn bộ trạng thái, làm cho hàm băm trở nên khó dự đoán và khó đảo ngược"""
   def iota(state, round_index):
   """ thực hiện bước XOR một hằng số vòng (round constant) với phần tử đầu tiên của trạng thái. 
   Mục đích của bước này là để phá vỡ tính đối xứng trong trạng thái, tăng cường tính bảo mật của hàm băm.
   """
        state[0] ^= RC[round_index]
        """
    state[0]: Đây là phần tử đầu tiên của trạng thái.
RC[round_index]: Đây là hằng số vòng tương ứng với chỉ số vòng hiện tại (round_index). Hằng số này được xác định trước và khác nhau cho mỗi vòng.
Phép toán XOR (^): Thực hiện phép toán XOR giữa state[0] và RC[round_index]. 
Phép toán XOR giúp kết hợp hai giá trị bit một cách hiệu quả, tạo ra một giá trị mới mà không thể dễ dàng dự đoán từ các giá trị ban đầu.
"""
        state[0] &= 0xFFFFFFFFFFFFFFFF
"""
Phép toán AND (&): Đảm bảo rằng kết quả của phép toán XOR vẫn là một số nguyên 64-bit. 0xFFFFFFFFFFFFFFFF là một số nhị phân với tất cả các bit đều là 1, 
tương đương với 64 bit.
Mục đích: Giới hạn giá trị của state[0] trong phạm vi 64 bit, đảm bảo tính nhất quán và tránh tràn số
"""
        return state

    for round_index in range(num_rounds):
        """
        Lặp qua các vòng: Áp dụng năm bước (theta, rho, pi, chi, iota) theo thứ tự cho mỗi vòng trong 24 vòng."""
        state = theta(state)
        state = rho(state)
        state = pi(state)
        state = chi(state)
        state = iota(state, round_index)

    return state


def absorbing_phase(message, rate, capacity):
"""
Hàm absorbing_phase trong thuật toán Keccak thực hiện giai đoạn hấp thụ (absorbing phase), 
nơi mà thông điệp đầu vào được kết hợp với trạng thái ban đầu thông qua các phép toán XOR và các vòng biến đổi Keccak-f. 
Mục đích của giai đoạn này là để chuẩn bị trạng thái cho giai đoạn nén (squeezing phase) sau đó
"""
    byte_data = pad_message(message, rate)
"""
pad_message(message, rate): Hàm này thực hiện việc đệm (padding) thông điệp để đảm bảo rằng độ dài của thông điệp là bội số của rate. 
Điều này là cần thiết để chia thông điệp thành các khối có kích thước cố định.
Mục đích: Đảm bảo rằng thông điệp có độ dài phù hợp để xử lý trong các vòng biến đổi tiếp theo.
"""
    block_size = rate // 8
"""
Tính toán kích thước khối
block_size: Kích thước của mỗi khối dữ liệu, tính bằng byte. rate là số bit, nên chia cho 8 để chuyển đổi sang byte.
Mục đích: Xác định kích thước của mỗi khối dữ liệu sẽ được xử lý trong mỗi vòng lặp
"""
    state = [0] * 25  # Initialize state as a list of 25 64-bit integers (1600 bits)
"""
state: Trạng thái ban đầu được khởi tạo là một danh sách gồm 25 số nguyên 64-bit, tương đương với 1600 bit.
Mục đích: Khởi tạo trạng thái để chuẩn bị cho các phép toán XOR và biến đổi Keccak-f."""

    for i in range(0, len(byte_data), block_size):
        block = byte_data[i:i + block_size]
        for j in range(block_size // 8):
            state[j] ^= int.from_bytes(block[j * 8:(j + 1) * 8], 'little')
            state[j] &= 0xFFFFFFFFFFFFFFFF  # Ensure it's 64-bit
        state = keccak_f(state)
"""
Vòng lặp for i in range(0, len(byte_data), block_size): Duyệt qua từng khối dữ liệu trong thông điệp đã được đệm.
block = byte_data[i:i + block_size]: Lấy một khối dữ liệu từ thông điệp.
Vòng lặp for j in range(block_size // 8): Duyệt qua từng phần tử trong khối dữ liệu.
state[j] ^= int.from_bytes(block[j * 8:(j + 1) * 8], 'little'): Thực hiện phép toán XOR giữa phần tử trạng thái và giá trị của khối dữ liệu, 
chuyển đổi từ byte sang số nguyên 64-bit theo thứ tự byte nhỏ (little-endian).
state[j] &= 0xFFFFFFFFFFFFFFFF: Đảm bảo rằng kết quả của phép toán XOR vẫn là một số nguyên 64-bit.
state = keccak_f(state): Thực hiện biến đổi Keccak-f trên trạng thái sau khi đã cập nhật với khối dữ liệu."""
    return state


def squeezing_phase(state, rate, output_length):
    """
    Hàm squeezing_phase trong thuật toán Keccak thực hiện giai đoạn nén (squeezing phase), 
    nơi mà trạng thái đã được cập nhật trong giai đoạn hấp thụ (absorbing phase) được sử dụng để tạo ra đầu ra hàm băm có độ dài mong muốn.
    """
    block_size = rate // 8
    """
    block_size: Kích thước của mỗi khối dữ liệu, tính bằng byte. rate là số bit, nên chia cho 8 để chuyển đổi sang byte.
Mục đích: Xác định kích thước của mỗi khối dữ liệu sẽ được xử lý trong mỗi vòng lặp.
"""
    hash_output = bytearray()
    """
    hash_output: Một mảng byte (bytearray) để lưu trữ đầu ra của hàm băm.
Mục đích: Chuẩn bị một biến để lưu trữ kết quả đầu ra của hàm băm.
"""

    while len(hash_output) < output_length:
        for i in range(block_size // 8):
            hash_output.extend(state[i].to_bytes(8, 'little'))
        if len(hash_output) < output_length:
            state = keccak_f(state)

    return hash_output[:output_length]
    """
    Vòng lặp while len(hash_output) < output_length: Tiếp tục lặp cho đến khi độ dài của hash_output đạt đến output_length.
Vòng lặp for i in range(block_size // 8): Duyệt qua từng phần tử trong trạng thái.
state[i].to_bytes(8, 'little'): Chuyển đổi phần tử trạng thái state[i] thành một chuỗi byte 8 byte theo thứ tự byte nhỏ (little-endian).
hash_output.extend(...): Thêm chuỗi byte này vào hash_output.
Kiểm tra độ dài if len(hash_output) < output_length: Nếu độ dài của hash_output vẫn chưa đạt đến output_length, thực hiện biến đổi Keccak-f trên trạng thái.
state = keccak_f(state): Thực hiện biến đổi Keccak-f trên trạng thái để chuẩn bị cho vòng lặp tiếp theo.
"""
    """
    hash_output[:output_length]: Trả về output_length byte đầu tiên của hash_output.
Mục đích: Đảm bảo rằng đầu ra có độ dài chính xác như yêu cầu.
"""


def sha3(message, output_length=32):
    """
    message: Thông điệp đầu vào cần được băm.
output_length: Độ dài của giá trị băm đầu ra, mặc định là 32 byte (256 bit)."""
    rate = 1088
    capacity = 512
    """
    rate: Số bit của trạng thái được sử dụng để hấp thụ dữ liệu. Trong SHA-3, rate thường là 1088 bit.
capacity: Số bit còn lại của trạng thái, không được sử dụng để hấp thụ dữ liệu. Trong SHA-3, capacity thường là 512 bit.
Tổng cộng: rate + capacity = 1600 bit, tương đương với kích thước trạng thái của Keccak.
"""
    state = absorbing_phase(message, rate, capacity)
    """
    absorbing_phase(message, rate, capacity): Hàm này thực hiện giai đoạn hấp thụ, nơi thông điệp đầu vào được kết hợp với trạng thái ban đầu thông qua các phép toán XOR và các vòng biến đổi Keccak-f.
state: Trạng thái sau khi đã hấp thụ toàn bộ thông điệp đầu vào.
"""
    return squeezing_phase(state, rate, output_length)
"""
squeezing_phase(state, rate, output_length): Hàm này thực hiện giai đoạn nén, nơi trạng thái đã được cập nhật 
trong giai đoạn hấp thụ được sử dụng để tạo ra đầu ra hàm băm có độ dài mong muốn.
Trả về: Giá trị băm có độ dài output_length.
"""

input = input("Enter data to hash: ")
input_data = input.encode('utf-8')
#input_data = b"Hello, World!" # Use a byte string for the message
final_hash = sha3(input_data)
print(f"SHA-3 hash of '{input_data.decode()}' is: {final_hash.hex()}")


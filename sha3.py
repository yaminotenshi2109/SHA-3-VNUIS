def pad_message(message, rate):
    byte_data = bytearray(message)

    # Add the padding "1" bit
    byte_data.append(0x01)

    # Add the padding zeros
    padding_length = rate // 8 - (len(byte_data) % (rate // 8))

    # Finalize padding by adding "1" at the end
    byte_data.extend([0] * (padding_length - 1))
    byte_data.append(0x80)

    return byte_data


def keccak_f(state):
    num_rounds = 24
    RC = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
        0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
    ]

    def theta(state):
        C = [0] * 5
        for x in range(5):
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]

        D = [0] * 5
        for x in range(5):
            D[x] = C[(x - 1) % 5] ^ ((C[(x + 1) % 5] << 1) | (C[(x + 1) % 5] >> (64 - 1))) & 0xFFFFFFFFFFFFFFFF

        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= D[x]
                state[x + 5 * y] &= 0xFFFFFFFFFFFFFFFF
        return state

    def rho(state):
        R = [
            [0, 36, 3, 41, 18],
            [1, 44, 10, 45, 2],
            [62, 6, 43, 15, 61],
            [28, 55, 25, 21, 56],
            [27, 20, 39, 8, 14]
        ]

        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = ((state[x + 5 * y] << R[x][y]) | (state[x + 5 * y] >> (64 - R[x][y]))) & 0xFFFFFFFFFFFFFFFF
        return state

    def pi(state):
        new_state = [0] * 25
        for x in range(5):
            for y in range(5):
                new_state[y + 5 * ((2 * x + 3 * y) % 5)] = state[x + 5 * y]
        return new_state

    def chi(state):
        for y in range(5):
            temp = [state[x + 5 * y] for x in range(5)]
            for x in range(5):
                state[x + 5 * y] ^= (~temp[(x + 1) % 5] & temp[(x + 2) % 5])
                state[x + 5 * y] &= 0xFFFFFFFFFFFFFFFF
        return state

    def iota(state, round_index):
        state[0] ^= RC[round_index]
        state[0] &= 0xFFFFFFFFFFFFFFFF
        return state

    for round_index in range(num_rounds):
        state = theta(state)
        state = rho(state)
        state = pi(state)
        state = chi(state)
        state = iota(state, round_index)

    return state


def absorbing_phase(message, rate, capacity):
    byte_data = pad_message(message, rate)
    block_size = rate // 8
    state = [0] * 25  # Initialize state as a list of 25 64-bit integers (1600 bits)

    for i in range(0, len(byte_data), block_size):
        block = byte_data[i:i + block_size]
        for j in range(block_size // 8):
            state[j] ^= int.from_bytes(block[j * 8:(j + 1) * 8], 'little')
            state[j] &= 0xFFFFFFFFFFFFFFFF  # Ensure it's 64-bit
        state = keccak_f(state)

    return state


def squeezing_phase(state, rate, output_length):
    block_size = rate // 8
    hash_output = bytearray()

    while len(hash_output) < output_length:
        for i in range(block_size // 8):
            hash_output.extend(state[i].to_bytes(8, 'little'))
        if len(hash_output) < output_length:
            state = keccak_f(state)

    return hash_output[:output_length]


def sha3(message, output_length=32):
    rate = 1088
    capacity = 512
    state = absorbing_phase(message, rate, capacity)
    return squeezing_phase(state, rate, output_length)


# Example usage
input = input("Enter data to hash: ")
input_data = input.encode('utf-8')
#input_data = b"Hello, World!" # Use a byte string for the message
final_hash = sha3(input_data)
print(f"SHA-3 hash of '{input_data.decode()}' is: {final_hash.hex()}")


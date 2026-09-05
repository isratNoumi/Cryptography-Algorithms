
#   AES-128 / 192 / 256 is:
#   Key size   : 16 bytes  / 24 bytes  / 32 bytes
#   Nr (rounds): 10        / 12        / 14
#   Round keys : 11        / 13        / 15

import os
# S-Box 
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]
# Inverse S-Box
SBOX_INV = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
]

# Round constants (RCON)
RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
        0x6c, 0xd8, 0xab, 0x4d, 0x9a]



def get_aes_settings(key_size_bits):

    if key_size_bits == 128:
        return 16, 4, 10   # 16 bytes, 4 words, 10 rounds
    elif key_size_bits == 192:
        return 24, 6, 12  
    elif key_size_bits == 256:
        return 32, 8, 14  
    else:
        raise ValueError("Key size must be 128, 192, or 256 bits.")


# ================================================================
#  GF(2^8) MULTIPLICATION  (used in MixColumns)
# ================================================================

def gf_multiply(a, b):
    """
    Multiply two bytes in GF(2^8).
    This is the math behind MixColumns -- slide page 17.
    """
    result = 0
    for _ in range(8):
        if b & 1:
            result = result ^ a          # XOR if current bit of b is 1
        if a & 0x80:
            a = ((a << 1) & 0xFF) ^ 0x1B  # reduce mod irreducible polynomial
        else:
            a = (a << 1) & 0xFF
        b = b >> 1
    return result


# ================================================================
#  STEP 1: ADD ROUND KEY
# ================================================================
# From slide page 18:
#   Input : 16-byte state + 16-byte round key
#   Output: state XOR round_key  (byte by byte)

def add_round_key(state, round_key):
    result = []
    for i in range(16):
        result.append(state[i] ^ round_key[i])
    return result


# ================================================================
#  STEP 2: BYTE SUBSTITUTION
# ================================================================
# From slide page 14:
#   Replace each byte using the S-Box lookup table.
#   Example from slide: input 0xC2 -> output 0x25

def byte_substitution(state):
    result = []
    for byte in state:
        result.append(SBOX[byte])
    return result

def byte_substitution_inv(state):
    result = []
    for byte in state:
        result.append(SBOX_INV[byte])
    return result


# ================================================================
#  STEP 3: SHIFT ROWS
# ================================================================
# From slide page 16:
#   Row 0: no shift
#   Row 1: shift left by 1
#   Row 2: shift left by 2
#   Row 3: shift left by 3
#
# State layout (column-major, 4x4):
#   index = col*4 + row
#   so row 0 = indices 0,4,8,12
#      row 1 = indices 1,5,9,13
#      row 2 = indices 2,6,10,14
#      row 3 = indices 3,7,11,15

def shift_rows(state):
    s = list(state)
    s[1],  s[5],  s[9],  s[13] = state[5],  state[9],  state[13], state[1]
    s[2],  s[6],  s[10], s[14] = state[10], state[14], state[2],  state[6]
    s[3],  s[7],  s[11], s[15] = state[15], state[3],  state[7],  state[11]
    return s

def shift_rows_inv(state):
    s = list(state)
    s[1],  s[5],  s[9],  s[13] = state[13], state[1],  state[5],  state[9]
    s[2],  s[6],  s[10], s[14] = state[10], state[14], state[2],  state[6]
    s[3],  s[7],  s[11], s[15] = state[7],  state[11], state[15], state[3]
    return s


# ================================================================
#  STEP 4: MIX COLUMNS
# ================================================================
# From slide page 17:
#   Each 4-byte column is multiplied by the fixed matrix:
#   | 02 03 01 01 |
#   | 01 02 03 01 |
#   | 01 01 02 03 |
#   | 03 01 01 02 |
#
# Multiplication is in GF(2^8) -- that's what gf_multiply() does.

def mix_columns(state):
    result = list(state)
    for col in range(4):
        i = col * 4                # starting index of this column
        s0 = state[i]
        s1 = state[i + 1]
        s2 = state[i + 2]
        s3 = state[i + 3]
        result[i]     = gf_multiply(0x02, s0) ^ gf_multiply(0x03, s1) ^ s2              ^ s3
        result[i + 1] = s0              ^ gf_multiply(0x02, s1) ^ gf_multiply(0x03, s2) ^ s3
        result[i + 2] = s0              ^ s1              ^ gf_multiply(0x02, s2) ^ gf_multiply(0x03, s3)
        result[i + 3] = gf_multiply(0x03, s0) ^ s1              ^ s2              ^ gf_multiply(0x02, s3)
    return result

def mix_columns_inv(state):
    result = list(state)
    for col in range(4):
        i = col * 4
        s0 = state[i]
        s1 = state[i + 1]
        s2 = state[i + 2]
        s3 = state[i + 3]
        result[i]     = gf_multiply(0x0e, s0) ^ gf_multiply(0x0b, s1) ^ gf_multiply(0x0d, s2) ^ gf_multiply(0x09, s3)
        result[i + 1] = gf_multiply(0x09, s0) ^ gf_multiply(0x0e, s1) ^ gf_multiply(0x0b, s2) ^ gf_multiply(0x0d, s3)
        result[i + 2] = gf_multiply(0x0d, s0) ^ gf_multiply(0x09, s1) ^ gf_multiply(0x0e, s2) ^ gf_multiply(0x0b, s3)
        result[i + 3] = gf_multiply(0x0b, s0) ^ gf_multiply(0x0d, s1) ^ gf_multiply(0x09, s2) ^ gf_multiply(0x0e, s3)
    return result


# ================================================================
#  KEY EXPANSION (KEY SCHEDULE)
# ================================================================
# From slide pages 28-29:
#   The original key is expanded into (Nr + 1) round keys.
#   Each round key is 16 bytes (128 bits).
#
#   G-Function (applied every Nk words):
#     Step 1: RotWord  -- rotate 4 bytes left: [a0,a1,a2,a3] -> [a1,a2,a3,a0]
#     Step 2: SubWord  -- apply S-Box to each byte
#     Step 3: XOR with RCON (round constant)

def key_expansion(key_bytes, Nk, Nr):
   
    expanded = list(key_bytes)
    total_bytes = (Nr + 1) * 16
    i = Nk

    while len(expanded) < total_bytes:
        # Take the last 4 bytes (last word)
        word = expanded[-4:]

        if i % Nk == 0:
            # ── G-Function ──
            # Step 1: RotWord 
            word = word[1:] + word[:1]
            # Step 2: SubWord
            word = [SBOX[b] for b in word]
            # Step 3: XOR first byte with RCON
            word[0] = word[0] ^ RCON[i // Nk]

        elif Nk > 6 and i % Nk == 4:
            # Extra SubWord for AES-256 only
            word = [SBOX[b] for b in word]

        new_word = []
        for j in range(4):
            new_word.append(expanded[len(expanded) - Nk * 4 + j] ^ word[j])

        expanded = expanded + new_word
        i = i + 1

    return expanded


def get_round_keys(key_bytes, Nk, Nr):
    expanded = key_expansion(key_bytes, Nk, Nr)
    round_keys = []
    for r in range(Nr + 1):
        start = r * 16
        round_keys.append(expanded[start : start + 16])
    return round_keys


def encrypt_block(block, round_keys, Nr):
    state = list(block)

    
    state = add_round_key(state, round_keys[0])

    for round_num in range(1, Nr):
        state = byte_substitution(state)  
        state = shift_rows(state)         
        state = mix_columns(state)         
        state = add_round_key(state, round_keys[round_num])  

    state = byte_substitution(state)       
    state = shift_rows(state)             
    state = add_round_key(state, round_keys[Nr])  

    return bytes(state)




def decrypt_block(block, round_keys, Nr):
    state = list(block)

    state = add_round_key(state, round_keys[Nr])
    state = shift_rows_inv(state)
    state = byte_substitution_inv(state)

    for round_num in range(Nr - 1, 0, -1):
        state = add_round_key(state, round_keys[round_num])
        state = mix_columns_inv(state)
        state = shift_rows_inv(state)
        state = byte_substitution_inv(state)

    state = add_round_key(state, round_keys[0])

    return bytes(state)


def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding.")
    return data[:-pad_len]


def aes_encrypt(plaintext_str, key_bytes, Nk, Nr):
    round_keys = get_round_keys(key_bytes, Nk, Nr)
    data       = pad(plaintext_str.encode())
    result     = b""
    for i in range(0, len(data), 16):
        result = result + encrypt_block(data[i : i + 16], round_keys, Nr)
    return result

def aes_decrypt(ciphertext_bytes, key_bytes, Nk, Nr):
    round_keys = get_round_keys(key_bytes, Nk, Nr)
    result     = b""
    for i in range(0, len(ciphertext_bytes), 16):
        result = result + decrypt_block(ciphertext_bytes[i : i + 16], round_keys, Nr)
    return unpad(result).decode()



def print_round_keys(key_bytes, Nk, Nr):
    round_keys = get_round_keys(key_bytes, Nk, Nr)
    print(f"\n  Total round keys: {Nr + 1}  (Round 0 is the original key)")
    print(f"  {'Round':<10} {'Round Key (hex)'}")
    print("  " + "-" * 50)
    for r in range(Nr + 1):
        label = f"Round {r}"
        if r == 0:
            label = "Round 0 (original key)"
        rk_hex = bytes(round_keys[r]).hex().upper()
        # print in groups of 2 for readability
        grouped = " ".join(rk_hex[j:j+2] for j in range(0, len(rk_hex), 2))
        print(f"  {label:<24} {grouped}")


def run_aes():
    key        = None
    key_bits   = None
    Nk         = None
    Nr         = None
    ciphertext = None

    while True:
        key_info = f"AES-{key_bits}, Key: {key.hex().upper()}" if key else "no key yet"
        print(f"\n--- AES  [{key_info}] ---")
        print("1. Choose AES variant and generate key")
        print("2. Encrypt")
        print("3. Decrypt")
        print("4. Show all round keys")
        print("5. Back")
        choice = input("Choice: ").strip()


        if choice == "1":
            print("\n  Select AES variant:")
            print("  [1] AES-128  (10 rounds, 16-byte key)")
            print("  [2] AES-192  (12 rounds, 24-byte key)")
            print("  [3] AES-256  (14 rounds, 32-byte key)")
            variant = input("  Choice: ").strip()

            if variant == "1":
                key_bits = 128
            elif variant == "2":
                key_bits = 192
            elif variant == "3":
                key_bits = 256
            else:
                print("  [!] Invalid choice.")
                continue

            key_size_bytes, Nk, Nr = get_aes_settings(key_bits)
            key = os.urandom(key_size_bytes)

            print(f"\n  AES-{key_bits} selected.")
            print(f"  Rounds     : {Nr}")
            print(f"  Round keys : {Nr + 1} (Round 0 through Round {Nr})")
            print(f"  Key (hex)  : {key.hex().upper()}")


        elif choice == "2":
            if key is None:
                print("  [!] Please generate a key first (option 1).")
                continue
            plaintext = input("  Plaintext: ").strip()
            if plaintext == "":
                print("  [!] Plaintext cannot be empty.")
                continue
            try:
                ciphertext = aes_encrypt(plaintext, key, Nk, Nr)
                print(f"  Ciphertext (hex): {ciphertext.hex().upper()}")
            except Exception as e:
                print(f"  [!] Encryption error: {e}")

        elif choice == "3":
            if key is None:
                print("  [!] Please generate a key first (option 1).")
                continue
            if ciphertext is None:
                print("  [!] No ciphertext available. Please encrypt something first.")
                continue
            try:
                plaintext = aes_decrypt(ciphertext, key, Nk, Nr)
                print(f"  Plaintext: {plaintext}")
            except Exception as e:
                print(f"  [!] Decryption error: {e}")

        # ── Option 4: Show all round keys ──
        elif choice == "4":
            if key is None:
                print("  [!] Please generate a key first (option 1).")
                continue
            print_round_keys(key, Nk, Nr)

        elif choice == "5":
            break
        else:
            print("  [!] Invalid choice.")

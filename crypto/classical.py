import string


def validate_sub_key(key):
    key = key.upper()
    if len(key) != 26:
        raise ValueError("Key must be exactly 26 characters long.")
    if sorted(key) != list(string.ascii_uppercase):
        raise ValueError("Key must be a permutation of A-Z (no duplicates, no missing letters).")
    return key


def sub_encrypt(plaintext, key):
    key = validate_sub_key(key)
    result = ""
    for ch in plaintext:
        if ch.upper() in string.ascii_uppercase:
            idx = ord(ch.upper()) - ord('A') 
            enc = key[idx]
            result += enc if ch.isupper() else enc.lower() 
        else:
            result += ch          
    return result


def sub_decrypt(ciphertext, key):
    key = validate_sub_key(key)
    reverse_key = [''] * 26
    for i, ch in enumerate(key):
        reverse_key[ord(ch) - ord('A')] = chr(ord('A') + i)
    result = ""
    for ch in ciphertext:
        if ch.upper() in string.ascii_uppercase:
            idx = ord(ch.upper()) - ord('A')
            dec = reverse_key[idx]
            result += dec if ch.isupper() else dec.lower()
        else:
            result += ch
    return result


def frequency_analysis(text):
    text = text.upper()
    counts = {}
    total = 0
    for ch in text:
        if ch in string.ascii_uppercase:
            counts[ch] = counts.get(ch, 0) + 1
            total += 1

    if total == 0:
        print("No alphabetic characters found.")
        return

    print("\nFrequency Analysis")
    sorted_counts = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    for letter, count in sorted_counts:
        percent = count / total * 100
        print(f"  {letter} : {count} ({percent:.1f}%)")
    print("Hint: In English, most common letters are E, T, A, O, I, N")


def brute_force_caesar(ciphertext):
    print("\n  === Brute Force (Caesar shifts) ===")
    for shift in range(1, 26):
        attempt = ""
        for ch in ciphertext:
            if ch.upper() in string.ascii_uppercase:
                base = ord('A') if ch.isupper() else ord('a')
                attempt += chr((ord(ch) - base - shift) % 26 + base)
            else:
                attempt += ch
        print(f"Shift {shift:2d}: {attempt}")


def run_substitution_cipher():
    print("\n--- Substitution Cipher ---")
    plaintext = input("Enter plaintext: ").strip()
    if not plaintext:
        print("Error: Plaintext cannot be empty.")
        return

    key = input("Enter 26-letter key: ").strip()
    if not key:
        print("Error: Key cannot be empty.")
        return

    try:
        ciphertext = sub_encrypt(plaintext, key)
        decrypted  = sub_decrypt(ciphertext, key)
        print(f"\nCiphertext : {ciphertext}")
        print(f"Decrypted  : {decrypted}")
        frequency_analysis(ciphertext)
        brute_force_caesar(ciphertext)
    except ValueError as e:
        print(f"Error: {e}")


def parse_permutation_key(prompt, n=None):
    raw = input(prompt).strip()
    if not raw:
        raise ValueError("Key cannot be empty.")
    try:
        key = list(map(int, raw.split()))
    except ValueError:
        raise ValueError("Key must contain only integers separated by spaces.")
    if n is not None and len(key) != n:
        raise ValueError(f"Expected {n} values, got {len(key)}.")
    expected = list(range(len(key)))
    if sorted(key) != expected:
        raise ValueError(f"Key must be a permutation of 0 to {len(key)-1} (no duplicates, no missing).")
    return key


def double_transpose_encrypt(plaintext, row_key, col_key):
    cols = len(col_key)
    rows = len(row_key)
    total = rows * cols
    if len(plaintext) < total:
        plaintext += 'x' * (total - len(plaintext))


    grid = []
    for r in range(rows):
        grid.append(list(plaintext[r * cols : (r + 1) * cols]))

    # Step 3: permute rows 
    grid = [grid[r] for r in row_key]

    # Step 4: permute columns
    grid = [[row[c] for c in col_key] for row in grid]

    # Step 5: read row by row to get ciphertext
    result = ""
    for row in grid:
        result += "".join(row)
    return result


def double_transpose_decrypt(ciphertext, row_key, col_key):
    cols = len(col_key)
    rows = len(row_key)

    grid = []
    for r in range(rows):
        grid.append(list(ciphertext[r * cols : (r + 1) * cols]))

    # undo column permutation
    inv_col = [0] * cols
    for new, old in enumerate(col_key):
        inv_col[old] = new
    grid = [[row[c] for c in inv_col] for row in grid]

    # undo row permutation 
    inv_row = [0] * rows
    for new, old in enumerate(row_key):
        inv_row[old] = new
    grid = [grid[r] for r in inv_row]

    # Step 4: read row by row
    result = ""
    for row in grid:
        result += "".join(row)
    return result


def run_double_transposition():
    print("\n--- Double Transposition Cipher ---")

    plaintext = input("Enter plaintext: ").strip()
    if not plaintext:
        print("Error: Plaintext cannot be empty.")
        return


    n_rows = int(input("How many rows (key 1 size)? ").strip())
    row_key = parse_permutation_key(
            f"Enter row permutation ({n_rows} values, 0 to {n_rows-1}), e.g. '2 4 0 3 1': ", n=n_rows
    )

    n_cols = int(input("How many columns (key 2 size)? ").strip())
    col_key = parse_permutation_key(
        f"Enter column permutation ({n_cols} values, 0 to {n_cols-1}), e.g. '0 2 1': ", n=n_cols
    )

    ciphertext = double_transpose_encrypt(plaintext, row_key, col_key)
    decrypted  = double_transpose_decrypt(ciphertext, row_key, col_key)
    print(f"\nCiphertext : {ciphertext}")
    print(f"Decrypted  : {decrypted}")
    frequency_analysis(ciphertext)

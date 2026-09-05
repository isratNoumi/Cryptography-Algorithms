import random
import math


FIXED_BASES_64BIT = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]


def is_prime(n):
    if n < 2:
        return False

    if n in (2, 3):
        return True

    if n % 2 == 0:
        return False

    # Step 1: Take n-1 =  2^k * m 
    k = 0
    m = n - 1
    while m % 2 == 0:
        m = m // 2
        k = k + 1

    #Step 2: Find a such that 1 < a < n - 1
    if n < (1 << 64):
        bases = FIXED_BASES_64BIT
    else:
        bases = [random.randrange(2, n - 1) for _ in range(20)]

    for a in bases:
        if a >= n:
            continue

        # Step 3: Compute b0 = a^m mod n
        b = pow(a, m, n)

        if b == 1 or b == n - 1:
            continue

        # Step 4: Square up to k-1 times
        passed = False
        for _ in range(k - 1):
            b = pow(b, 2, n)

            if b == n - 1:
                passed = True  
                break

            if b == 1:
                return False    # hit 1 without -1 first

        if not passed:
            return False

    return True    


def generate_prime(bits):

    low  = 2 ** (bits - 1) 
    high = 2 ** bits - 1

    if low % 2 == 0:
        low = low + 1

    while True:
        n = random.randrange(low, high + 1, 2)
        if is_prime(n):
            return n


def mod_inverse(e, phi):
    print(f"\n  Finding d such that {e} * d = 1 mod {phi}")
    print(f"  GCD({phi}, {e}) = 1\n")
    col = 12
    print(f"  {'Step':>4} | {'g':>4} | {'r1':>{col}} | {'r2':>{col}} | {'r':>{col}} | {'t0':>{col}} | {'t1':>{col}} | {'t2':>{col}}")
    print(f"  {'-'*4}-+-{'-'*4}-+-{'-'*col}-+-{'-'*col}-+-{'-'*col}-+-{'-'*col}-+-{'-'*col}-+-{'-'*col}")
 
    r1 = phi
    r2 = e
    t0 = 0 
    t1 = 1
    step = 1
 
    while r2 != 0:
        g  = r1 // r2
        r  = r1 % r2
        t2 = t0 - g * t1
 
        print(f"  {step:>4} | {g:>4} | {r1:>{col}} | {r2:>{col}} | {r:>{col}} | {t0:>{col}} | {t1:>{col}} | {t2:>{col}}")
        r1 = r2
        r2 = r
        t0 = t1
        t1 = t2
        step = step + 1
 
    if r1 != 1:
        raise ValueError("e and phi are not coprime — cannot find d.")
 
    d = t0 % phi
    return d
 



rsa_keys = {
    "p": None, "q": None, "n": None,
    "e": None, "d": None, "phi": None,
    "last_cipher": None,
    "bits": None
}



#  KEY GENERATION  
def rsa_generate_keys(bits):
    half = bits // 2
    print(f"\n  Generating two distinct {half}-bit primes p and q")

    # Step 1: Two large distinct primes p and q
    p = generate_prime(half)
    q = p
    while q == p:
        q = generate_prime(half)

    # Step 2: N = p * q
    n = p * q

    # Step 3: phi(N) = (p-1)(q-1)
    phi = (p - 1) * (q - 1)

    # Step 4: choose e such that e is relatively prime to (p-1)(q-1)
    e = 65537
    while math.gcd(e, phi) != 1:
        e = e + 2  

    # Step 5: find d such that e * d = 1 mod phi
    d = mod_inverse(e, phi)

    rsa_keys.update({
        "p": p, "q": q, "n": n,
        "e": e, "d": d, "phi": phi,
        "last_cipher": None,
        "bits": bits
    })

    print(f"\n  --- Key Generation Steps ---")
    print(f"  Step 1: p   = {p}")
    print(f"          q   = {q}")
    print(f"  Step 2: N   = p * q = {n}")
    print(f"  Step 3: phi = (p-1) * (q-1) = {p-1} * {q-1} = {phi}")
    print(f"  Step 4: e   = {e}   (gcd(e, phi) = {math.gcd(e, phi)}, must be 1)")
    print(f"  Step 5: d   = {d}   (e*d mod phi = {(e*d) % phi}, must be 1)")
    print(f"\n  Public key  (N, e) = ({n}, {e})")
    print(f"  Private key (d)    = {d}")



#  ENCRYPTION  
def rsa_encrypt(plaintext, e=None, n=None):
    if e is None:
        e = rsa_keys["e"]
    if n is None:
        n = rsa_keys["n"]

    print(f"\nEncryption")
    print(f"  Formula   : C = M^e mod N")
    print(f"  Public key: N = {n},  e = {e}\n")

    cipher = []
    for ch in plaintext:
        m = ord(ch)
        if m >= n:
            raise ValueError(
                f"  Character '{ch}' has ASCII value {m} which is >= N ({n}).\n"
            )
        c = pow(m, e, n)
        print(f"  '{ch}' -> ASCII {m} -> C = {m}^{e} mod {n} = {c}")
        cipher.append(c)

    return cipher



#  DECRYPTION  
def rsa_decrypt(cipher, d=None, n=None):
    if d is None:
        d = rsa_keys["d"]
    if n is None:
        n = rsa_keys["n"]

    print(f"\n Decryption")
    print(f"  Formula    : M = C^d mod N")
    print(f"  Private key: d = {d},  N = {n}\n")

    result = ""
    for c in cipher:
        m = pow(c, d, n)
        ch = chr(m)
        print(f"  C = {c} -> M = {c}^{d} mod {n} = {m} -> '{ch}'")
        result = result + ch

    return result



#  FACTORIZATION ATTACK  
#  Uses Fermat's method: if N = a^2 - b^2 then N = (a-b)(a+b)

def factorization_attack(n):
    print(f"\n  --- Factorization Attack on N = {n} ---")

    if n % 2 == 0:
        print(f"  N is even. Trivial factors: 2 x {n // 2}")
        return {"success": True, "p": 2, "q": n // 2, "steps": 0, "verified": True}

    # start a from ceil(sqrt(n)) and move upward
    a = math.isqrt(n)
    if a * a < n:
        a = a + 1

    found = False
    result_dict = {"success": False, "steps": 500000}
    for step in range(500000):
        b2 = a * a - n
        b  = math.isqrt(b2)
        if b * b == b2:
            p = a - b
            q = a + b
            print(f"  Found after {step + 1} step(s)!")
            print(f"  a = {a}")
            print(f"  b = {b}  (b^2 = a^2 - N = {a*a} - {n} = {b2})")
            print(f"  p = a - b = {a} - {b} = {p}")
            print(f"  q = a + b = {a} + {b} = {q}")
            print(f"  Verify: p * q = {p} * {q} = {p*q}  (N = {n})")
            print(f"\n  Attacker now knows p and q, so they can compute:")
            print(f"  phi = (p-1)*(q-1) = {p-1} * {q-1} = {(p-1)*(q-1)}")
            print(f"  d   = e^-1 mod phi  ->  private key recovered -> RSA broken!")
            found = True
            result_dict = {
                "success": True,
                "a": a,
                "b": b,
                "p": p,
                "q": q,
                "steps": step + 1,
                "verified": (p * q == n)
            }
            break
        a = a + 1

    if not found:
        print(f"  Could not factor N in 500,000 steps.")
    return result_dict


def run_rsa():
    print("\n--- RSA Cryptography ---")

    while True:
        print("\nOptions:")
        print("  1. Generate Keys")
        print("  2. Encrypt")
        print("  3. Decrypt")
        print("  4. Factorization Attack  (optional)")
        print("  5. Back")
        choice = input("Choice: ").strip()

        if choice == "1":
            print("\nSelect key size:")
            print("  1. 512-bit")
            print("  2. 1024-bit")
            print("  3. Random  (16 to 1023, excluding 512 and 1024)")
            ks = input("Choice: ").strip()

            if ks == "1":
                bits = 512
            elif ks == "2":
                bits = 1024
            elif ks == "3":
                pool = list(range(16, 512)) + list(range(513, 1024))
                bits = random.choice(pool)
                #bits = 16
                print(f"  Randomly chosen: {bits} bits")
            else:
                print("Invalid choice. Pick 1, 2, or 3.")
                continue

            rsa_generate_keys(bits)

        elif choice == "2":
            if rsa_keys["n"] is None:
                print("Generate keys first (option 1).")
                continue
            plaintext = input("Enter plaintext string: ").strip()
            if not plaintext:
                print("Plaintext cannot be empty.")
                continue
            try:
                cipher = rsa_encrypt(plaintext)
                rsa_keys["last_cipher"] = cipher
                print(f"\n  Ciphertext (integers): {cipher}")

                # Format as continuous hex and single integer
                bits = rsa_keys.get("bits", 1024)
                hex_len = (bits + 3) // 4
                hex_chunks = [f"{c:0{hex_len}x}" for c in cipher]
                continuous_hex = "".join(hex_chunks)
                single_int = int(continuous_hex, 16)

                print(f"  Ciphertext (continuous hex)      : {continuous_hex.upper()}")
                print(f"  Ciphertext (single giant integer): {single_int}")
            except ValueError as ex:
                print(f"Error: {ex}")

        elif choice == "3":
            if rsa_keys["n"] is None:
                print("Generate keys first (option 1).")
                continue
            
            print("\nDecryption Input Mode:")
            print("  1. Decrypt last encrypted message automatically")
            print("  2. Input custom ciphertext (hex or single giant integer)")
            dec_choice = input("  Choice: ").strip()

            cipher_to_decrypt = None
            if dec_choice == "1":
                if rsa_keys["last_cipher"] is None:
                    print("  No previous ciphertext found. Encrypt something first.")
                    continue
                cipher_to_decrypt = rsa_keys["last_cipher"]
            elif dec_choice == "2":
                user_input = input("  Enter Ciphertext: ").strip()
                if not user_input:
                    print("  Input cannot be empty.")
                    continue
                try:
                    bits = rsa_keys.get("bits", 1024)
                    hex_len = (bits + 3) // 4

                    # check if the input is exclusively digits
                    if user_input.isdigit():
                        val = int(user_input)
                        raw_hex = f"{val:x}"
                        remainder = len(raw_hex) % hex_len
                        if remainder != 0:
                            raw_hex = "0" * (hex_len - remainder) + raw_hex
                    else:
                        raw_hex = user_input.lower().replace("0x", "").replace(" ", "")

                    # Split into chunks of hex_len
                    chunks = [raw_hex[i : i + hex_len] for i in range(0, len(raw_hex), hex_len)]
                    # Convert chunks to integers
                    cipher_to_decrypt = [int(chk, 16) for chk in chunks if chk.strip()]
                    if not cipher_to_decrypt:
                        print("  Invalid ciphertext format.")
                        continue
                except Exception as ex:
                    print(f"  Error parsing custom ciphertext: {ex}")
                    continue
            else:
                print("  Invalid choice.")
                continue

            try:
                msg = rsa_decrypt(cipher_to_decrypt)
                print(f"\n  Decrypted message: {msg}")
            except Exception as ex:
                print(f"  Decryption error: {ex}")

        elif choice == "4":
            if rsa_keys["n"] is None:
                print("Generate keys first (option 1).")
                continue
            factorization_attack(rsa_keys["n"])

        elif choice == "5":
            break
        else:
            print("Invalid choice. Pick 1 to 5.")
import os
import math
import string
from flask import Flask, jsonify, render_template, request

# Import our modular cryptography package
from crypto import (
    sub_encrypt, sub_decrypt,
    double_transpose_encrypt, double_transpose_decrypt,
    validate_sub_key, parse_permutation_key,
    generate_round_keys, des_encrypt, des_decrypt, bits_to_bytes,
    get_aes_settings, aes_encrypt, aes_decrypt, get_round_keys,
    rsa_generate_keys, rsa_encrypt, rsa_decrypt, rsa_keys, factorization_attack,
    point_add, scalar_mul, list_subgroup, is_on_curve
)

app = Flask(__name__)

# Frequency analysis helper
def get_frequency_analysis(text):
    text = text.upper()
    counts = {}
    total = 0
    for ch in text:
        if ch in string.ascii_uppercase:
            counts[ch] = counts.get(ch, 0) + 1
            total += 1
    
    analysis = []
    # Fill in all A-Z
    for ch in string.ascii_uppercase:
        count = counts.get(ch, 0)
        percentage = (count / total * 100) if total > 0 else 0.0
        analysis.append({
            "letter": ch,
            "count": count,
            "percentage": round(percentage, 2)
        })
    # Sort descending by count
    analysis_sorted = sorted(analysis, key=lambda x: x["count"], reverse=True)
    return {
        "distribution": analysis,  # A-Z order
        "sorted": analysis_sorted   # Descending count order
    }

# Caesar brute force helper
def get_caesar_brute_force(ciphertext):
    solutions = []
    for shift in range(1, 26):
        attempt = ""
        for ch in ciphertext:
            if ch.upper() in string.ascii_uppercase:
                base = ord('A') if ch.isupper() else ord('a')
                attempt += chr((ord(ch) - base - shift) % 26 + base)
            else:
                attempt += ch
        solutions.append({"shift": shift, "text": attempt})
    return solutions

# ----------------- ROUTES -----------------

def parse_int(value, default=None):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default

@app.route('/')
def index():
    return render_template('index.html')


# 1a. Classical - Substitution Cipher
@app.route('/api/classical/substitution', methods=['POST'])
def api_substitution():
    data = request.json or {}
    plaintext = data.get("plaintext", "").strip()
    key = data.get("key", "").strip()
    action = data.get("action", "encrypt")  # 'encrypt' or 'decrypt'

    if not plaintext or not key:
        return jsonify({"error": "Plaintext/ciphertext and key cannot be empty"}), 400

    try:
        validated_key = validate_sub_key(key)
    except ValueError as ex:
        return jsonify({"error": str(ex)}), 400

    try:
        if action == "encrypt":
            ciphertext = sub_encrypt(plaintext, validated_key)
            decrypted = sub_decrypt(ciphertext, validated_key)
            freq = get_frequency_analysis(ciphertext)
            caesar = get_caesar_brute_force(ciphertext)
            return jsonify({
                "plaintext": plaintext,
                "ciphertext": ciphertext,
                "decrypted": decrypted,
                "frequency": freq,
                "caesar_brute_force": caesar
            })
        else:
            decrypted = sub_decrypt(plaintext, validated_key)
            freq = get_frequency_analysis(plaintext)
            return jsonify({
                "ciphertext": plaintext,
                "decrypted": decrypted,
                "frequency": freq
            })
    except Exception as ex:
        return jsonify({"error": str(ex)}), 500


# 1b. Classical - Double Transposition Cipher
@app.route('/api/classical/double_transposition', methods=['POST'])
def api_double_transposition():
    data = request.json or {}
    plaintext = data.get("plaintext", "").strip()
    row_key_str = data.get("row_key", "").strip()
    col_key_str = data.get("col_key", "").strip()
    action = data.get("action", "encrypt")

    if not plaintext or not row_key_str or not col_key_str:
        return jsonify({"error": "Plaintext, Row Key and Column Key cannot be empty"}), 400

    try:
        # Permutation keys parse helper - support space and comma separated
        row_tokens = row_key_str.replace(',', ' ').split()
        col_tokens = col_key_str.replace(',', ' ').split()
        row_key = list(map(int, row_tokens))
        col_key = list(map(int, col_tokens))
    except ValueError:
        return jsonify({"error": "Keys must contain only integers separated by spaces or commas"}), 400

    if len(row_key) < 2:
        return jsonify({"error": "Row key must contain at least 2 values (e.g. 2 4 0 3 1)"}), 400
    if len(col_key) < 2:
        return jsonify({"error": "Column key must contain at least 2 values (e.g. 0 2 1)"}), 400

    # Key validations
    if sorted(row_key) != list(range(len(row_key))):
        return jsonify({"error": f"Row key must be a permutation of 0 to {len(row_key)-1}"}), 400
    if sorted(col_key) != list(range(len(col_key))):
        return jsonify({"error": f"Column key must be a permutation of 0 to {len(col_key)-1}"}), 400

    try:
        if action == "encrypt":
            ciphertext = double_transpose_encrypt(plaintext, row_key, col_key)
            decrypted = double_transpose_decrypt(ciphertext, row_key, col_key)
            freq = get_frequency_analysis(ciphertext)
            return jsonify({
                "plaintext": plaintext,
                "ciphertext": ciphertext,
                "decrypted": decrypted,
                "frequency": freq
            })
        else:
            decrypted = double_transpose_decrypt(plaintext, row_key, col_key)
            freq = get_frequency_analysis(plaintext)
            return jsonify({
                "ciphertext": plaintext,
                "decrypted": decrypted,
                "frequency": freq
            })
    except Exception as ex:
        return jsonify({"error": str(ex)}), 500


# 2a. Symmetric - DES
@app.route('/api/symmetric/des/generate_key', methods=['GET'])
def api_des_generate_key():
    key_bytes = os.urandom(8)
    return jsonify({
        "key_hex": key_bytes.hex().upper()
    })

@app.route('/api/symmetric/des/execute', methods=['POST'])
def api_des_execute():
    data = request.json or {}
    plaintext = data.get("plaintext", "").strip()
    key_hex = data.get("key_hex", "").strip()
    action = data.get("action", "encrypt")

    if not plaintext or not key_hex:
        return jsonify({"error": "Plaintext/ciphertext and Key cannot be empty"}), 400

    try:
        key_bytes = bytes.fromhex(key_hex)
        if len(key_bytes) != 8:
            return jsonify({"error": "DES key must be exactly 8 bytes (16 hex chars)"}), 400
    except ValueError:
        return jsonify({"error": "Invalid hex format for Key"}), 400

    try:
        round_keys = generate_round_keys(key_bytes)
        # Format round keys for UI display
        formatted_round_keys = []
        for i, rk in enumerate(round_keys):
            rk_bytes = bits_to_bytes(rk + [0]*8)[:6]
            formatted_round_keys.append({
                "round": i + 1,
                "hex": " ".join(f"{b:02X}" for b in rk_bytes)
            })

        if action == "encrypt":
            ciphertext_bytes = des_encrypt(plaintext, key_bytes)
            ciphertext_hex = ciphertext_bytes.hex().upper()
            decrypted = des_decrypt(ciphertext_bytes, key_bytes)
            return jsonify({
                "plaintext": plaintext,
                "ciphertext_hex": ciphertext_hex,
                "decrypted": decrypted,
                "round_keys": formatted_round_keys
            })
        else:
            try:
                ct_bytes = bytes.fromhex(plaintext)
            except ValueError:
                return jsonify({"error": "Ciphertext must be a valid hex string for decryption"}), 400
            decrypted = des_decrypt(ct_bytes, key_bytes)
            return jsonify({
                "ciphertext_hex": plaintext,
                "decrypted": decrypted,
                "round_keys": formatted_round_keys
            })
    except Exception as ex:
        return jsonify({"error": str(ex)}), 500


# 2b. Symmetric - AES
@app.route('/api/symmetric/aes/generate_key', methods=['POST'])
def api_aes_generate_key():
    data = request.json or {}
    bits = data.get("bits", 128)
    if bits not in (128, 192, 256):
        return jsonify({"error": "AES key size must be 128, 192, or 256 bits"}), 400
    key_bytes = os.urandom(bits // 8)
    return jsonify({
        "key_hex": key_bytes.hex().upper(),
        "bits": bits
    })

@app.route('/api/symmetric/aes/execute', methods=['POST'])
def api_aes_execute():
    data = request.json or {}
    plaintext = data.get("plaintext", "").strip()
    key_hex = data.get("key_hex", "").strip()
    bits = data.get("bits", 128)
    action = data.get("action", "encrypt")

    if not plaintext or not key_hex:
        return jsonify({"error": "Plaintext/ciphertext and Key cannot be empty"}), 400

    try:
        key_bytes = bytes.fromhex(key_hex)
        required_len = bits // 8
        if len(key_bytes) != required_len:
            return jsonify({"error": f"Key size mismatch. Expected {required_len} bytes for AES-{bits}"}), 400
    except ValueError:
        return jsonify({"error": "Invalid hex format for Key"}), 400

    try:
        key_size_bytes, Nk, Nr = get_aes_settings(bits)
        round_keys = get_round_keys(key_bytes, Nk, Nr)
        
        # Round keys hex list
        formatted_round_keys = []
        for r, rk in enumerate(round_keys):
            rk_hex = bytes(rk).hex().upper()
            formatted_round_keys.append({
                "round": r,
                "hex": " ".join(rk_hex[j:j+2] for j in range(0, len(rk_hex), 2))
            })

        if action == "encrypt":
            ciphertext_bytes = aes_encrypt(plaintext, key_bytes, Nk, Nr)
            ciphertext_hex = ciphertext_bytes.hex().upper()
            decrypted = aes_decrypt(ciphertext_bytes, key_bytes, Nk, Nr)
            return jsonify({
                "plaintext": plaintext,
                "ciphertext_hex": ciphertext_hex,
                "decrypted": decrypted,
                "round_keys": formatted_round_keys
            })
        else:
            try:
                ct_bytes = bytes.fromhex(plaintext)
            except ValueError:
                return jsonify({"error": "Ciphertext must be a valid hex string for decryption"}), 400
            decrypted = aes_decrypt(ct_bytes, key_bytes, Nk, Nr)
            return jsonify({
                "ciphertext_hex": plaintext,
                "decrypted": decrypted,
                "round_keys": formatted_round_keys
            })
    except Exception as ex:
        return jsonify({"error": str(ex)}), 500


# 3a. Public Key - RSA
@app.route('/api/public/rsa/generate_keys', methods=['POST'])
def api_rsa_generate_keys():
    data = request.json or {}
    bits = data.get("bits", 512)
    try:
        rsa_generate_keys(bits)
        # Gather key steps state
        return jsonify({
            "p": str(rsa_keys["p"]),
            "q": str(rsa_keys["q"]),
            "n": str(rsa_keys["n"]),
            "phi": str(rsa_keys["phi"]),
            "e": rsa_keys["e"],
            "d": str(rsa_keys["d"]),
            "bits": bits
        })
    except Exception as ex:
        return jsonify({"error": str(ex)}), 500

@app.route('/api/public/rsa/encrypt', methods=['POST'])
def api_rsa_encrypt():
    data = request.json or {}
    plaintext = data.get("plaintext", "").strip()
    e = parse_int(data.get("e", rsa_keys.get("e")))
    n = parse_int(data.get("n", rsa_keys.get("n")))
    bits = parse_int(data.get("bits", rsa_keys.get("bits", 512)), 512)

    if not plaintext:
        return jsonify({"error": "Plaintext cannot be empty"}), 400
    if not e or not n:
        return jsonify({"error": "RSA Keys (N, e) are uninitialized. Generate keys first!"}), 400

    try:
        # Set keys
        temp_keys = dict(rsa_keys)
        rsa_keys["e"] = e
        rsa_keys["n"] = n
        
        cipher_ints = rsa_encrypt(plaintext, e, n)
        
        # Continuous hex & giant int formatting
        hex_len = (bits + 3) // 4
        hex_chunks = [f"{c:0{hex_len}x}" for c in cipher_ints]
        continuous_hex = "".join(hex_chunks)
        single_int = int(continuous_hex, 16)

        return jsonify({
            "cipher_ints": cipher_ints,
            "continuous_hex": continuous_hex.upper(),
            "single_int": str(single_int)
        })
    except Exception as ex:
        return jsonify({"error": str(ex)}), 500

@app.route('/api/public/rsa/decrypt', methods=['POST'])
def api_rsa_decrypt():
    data = request.json or {}
    ciphertext_str = data.get("ciphertext", "").strip()
    d = parse_int(data.get("d", rsa_keys.get("d")))
    n = parse_int(data.get("n", rsa_keys.get("n")))
    bits = parse_int(data.get("bits", rsa_keys.get("bits", 512)), 512)

    if not ciphertext_str:
        return jsonify({"error": "Ciphertext cannot be empty"}), 400
    if not d or not n:
        return jsonify({"error": "RSA Keys (d, N) are uninitialized. Generate keys first!"}), 400

    try:
        hex_len = (bits + 3) // 4
        # Parse potential custom formats
        if ciphertext_str.startswith("[") and ciphertext_str.endswith("]"):
            # raw sequence representation
            clean = ciphertext_str[1:-1].replace(",", " ")
            cipher_ints = list(map(int, clean.split()))
        elif ciphertext_str.isdigit():
            val = int(ciphertext_str)
            raw_hex = f"{val:x}"
            remainder = len(raw_hex) % hex_len
            if remainder != 0:
                raw_hex = "0" * (hex_len - remainder) + raw_hex
            chunks = [raw_hex[i:i+hex_len] for i in range(0, len(raw_hex), hex_len)]
            cipher_ints = [int(chk, 16) for chk in chunks if chk.strip()]
        else:
            raw_hex = ciphertext_str.lower().replace("0x", "").replace(" ", "")
            chunks = [raw_hex[i:i+hex_len] for i in range(0, len(raw_hex), hex_len)]
            cipher_ints = [int(chk, 16) for chk in chunks if chk.strip()]

        if not cipher_ints:
            return jsonify({"error": "Unable to parse inputs"}), 400

        decrypted = rsa_decrypt(cipher_ints, d, n)
        return jsonify({
            "decrypted": decrypted
        })
    except Exception as ex:
        return jsonify({"error": str(ex)}), 500

@app.route('/api/public/rsa/factor', methods=['POST'])
def api_rsa_factor():
    data = request.json or {}
    n = parse_int(data.get("n", rsa_keys.get("n")))
    if not n:
        return jsonify({"error": "Invalid mod N"}), 400
    try:
        res = factorization_attack(n)
        # Convert values to strings to prevent JSON numeric overflows if huge
        for k, v in res.items():
            if isinstance(v, int) and v > 10**15:
                res[k] = str(v)
        return jsonify(res)
    except Exception as ex:
        return jsonify({"error": str(ex)}), 500


# 3b. Public Key - ECC & ECDH
@app.route('/api/public/ecc/validate_parameters', methods=['POST'])
def api_ecc_validate():
    data = request.json or {}
    try:
        p = int(data.get("p", 17))
        a = int(data.get("a", 2))
        b = int(data.get("b", 2))
        Gx = int(data.get("Gx", 5))
        Gy = int(data.get("Gy", 1))

        if (4 * a**3 + 27 * b**2) % p == 0:
            return jsonify({"error": "Discriminant (4a^3 + 27b^2) is 0 mod p — Singular Curve!"}), 400

        G = (Gx, Gy)
        if not is_on_curve(G, a, b, p):
            return jsonify({"error": f"Generator G = {G} is NOT on the curve!"}), 400

        subgroup = list_subgroup(G, a, b, p)
        n_param = len(subgroup)

        # Convert points lists safely to string tuples
        points_serialized = []
        for step, pt in subgroup:
            points_serialized.append({
                "step": step,
                "coord": str(pt) if pt is not None else "Infinity (O)"
            })

        return jsonify({
            "valid": True,
            "curve_str": f"y^2 = x^3 + {a}x + {b} (mod {p})",
            "p": p, "a": a, "b": b, "G": str(G),
            "n": n_param,
            "subgroup": points_serialized
        })
    except Exception as ex:
        return jsonify({"error": str(ex)}), 500

@app.route('/api/public/ecc/exchange', methods=['POST'])
def api_ecc_exchange():
    data = request.json or {}
    try:
        p = int(data.get("p", 17))
        a = int(data.get("a", 2))
        b = int(data.get("b", 2))
        
        Px = int(data.get("Px", 5))
        Py = int(data.get("Py", 1))
        P = (Px, Py)

        alice_priv = int(data.get("alice_priv", 3))
        bob_priv = int(data.get("bob_priv", 5))

        if not is_on_curve(P, a, b, p):
            return jsonify({"error": f"Primitive element P = {P} is NOT on the curve!"}), 400

        subgroup_P = list_subgroup(P, a, b, p)
        order_P = len(subgroup_P)

        if not (1 <= alice_priv < order_P) or not (1 <= bob_priv < order_P):
            return jsonify({"error": f"Private keys must be in the range 1 to {order_P - 1}"}), 400

        # Calculate Public Keys
        alice_pub = scalar_mul(alice_priv, P, a, p)
        bob_pub = scalar_mul(bob_priv, P, a, p)

        # Calculate Shared Secret
        alice_shared = scalar_mul(alice_priv, bob_pub, a, p)
        bob_shared = scalar_mul(bob_priv, alice_pub, a, p)

        # Serialize P's multiples subgroup
        subgroup_p_serialized = []
        for step, pt in subgroup_P:
            subgroup_p_serialized.append({
                "step": step,
                "coord": str(pt) if pt is not None else "Infinity (O)"
            })

        match = (alice_shared == bob_shared)
        shared_key = str(alice_shared[0]) if (match and alice_shared is not None) else "Infinity"

        return jsonify({
            "alice_pub": str(alice_pub) if alice_pub is not None else "Infinity",
            "bob_pub": str(bob_pub) if bob_pub is not None else "Infinity",
            "alice_shared": str(alice_shared) if alice_shared is not None else "Infinity",
            "bob_shared": str(bob_shared) if bob_shared is not None else "Infinity",
            "match": match,
            "shared_key": shared_key,
            "subgroup_p": subgroup_p_serialized,
            "order_p": order_P
        })
    except Exception as ex:
        return jsonify({"error": str(ex)}), 500


if __name__ == '__main__':
    # Flask default is 127.0.0.1:5000
    app.run(debug=True)

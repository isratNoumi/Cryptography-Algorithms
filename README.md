# CSE721: Introduction to Cryptography
## Portfolio of Classical & Modern Cryptographic Algorithms

Deployed URL -- https://cryptography-algorithms-qxti.onrender.com/

This is an interactive educational web dashboard implemented entirely from scratch in Python (with zero external block-crypto dependencies) to fulfill the requirements of the CSE721 Cryptography course. 

The portfolio features a comprehensive visual breakdown of historical, symmetric-key, and public-key cryptosystems, along with live analytical security simulations.

---

##  Implemented Systems

### 1. Classical Cryptography
*   **Substitution Cipher**
    *   Dynamic mapping using custom 26-character keys.
    *   Live ciphertext Frequency Analysis distributions.
    *   Brute-force Caesar shift calculation simulations (Shifts 1–25).
*   **Double Transposition Cipher**
    *   Two-stage matrix transposition using row/col permutations.
    *   Automatic grid-size padding management.

### 2. Symmetric-Key Cryptography
*   **DES (Data Encryption Standard)**
    *   64-bit block Feistel network implementation.
    *   Outputs detailed 16-round subkey schedules (derived from effective 56-bit space).
*   **AES (Advanced Encryption Standard)**
    *   Rijndael block-cipher support for AES-128, AES-192, and AES-256.
    *   Full round state operations: SubBytes, ShiftRows, MixColumns (over GF(2⁸)), and AddRoundKey.
    *   Outputs the complete derived Rijndael Key Schedule.

### 3. Public-Key Cryptography
*   **RSA Cryptosystem**
    *   Generates public/private key pairs up to 1024-bit using Miller-Rabin primality tests.
    *   Tabulates Extended Euclidean Algorithm steps modulating values for modular inverse $d$.
    *   Renders outputs in continuous hex formatting and giant single decimal integer blocks.
    *   **Fermat Factorization Attack**: Simulates a Fermat primes cracker ($N = a^2 - b^2$) showing loop counters and security limits.
*   **ECC (Elliptic Curve Cryptography) & ECDH**
    *   Validates point existence and addition/doubling over Galois prime field $y^2 = x^3 + ax + b \pmod p$.
    *   Performs structural vertical-slope coordinate additions avoiding zero division errors.
    *   Lists cyclic multiplier generators ($1G, 2G \dots$).
    *   **Elliptic Curve Diffie-Hellman Key Exchange**: Co-registers Alice and Bob's private $a, b$ values to isolate matching shared secrets.

---

##  How to Run Locally

### Prerequisites
*   Python 3.10 or higher

### Steps
1.  **Clone the workspace**:
    ```bash
    git clone <your-repository-url>
    cd <your-repository-folder>
    ```
2.  **Initialize the virtual environment & install Flask**:
    ```bash
    python -m venv venv
    .\venv\Scripts\activate      # For Windows Powershell / Command Prompt
    # source venv/bin/activate  # For macOS/Linux
    pip install flask
    ```
3.  **Launch the flask server**:
    ```bash
    python app.py
    ```
4.  **View Dashboard**:
    Open [http://127.0.0.1:5000/](http://127.0.0.1:5000/) in your web browser.


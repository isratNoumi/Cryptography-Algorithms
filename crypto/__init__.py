"""
Cryptographic Algorithm Engine (CSE721)
Modular library providing Classical, Symmetric, and Public-Key cryptographic algorithms.
"""

from .math_utils import mod_inverse, extended_gcd

from .classical import (
    sub_encrypt,
    sub_decrypt,
    double_transpose_encrypt,
    double_transpose_decrypt,
    validate_sub_key,
    parse_permutation_key,
    frequency_analysis,
    brute_force_caesar,
    run_substitution_cipher,
    run_double_transposition,
)

from .des import (
    generate_round_keys,
    des_encrypt,
    des_decrypt,
    bits_to_bytes,
    run_des,
)

from .aes import (
    get_aes_settings,
    aes_encrypt,
    aes_decrypt,
    get_round_keys,
    run_aes,
)

from .rsa import (
    rsa_generate_keys,
    rsa_encrypt,
    rsa_decrypt,
    rsa_keys,
    factorization_attack,
    run_rsa,
)

from .ecc import (
    point_add,
    scalar_mul,
    list_subgroup,
    is_on_curve,
    run_ecc,
)

__all__ = [
    # Math
    "mod_inverse",
    "extended_gcd",
    # Classical
    "sub_encrypt",
    "sub_decrypt",
    "double_transpose_encrypt",
    "double_transpose_decrypt",
    "validate_sub_key",
    "parse_permutation_key",
    "frequency_analysis",
    "brute_force_caesar",
    "run_substitution_cipher",
    "run_double_transposition",
    # Symmetric - DES
    "generate_round_keys",
    "des_encrypt",
    "des_decrypt",
    "bits_to_bytes",
    "run_des",
    # Symmetric - AES
    "get_aes_settings",
    "aes_encrypt",
    "aes_decrypt",
    "get_round_keys",
    "run_aes",
    # Public-Key - RSA
    "rsa_generate_keys",
    "rsa_encrypt",
    "rsa_decrypt",
    "rsa_keys",
    "factorization_attack",
    "run_rsa",
    # Public-Key - ECC
    "point_add",
    "scalar_mul",
    "list_subgroup",
    "is_on_curve",
    "run_ecc",
]

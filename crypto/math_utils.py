"""Shared mathematical utilities for cryptographic calculations."""


def extended_gcd(a, b):
    """
    Computes the greatest common divisor and Bézout coefficients (x, y)
    such that a*x + b*y = gcd(a, b).
    """
    r1, r2 = a, b
    s1, s2 = 1, 0
    t1, t2 = 0, 1

    while r2 != 0:
        q = r1 // r2
        r1, r2 = r2, r1 - q * r2
        s1, s2 = s2, s1 - q * s2
        t1, t2 = t2, t1 - q * t2

    return r1, s1, t1


def mod_inverse(a, m, verbose=False):
    """
    Calculates the modular inverse d of a modulo m such that (a * d) % m == 1.
    Raises ValueError if gcd(a, m) != 1.
    """
    if verbose:
        print(f"\n  Finding d such that {a} * d = 1 mod {m}")
        print(f"  GCD({m}, {a}) = 1\n")
        col = 12
        print(f"  {'Step':>4} | {'g':>4} | {'r1':>{col}} | {'r2':>{col}} | {'r':>{col}} | {'t0':>{col}} | {'t1':>{col}} | {'t2':>{col}}")
        print(f"  {'-'*4}-+-{'-'*4}-+-{'-'*col}-+-{'-'*col}-+-{'-'*col}-+-{'-'*col}-+-{'-'*col}-+-{'-'*col}")

    r1, r2 = m, a
    t0, t1 = 0, 1
    step = 1

    while r2 != 0:
        g = r1 // r2
        r = r1 % r2
        t2 = t0 - g * t1

        if verbose:
            print(f"  {step:>4} | {g:>4} | {r1:>{col}} | {r2:>{col}} | {r:>{col}} | {t0:>{col}} | {t1:>{col}} | {t2:>{col}}")

        r1 = r2
        r2 = r
        t0 = t1
        t1 = t2
        step += 1

    if r1 != 1:
        raise ValueError(f"{a} and {m} are not coprime (gcd = {r1}) — modular inverse does not exist.")

    return t0 % m

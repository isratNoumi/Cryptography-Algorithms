
def mod_inverse(k, p):
    r1, r2 = p, k
    t0, t1 = 0, 1

    while r2 != 0:
        g  = r1 // r2
        r  = r1 % r2
        t2 = t0 - g * t1
        r1 = r2
        r2 = r
        t0 = t1
        t1 = t2

    return t0 % p


def point_add(P, Q, a, p):
    if P is None:
        return Q
    if Q is None:
        return P

    x1, y1 = P
    x2, y2 = Q

    # P + (-P) = point at infinity
    if x1 == x2 and (y1 + y2) % p == 0:
        return None

    if P == Q:
        # doubling: 
        num = (3 * x1 * x1 + a) % p
        den = (2 * y1) % p
    else:
        # addition: 
        num = (y2 - y1) % p
        den = (x2 - x1) % p

    if den % p == 0:
        return None

    S  = num * mod_inverse(den, p) % p
    x3 = (S * S - x1 - x2) % p
    y3 = (S * (x1 - x3) - y1) % p
    return (x3, y3)


def scalar_mul(k, P, a, p):
    result = None
    base   = P

    while k > 0:
        if k & 1:
            result = point_add(result, base, a, p)
        base = point_add(base, base, a, p)
        k    = k >> 1

    return result


def is_on_curve(P, a, b, p):
    if P is None:
        return True
    x, y = P
    return (y * y) % p == (x * x * x + a * x + b) % p


def list_subgroup(G, a, b, p, max_points=500):
    points  = []
    current = G
    step    = 1

    while current is not None and step <= max_points:
        points.append((step, current))
        current = point_add(current, G, a, p)
        step    = step + 1

    points.append((step, None))   # add infinity
    return points


def run_ecc():
    print("\n--- Elliptic Curve Cryptography (ECC) + ECDH ---")
    print("Curve: y^2 = x^3 + ax + b  (mod p)\n")

    print("Enter domain parameters:")
    p  = int(input("  Prime p      : ").strip())
    a  = int(input("  Parameter a  : ").strip())
    b  = int(input("  Parameter b  : ").strip())
    Gx = int(input("  Generator Gx : ").strip())
    Gy = int(input("  Generator Gy : ").strip())

    G = (Gx, Gy)

    if (4 * a**3 + 27 * b**2) % p == 0:
        print("Error: discriminant is zero — singular curve.")
        return

    if not is_on_curve(G, a, b, p):
        print(f"Error: G = {G} is not on the curve.")
        return

    subgroup_G = list_subgroup(G, a, b, p)
    n_param = len(subgroup_G)

    print(f"\nCurve : y^2 = x^3 + {a}x + {b}  (mod {p})")
    print(f"Generator G = {G}")
    print(f"Domain parameters (p, a, b, G, n):")
    print(f"  p = {p}")
    print(f"  a = {a}")
    print(f"  b = {b}")
    print(f"  G = {G}")
    print(f"  n = {n_param}  (subgroup order)")

    print("\n=== All Multiples of G ===")
    for i, pt in subgroup_G:
        if pt is None:
            print(f"  {i}G = Infinity (O)")
        else:
            print(f"  {i}G = {pt}")

    # primitive element
    print("\n=== Key Generation ===")
    print("Enter primitive element P(x, y):")
    Px = int(input("  P x : ").strip())
    Py = int(input("  P y : ").strip())

    P = (Px, Py)
    if not is_on_curve(P, a, b, p):
        print(f"Error: P = {P} is not on the curve.")
        return

    print("\n=== List of all Ps (Multiples of Primitive Element P) ===")
    subgroup_P = list_subgroup(P, a, b, p)
    for i, pt in subgroup_P:
        if pt is None:
            print(f"  {i}P = Infinity (O)")
        else:
            print(f"  {i}P = {pt}")

    order_P = len(subgroup_P)
    print(f"\nOrder of Primitive Element P: {order_P}")

    # private keys — range comes from counted points
    alice_priv = int(input(f"Alice private key a (1 to {order_P - 1}): ").strip())
    bob_priv   = int(input(f"Bob   private key b (1 to {order_P - 1}): ").strip())

    if not (1 <= alice_priv <= order_P - 1) or not (1 <= bob_priv <= order_P - 1):
        print(f"Error: private keys must be between 1 and {order_P - 1}.")
        return

    alice_pub = scalar_mul(alice_priv, P, a, p)
    bob_pub   = scalar_mul(bob_priv,   P, a, p)

    print(f"\n--- Key Generation Output ---")
    print(f"Alice private key a : {alice_priv}")
    print(f"Alice public key  A : {alice_priv} * {P} = {alice_pub}")
    print(f"Bob private key b   : {bob_priv}")
    print(f"Bob public key  B   : {bob_priv} * {P} = {bob_pub}")

    # ECDH
    print("\n=== Elliptic Curve Diffie-Hellman Key Exchange ===")
    print(f"Alice private key a: {alice_priv}")
    print(f"Bob private key b  : {bob_priv}")

    alice_shared = scalar_mul(alice_priv, bob_pub, a, p)
    bob_shared   = scalar_mul(bob_priv, alice_pub, a, p)

    print(f"Alice: {alice_priv} * {bob_pub} = {alice_shared}")
    print(f"Bob  : {bob_priv} * {alice_pub} = {bob_shared}")
    print(f"\nShared key match : {alice_shared == bob_shared}")
    if alice_shared == bob_shared:
        print(f"Shared Key = {alice_shared[0] if alice_shared is not None else 'Infinity'}")
    else:
        print("Mismatch — check domain parameters.")
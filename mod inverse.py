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



print (mod_inverse(44,29))
def extended_euclidean(a: int, b: int) -> tuple[int, int, int]:
    if a < b:
        a, b = b, a
    s1, s2 = 1, 0
    t1, t2 = 0, 1
    r1, r2 = a, b
    q, r, s, t = 0, 0, 0, 0
    while r2 != 0:
        q = r1 // r2
        r = r1 % r2
        s = s1 - s2 * q
        t = t1 - t2 * q
        r1, r2, s1, s2, t1, t2 = r2, r, s2, s, t2, t
    if s1 < 0:
        s1 = s1 + b
    return (r1, s1, t1)


def crt(m: list[int], a: list[int]) -> int:
    M = 1
    for mi in m:
        M *= mi
    x = 0
    for mi, ai in zip(m, a):
        Mi = M // mi
        gcd, Mi_1, _ = extended_euclidean(Mi, mi)
        if gcd != 1:
            return -1
        x += ai * Mi * Mi_1
    return x % M


def generalized_crt(m: list[int], a: list[int]) -> tuple[int, int] | None:
    if len(m) != len(a):
        return None
    if not m:
        return None
    a = [ai % mi for ai, mi in zip(a, m)]
    x, m0 = a[0], m[0]
    for i in range(1, len(m)):
        ai, mi = a[i], m[i]
        g, s, t = extended_euclidean(m0, mi)
        if (ai - x) % g != 0:
            return None
        lcm = m0 // g * mi
        step = ((ai - x) // g) * s % (mi // g)
        x = (x + m0 * step) % lcm
        m0 = lcm
    return x, m0


def unified_crt(m, a):
    pairwise_coprime = True
    for i in range(len(m)):
        for j in range(i + 1, len(m)):
            if extended_euclidean(m[i], m[j])[0] != 1:
                pairwise_coprime = False
                break
        if not pairwise_coprime:
            break
    if pairwise_coprime:
        return crt(m, a), sum(m)
    else:
        return generalized_crt(m, a)


if __name__ == "__main__":
    n = list(map(int, input("Enter the moduli (space-separated): ").split()))
    a = list(map(int, input("Enter the remainders (space-separated): ").split()))
    result = unified_crt(n, a)
    if result is not None:
        x, mod = result
        print(f"\nUnified CRT Solution: x ≡ {x} (mod {mod})")
        
# def crtt(m, a):
#     M = 1
#     for mi in m:
#         M *= mi
#     x = 0
#     for mi, ai in zip(m, a):
#         Mi = M // mi
#         gcd, Mi_1, _ = extended_euclidean(Mi, mi)
#         if gcd != 1:
#             return -1
#         x += ai * Mi * Mi_1
#     return x % M

# def gen_crt(m, a):
#     a = [ai % mi for ai, mi in zip(a, m)]
#     x, m0 = a[0], m[0] # Initial solution and modulus
#     for i in range(1, len(m)):
#         ai, mi = a[i], m[i] # Current remainder and modulus
#         g, s, t = extended_euclidean(m0, mi) # GCD and coefficients
#         if (ai - x) % g != 0: # No solution exists
#             return None
#         lcm = m0 // g * mi # Least common multiple of m0 and mi
#         step = ((ai - x) // g) * s % (mi // g) # Step to adjust x
#         x = (x + m0 * step) % lcm # Update solution
#         m0 = lcm # Update modulus
        
#         # For each step we ensure x satisfies the new congruence
#         # and stop when all congruences are processed
        
#     return x, m0 # Final solution and modulus

# def uni_crt(m, a):
#     pairwise_coprime = True
#     for i in range(len(m)):
#         for j in range(i + 1, len(m)):
#             if extended_euclidean(m[i], m[j])[0] != 1: # any pair of m is not coprime i.e gcd != 1
#                 pairwise_coprime = False
#                 break
#         if not pairwise_coprime:
#             break
#     if pairwise_coprime:
#         return crt(m, a), sum(m) # if pairwise coprime, use standard CRT
#     else:
#         return gen_crt(m, a) # otherwise, use generalized CRT
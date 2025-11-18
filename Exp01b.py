def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    print(f"  Calculating GCD of {a} and {b} using Extended Euclidean algorithm")
    if a < b:
        a, b = b, a
    s1, s2 = 1, 0
    t1, t2 = 0, 1
    r1, r2 = a, b
    q, r, s, t = 0, 0, 0, 0
    print("  " + ("-" * 79))
    print(f"  | q\t| r1\t| r2\t| r\t| s1\t| s2\t| s\t| t1\t| t2\t| t\t|")
    print("  " + ("-" * 79))
    while r2 != 0:
        q = r1 // r2
        r = r1 % r2
        s = s1 - s2 * q
        t = t1 - t2 * q
        print(f"  | {q}\t| {r1}\t| {r2}\t| {r}\t| {s1}\t| {s2}\t| {s}\t| {t1}\t| {t2}\t| {t}\t|")
        r1, r2, s1, s2, t1, t2 = r2, r, s2, s, t2, t
    print("  " + ("-" * 79))
    print(f"  | \t| {r1}\t| {r2}\t| \t| {s1}\t| {s2}\t| \t| {t1}\t| {t2}\t| \t|")
    print("  " + ("-" * 79))
    if s1 < 0:
        s1 = s1 + b
    print(f"  GCD of {a} and {b} is {r1} and (s,t) is ({s1, t1}) using Extended Euclidean algorithm [Tabular Method]\n")
    return (r1, s1, t1)


def crt(n: list[int], a: list[int]) -> int:
    if len(n) != len(a):
        print("The lists of moduli and remainders must have the same length.")
        return -1

    N = 1
    for ni in n:
        N *= ni
    print(f"Product of all moduli (N): {N}\n")

    x = 0
    for i, (ni, ai) in enumerate(zip(n, a)):
        Ni = N // ni
        print(f"Step {i + 1}:")
        print(f"  Current modulus (n[{i}]): {ni}")
        print(f"  Current remainder (a[{i}]): {ai}")
        print(f"  Partial product (N/{ni}): {Ni}\n")

        gcd, yi, _ = extended_gcd(Ni, ni)
        if gcd != 1:
            print(f"Moduli {n} are not pairwise coprime.")
            return -1
        print(f"  Multiplicative inverse of {Ni} mod {ni} (y): {yi}")

        contribution = ai * Ni * yi
        print(f"  Contribution to solution: {ai} * {Ni} * {yi} = {contribution}\n")
        x += contribution

    result = x % N
    print(f"Final solution (x mod N): {x} mod {N} = {result}")
    return result


def generalized_crt(n: list[int], a: list[int]) -> tuple[int, int] | None:
    if len(n) != len(a):
        print("The lists of moduli and remainders must have the same length.")
        return None
    if not n:
        print("Empty system of congruences.")
        return None

    a = [ai % ni for ai, ni in zip(a, n)]
    x, m = a[0], n[0]
    print(f"Starting with x = {x} (mod {m})")
    for i in range(1, len(n)):
        ai, ni = a[i], n[i]
        print(f"Combining with x = {ai} (mod {ni})")
        g, s, t = extended_gcd(m, ni)
        if (ai - x) % g != 0:
            print(f"No solution: {x} =/= {ai} (mod gcd({m}, {ni}) = {g})\n")
            return None

        lcm = m // g * ni
        step = ((ai - x) // g) * s % (ni // g)
        x = (x + m * step) % lcm
        m = lcm

        print(f"New combined congruence: x = {x} (mod {m})")

    return x, m


def unified_crt(n: list[int], a: list[int]):
    print("System of congruences:")
    for ni, ai in zip(n, a):
        print(f"x ≡ {ai} (mod {ni})")
    from math import gcd
    pairwise_coprime = True
    for i in range(len(n)):
        for j in range(i + 1, len(n)):
            if gcd(n[i], n[j]) != 1:
                pairwise_coprime = False
                break
        if not pairwise_coprime:
            break

    if pairwise_coprime:
        print("\n=== Using Standard CRT (pairwise coprime case) ===")
        return crt(n, a), sum(n)
    else:
        print("\n=== Using Generalized CRT (non-coprime case) ===")
        return generalized_crt(n, a)


if __name__ == "__main__":
    while True:
        print("-"*40 + " Chinese Remainder Theorem "+ "-"*40)
        print("1) Solve system")
        print("2) Exit")
        ch = input("Choice: ").strip()
        if ch == '2':
            print("Bye.")
            break
        if ch != '1':
            print("Invalid.")
            continue
        k = int(input("Number of congruences: ").strip())
        if k <= 0:
            print("Must be > 0.")
            continue
        try:
            n = list(map(int, input(f"Enter {k} moduli: ").split()))
            a = list(map(int, input(f"Enter {k} remainders: ").split()))
        except ValueError:
            print("Invalid list.")
            continue
        if len(n) != k or len(a) != k:
            print("Count mismatch.")
            continue
        if any(ni == 0 for ni in n):
            print("Modulus 0 invalid.")
            continue
        res = unified_crt(n, a)
        if res:
            x, mod = res
            print(f"\nSolution: x ≡ {x} (mod {mod})")
        else:
            print("\nNo solution.")
        print("-" * 107)
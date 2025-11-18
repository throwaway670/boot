def euclidean(a: int, b:int) -> int:
    if a < b:
        a, b = b, a
    print("-"*33)
    print(f"| q\t| r1\t| r2\t| r\t|")
    print("-"*33)
    while b != 0:
        q = a // b
        r = a % b
        print(f"| {q}\t| {a}\t| {b}\t| {r}\t|")
        a, b = b, r
    print("-"*33)
    print(f"| \t| {a}\t| {b}\t| \t|")
    print("-"*33)
    return a

def extended_euclidean(a: int, b: int) -> tuple[int, int, int]:
    if a < b:
        a, b = b, a
    s1, s2= 1, 0
    t1, t2= 0, 1
    q, r, s, t= 0, 0, 0, 0
    print("-"*81)
    print(f"| q\t| r1\t| r2\t| r\t| s1\t| s2\t| s\t| t1\t| t2\t| t\t|")
    print("-"*81)
    while b != 0:
        q = a // b
        r = a % b
        s = s1 - s2*q
        t = t1 - t2*q
        print(f"| {q}\t| {a}\t| {b}\t| {r}\t| {s1}\t| {s2}\t| {s}\t| {t1}\t| {t2}\t| {t}\t|")
        a, b, s1, s2, t1, t2 = b, r, s2, s, t2, t
    print("-"*81)
    print(f"| \t| {a}\t| {b}\t| \t| {s1}\t| {s2}\t| \t| {t1}\t| {t2}\t| \t|")
    print("-"*81)
    return (a, s1, t1)

def extended_euclidean_inverse(a: int, b: int) -> tuple[int, int | None]:
    if a < b:
        a, b = b, a
    s1, s2= 1, 0
    t1, t2= 0, 1
    q, r, s, t = 0, 0, 0, 0
    print("-"*57)
    print("| q\t| r1\t| r2\t| r\t| t1\t| t2\t| t\t|")
    print("-"*57)
    while b != 0:
        q = a // b
        r = a % b
        t = t1 - q * t2
        print(f"| {q}\t| {a}\t| {b}\t| {r}\t| {t1}\t| {t2}\t| {t}\t|")
        a, b = b, r
        t1, t2 = t2, t
    print("-"*57)
    print(f"| \t| {a}\t| {b}\t| \t| {t1}\t| \t| \t|")
    print("-"*57)
    mi = t1
    if mi < 0:
        mi += a
    if a != 1:
        mi = None
    return (a, mi)

a, b= map(int, input("Enter two numbers: ").split())
print(f"\nGCD of {a} and {b} is {euclidean(a,b)} using Basic Euclidean algorithm [Tabular Method] for GCD")
res2= extended_euclidean(a,b)
print(f"\nGCD of {a} and {b} is {res2[0]} and (s,t) is ({res2[1], res2[2]}) using Extended Euclidean algorithm [Tabular Method] for GCD and (s,t) ")
res3= extended_euclidean_inverse(a,b)
print(f"\nGCD of {a} and {b} is {res3[0]} and MI is {res3[1]} using Euclidean algorithm [Tabular Method] for GCD and MI")

# def euc(a,b):
#     q=0
#     r1 = a
#     r2 = b
#     r = 0
#     s1, s2, t1, t2 = 1,0,0,1
#     s, t = 0,0
#     print("-"*81)
#     print(f"| q\t| r1\t| r2\t| r\t| s1\t| s2\t| s\t| t1\t| t2\t| t\t|")
#     print("-"*81)
#     while r2 > 0:
#         q = r1 // r2
#         r = r1 % r2
#         s = s1 - q * s2
#         t = t1 - q * t2
#         print(f"| {q}\t| {r1}\t| {r2}\t| {r}\t| {s1}\t| {s2}\t| {s}\t| {t1}\t| {t2}\t| {t}\t|")
#         r1, r2 = r2, r
#         s1, s2 = s2, s
#         t1, t2 = t2, t
#     print("-"*81)
#     print(f"| \t| {r1}\t| {r2}\t| \t| {s1}\t| {s2}\t| \t| {t1}\t| {t2}\t| \t|")
#     print("-"*81)
#     mi = t1
#     if mi < 0:
#         mi += a
#     if r1 != 1:
#         mi = None
#     return r1, s1, t1, mi
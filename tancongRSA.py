#!/usr/bin/env python3

import math
import sys
from Crypto.Util.number import long_to_bytes, inverse

# ---------------- tiện ích chung ----------------
def mod_inverse(a, m):
    """Tính nghịch đảo modulo - sử dụng inverse() từ pycryptodome"""
    try:
        return inverse(a, m)
    except:
        raise Exception('Nghịch đảo modulo không tồn tại (gcd != 1)')

# ---------------- integer nth root (đã sửa) ----------------
def integer_nth_root(x: int, n: int):
    """Trả về floor(root_n(x))."""
    if x == 0:
        return 0
    lo, hi = 0, x
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if pow(mid, n) <= x:
            lo = mid
        else:
            hi = mid - 1
    return lo

# ---------------- Fermat attack ----------------
def fermat_attack(N, limit=10000000):
    """
    Fermat factorization: hiệu quả nếu p và q gần nhau.
    Trả về (p,q) nếu tìm được, ngược lại (None, None).
    """
    print(f"[!] Bắt đầu Tấn công Fermat trên N = {N}...")
    
    # Kiểm tra N chẵn
    if N % 2 == 0:
        print(f"[+] N là số chẵn, phân tích ngay lập tức.")
        return 2, N // 2
    
    a = math.isqrt(N)
    if a * a != N:
        a += 1  # ceil(sqrt(N))

    for i in range(limit):
        b2 = a * a - N
        if b2 >= 0:
            b = math.isqrt(b2)
            if b * b == b2:
                p = a + b
                q = a - b
                if p * q == N:
                    print(f"[+] Tấn công thành công sau {i+1} bước lặp.")
                    return p, q
        a += 1

    print(f"[-] Tấn công thất bại (Không tìm thấy p, q trong giới hạn {limit} bước).")
    return None, None

# ===== Wiener (d nhỏ) =====
def _cf(n, d):  # Chuỗi phân số liên tiếp
    while d:
        a = n // d
        yield a
        n, d = d, n - a*d

def _convergents(cf): # Các phân số gần đúng từ chuỗi phân số liên tiếp
    p2, p1, q2, q1 = 0, 1, 1, 0
    for a in cf:
        p = a*p1 + p2
        q = a*q1 + q2
        yield p, q         
        p2, p1, q2, q1 = p1, p, q1, q

def _solve_pq_from_phi(n, phi): # Từ phi tìm p,q
    s = n - phi + 1
    Δ = s*s - 4*n
    if Δ < 0:
        return None, None
    r = math.isqrt(Δ)
    if r*r != Δ: return None, None
    p, q = (s + r)//2, (s - r)//2
    return (p, q) if p>0 and q>0 and p*q==n else (None, None)

def wiener_attack(e, n): # Trả về (d,p,q,phi) nếu tìm được, ngược lại (None,None,None,None)
    for k, d in _convergents(_cf(e, n)):
        if k == 0: 
            continue
        t = e*d - 1
        if t % k: 
            continue
        phi = t // k
        p, q = _solve_pq_from_phi(n, phi)
        if p and q:
            return d, p, q, phi
    return None, None, None, None

# ---------------- chức năng chính cho 3 lựa chọn ----------------
def run_fermat_flow():
    try:
        N = int(input("Nhập N: ").strip())
        e = int(input("Nhập e: ").strip())
        c = int(input("Nhập ciphertext c: ").strip())
    except ValueError:
        print("Lỗi: nhập phải là số nguyên. Quay về menu.")
        return

    p, q = fermat_attack(N)
    if p is None or q is None:
        print("Fermat thất bại — không tìm được p,q.")
        return

    print("\n--- KẾT QUẢ PHÂN TÍCH NHÂN TỬ ---")
    print(f"p = {p}")
    print(f"q = {q}")

    try:
        phi = (p - 1) * (q - 1)
        d = mod_inverse(e, phi)
    except Exception as ex:
        print("Lỗi khi tính d:", ex)
        return

    print("\n--- KHÓA BÍ MẬT ---")
    print(f"phi(N) = {phi}")
    print(f"d = {d}")

    m = pow(c, d, N)
    print("\n--- GIẢI MÃ ---")
    print("m =", m)
    try:        
        b = long_to_bytes(m)        
        try:
            print("m (utf-8) =", b.decode("utf-8"))
        except Exception:
            print("m (utf-8) = <không thể decode>")
    except Exception as ex:
        print("Không thể chuyển m -> bytes:", ex)

def run_root_flow():
    try:
        e = int(input("Nhập e: ").strip())
        N = int(input("Nhập N: ").strip())
        c = int(input("Nhập ciphertext c: ").strip())
    except ValueError:
        print("Lỗi: nhập phải là số nguyên. Quay về menu.")
        return

    # Tìm căn nguyên e của c
    r = integer_nth_root(c, e)
    if pow(r, e) != c:
        print("Không phải trường hợp m^e = c (không tìm được căn chính xác).")
        return

    m = r
    print("\n--- KẾT QUẢ ---")
    print("m (integer) =", m)
    try:
        b = long_to_bytes(m)
        try:
            print("m (utf-8)   =", b.decode("utf-8"))
        except Exception:
            print("m (utf-8)   = <không thể decode>")
    except Exception as ex:
        print("Không thể chuyển m -> bytes:", ex)
        
def run_wiener_flow():
    try:
        N = int(input("Nhập N: ").strip())
        e = int(input("Nhập e: ").strip())
        c = int(input("Nhập ciphertext c: ").strip())
    except ValueError:
        print("Lỗi: nhập phải là số nguyên. Quay về menu.")
        return

    d, p, q, phi = wiener_attack(e, N)
    if d is None:
        print("[-] Wiener thất bại — d không đủ nhỏ")
        return

    print("\n--- KẾT QUẢ WIENER (d nhỏ) ---")
    print(f"p = {p}")
    print(f"q = {q}")
    print(f"phi(N) = {phi}")
    print(f"d = {d}")

    m = pow(c, d, N)
    print("\n--- GIẢI MÃ ---")
    print("m =", m)
    b = long_to_bytes(m)  
    try:
        print("m (utf-8) =", b.decode("utf-8"))
    except:
        print("m (utf-8) = <không decode được>")
        print("m (hex)   =", b.hex())

# ---------------- menu ----------------
def main_menu():
    banner = """
======================================
        TẤN CÔNG RSA - MENU
 1) Fermat attack (p và q gần nhau)
 2) Trường hợp m^e = c (m^e < N)
 3) Wiener attack (d nhỏ)
 0) Thoát
======================================
"""
    while True:
        print(banner)
        choice = input("Chọn (0/1/2/3): ").strip()
        if choice == "1":
            run_fermat_flow()
        elif choice == "2":
            run_root_flow()
        elif choice == "3":
            run_wiener_flow()
        elif choice == "0" or choice.lower() in ("q", "exit", "thoát"):
            print("Thoát. Tạm biệt!")
            return
        else:
            print("Lựa chọn không hợp lệ. Thử lại.")
        input("\nNhấn Enter để quay về menu...")

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\nBị hủy bởi người dùng. Bye.")
        sys.exit(0)

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

# ---------------- integer nth root ----------------
def integer_nth_root(x: int, n: int):
    """Trả về floor(root_n(x))."""
    if x == 0:
        return 0
    l, r = 0, x
    while l < r:
        mid = (l + r + 1) // 2
        if pow(mid, n) <= x:
            l = mid
        else:
            r = mid - 1
    return l

def extended_gcd(a, b):
    """Trả về (g, x, y) sao cho ax + by = g = gcd(a,b)."""
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    return g, y1, x1 - (a // b) * y1

def mod_pow_signed(base, exp, mod):
    """Tính base^exp mod mod, hỗ trợ exp âm bằng nghịch đảo modulo."""
    if exp >= 0:
        return pow(base, exp, mod)
    inv_base = mod_inverse(base, mod)
    return pow(inv_base, -exp, mod)

def recover_phi_from_n_e_d_approx_k(n, e, d, max_adjust=1_000_000):
    """
    Khôi phục phi(n) từ (n, e, d) bằng xấp xỉ k:
      e*d - 1 = k * phi(n), với k xấp xỉ (e*d - 1)/n.
    """
    ed_minus_1 = e * d - 1
    if ed_minus_1 <= 0:
        raise ValueError("e*d - 1 phải dương.")

    k = ed_minus_1 // n
    if k <= 0:
        k = 1

    for _ in range(max_adjust):
        if ed_minus_1 % k == 0:
            phi = ed_minus_1 // k
            if phi * k == ed_minus_1:
                return phi, k
        k += 1
    raise ValueError("Không tìm được phi(n) phù hợp trong giới hạn lặp xấp xỉ k.")

# ---------------- Fermat attack ----------------
def fermat_attack(N, limit=100000000000):
    """
    Fermat factorization: hiệu quả nếu p và q gần nhau.
    Trả về (p,q) nếu tìm được, ngược lại (None, None).
    """
    print(f"[!] Bắt đầu Tấn công Fermat trên N = {N}...")
    
    if N % 2 == 0:
        print(f"[+] N là số chẵn, phân tích ngay lập tức.")
        return 2, N // 2
    
    a = math.isqrt(N)
    if a * a != N:
        a += 1 

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
def _cf(n, d):  
    while d:
        a = n // d
        yield a
        n, d = d, n - a*d

def _convergents(cf): 
    p2, p1, q2, q1 = 0, 1, 1, 0
    for a in cf:
        p = a*p1 + p2
        q = a*q1 + q2
        yield p, q         
        p2, p1, q2, q1 = p1, p, q1, q

def _solve_pq_from_phi(n, phi): 
    s = n - phi + 1
    Δ = s*s - 4*n
    if Δ < 0:
        return None, None
    r = math.isqrt(Δ)
    if r*r != Δ: return None, None
    p, q = (s + r)//2, (s - r)//2
    return (p, q) if p>0 and q>0 and p*q==n else (None, None)

def wiener_attack(e, n): 
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

def factordb_attack(n):
    """Lấy p, q của n từ FactorDB. Trả về (p, q) hoặc (None, None)."""
    try:
        from factordb.factordb import FactorDB
    except ImportError:
        print("[-] Thiếu thư viện factordb-python.")
        print("    Cài bằng: python -m pip install factordb-python")
        return None, None

    try:
        f = FactorDB(n)
        f.connect()
        factors = f.get_factor_from_api()
    except Exception as ex:
        print("[-] Lỗi khi kết nối/đọc dữ liệu từ FactorDB:", ex)
        return None, None

    if not factors:
        print("[-] FactorDB chưa có dữ liệu phân tích cho N này.")
        return None, None

    expanded = []
    for factor, exponent in factors:
        factor_int = int(factor)
        for _ in range(int(exponent)):
            expanded.append(factor_int)

    if len(expanded) != 2:
        print("[-] N không có đúng dạng tích của 2 thừa số nguyên tố (theo dữ liệu FactorDB).")
        return None, None

    p, q = expanded[0], expanded[1]
    if p * q != n:
        print("[-] Dữ liệu FactorDB không khớp với N.")
        return None, None
    return p, q

# ---------------- chức năng chính cho các lựa chọn ----------------
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

def run_factordb_flow():
    try:
        N = int(input("Nhập N: ").strip())
        e = int(input("Nhập e: ").strip())
        c = int(input("Nhập ciphertext c: ").strip())
    except ValueError:
        print("Lỗi: nhập phải là số nguyên. Quay về menu.")
        return

    print(f"[!] Bắt đầu tấn công FactorDB trên N = {N}...")
    p, q = factordb_attack(N)
    if p is None or q is None:
        print("FactorDB thất bại — không lấy được p,q.")
        return

    print("\n--- KẾT QUẢ PHÂN TÍCH NHÂN TỬ (FactorDB) ---")
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
    b = long_to_bytes(m)
    try:
        print("m (utf-8) =", b.decode("utf-8"))
    except Exception:
        print("m (utf-8) = <không decode được>")
        print("m (hex)   =", b.hex())

def run_common_modulus_flow():
    """
    Common Modulus Attack:
    c1 = m^e1 mod N, c2 = m^e2 mod N, gcd(e1, e2)=1 và cùng N.
    """
    try:
        N = int(input("Nhập N (modulus dùng chung): ").strip())
        e1 = int(input("Nhập e1: ").strip())
        e2 = int(input("Nhập e2: ").strip())
        c1 = int(input("Nhập ciphertext c1: ").strip())
        c2 = int(input("Nhập ciphertext c2: ").strip())
    except ValueError:
        print("Lỗi: nhập phải là số nguyên. Quay về menu.")
        return

    print(f"[!] Bắt đầu Common Modulus Attack trên N = {N}...")
    g, u, v = extended_gcd(e1, e2)
    if g != 1:
        print("[-] Thất bại: gcd(e1, e2) != 1 nên không áp dụng được.")
        return

    try:
        part1 = mod_pow_signed(c1, u, N)
        part2 = mod_pow_signed(c2, v, N)
    except Exception as ex:
        print("[-] Không thể xử lý lũy thừa âm (cần nghịch đảo modulo):", ex)
        return

    m = (part1 * part2) % N
    print("\n--- KẾT QUẢ COMMON MODULUS ---")
    print(f"u = {u}, v = {v} (thỏa e1*u + e2*v = 1)")
    print("m =", m)
    b = long_to_bytes(m)
    try:
        print("m (utf-8) =", b.decode("utf-8"))
    except Exception:
        print("m (utf-8) = <không decode được>")
        print("m (hex)   =", b.hex())

def run_shared_modulus_k_approx_flow():
    """
    Cùng modulus n:
    Biết (n, e1, d1) của user 1 và e2 của user 2 -> tìm d2.
    """
    try:
        n = int(input("Nhập n (modulus dùng chung): ").strip())
        e1 = int(input("Nhập e1 (public key 1): ").strip())
        d1 = int(input("Nhập d1 (private key 1): ").strip())
        e2 = int(input("Nhập e2 (public key 2): ").strip())
    except ValueError:
        print("Lỗi: nhập phải là số nguyên. Quay về menu.")
        return

    print(f"[!] Bắt đầu tấn công cùng modulus - xấp xỉ k trên n = {n}...")
    try:
        phi_n, k = recover_phi_from_n_e_d_approx_k(n, e1, d1)
    except Exception as ex:
        print("[-] Không thể khôi phục phi(n):", ex)
        return

    try:
        d2 = mod_inverse(e2, phi_n)
    except Exception as ex:
        print("[-] Không thể tính d2 (có thể gcd(e2, phi(n)) != 1):", ex)
        return

    print("\n--- KẾT QUẢ CÙNG MODULUS - XẤP XỈ k ---")
    print(f"k = {k}")
    print(f"phi(n) = {phi_n}")
    print(f"d2 = {d2}")
    check = (e1 * d1 - 1) // k
    print(f"Kiểm tra phi(n) (từ (e1*d1-1)/k) = {check}")

# ---------------- menu ----------------
def main_menu():
    banner = """
======================================
        TẤN CÔNG RSA - MENU
 1) Fermat attack (p và q gần nhau)
 2) Trường hợp m^e = c (m^e < N)
 3) Wiener attack (d nhỏ)
 4) FactorDB attack (tra p, q online)
 5) Common Modulus attack (cùng N, khác e)
 6) Cùng modulus - xấp xỉ k (tìm d2 từ e1,d1,e2)
 0) Thoát
======================================
"""
    while True:
        print(banner)
        choice = input("Chọn: ").strip()
        if choice == "1":
            run_fermat_flow()
        elif choice == "2":
            run_root_flow()
        elif choice == "3":
            run_wiener_flow()
        elif choice == "4":
            run_factordb_flow()
        elif choice == "5":
            run_common_modulus_flow()
        elif choice == "6":
            run_shared_modulus_k_approx_flow()
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

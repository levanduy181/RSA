#!/usr/bin/env python3
import tkinter as tk
from tkinter import messagebox, ttk
from Cryptodome.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes

APP_TITLE = "RSA GUI"
MONO = ("Courier New", 10)

# =============== small utils ===============
def get_text(widget):
    return widget.get("1.0", tk.END).strip()

def set_text(widget, text):
    widget.config(state="normal")
    widget.delete("1.0", tk.END)
    widget.insert(tk.END, text)

def parse_int_from(widget, field_name="giá trị"):
    s = get_text(widget)
    if not s:
        raise ValueError(f"{field_name} đang trống")
    try:
        return int(s)
    except Exception:
        raise ValueError(f"{field_name} phải là số nguyên")

# =============== encode/decode util ===============
def encode_text():
    data = get_text(input_box)
    if not data:
        messagebox.showwarning("Cảnh báo", "Chưa nhập dữ liệu!")
        return
    try:
        n = int(data) if data.isdigit() else bytes_to_long(data.encode())
        set_text(output_box, str(n))
    except Exception as e:
        messagebox.showerror("Lỗi", f"Encode thất bại: {e}")

def decode_text():
    raw = get_text(input_box)
    if not raw:
        messagebox.showwarning("Cảnh báo", "Chưa nhập dữ liệu!")
        return
    try:
        n = int(raw)
        b = long_to_bytes(n)
        try:
            text = b.decode()
            set_text(output_box, text)
        except Exception:
            set_text(output_box, f"(bytes, hex)\n{b.hex()}")
    except Exception as e:
        messagebox.showerror("Lỗi", f"Decode thất bại: {e}")

# =============== RSA ===============
def gen_key():
    try:
        p, q = getPrime(128), getPrime(128)
        n, phi = p * q, (p - 1) * (q - 1)
        e = 65537
        d = inverse(e, phi)
        set_text(p_box, str(p))
        set_text(q_box, str(q))
        set_text(n_box, str(n))
        set_text(e_box, str(e))
        set_text(d_box, str(d))
        messagebox.showinfo("RSA", "Đã sinh khóa RSA!")
    except Exception as e:
        messagebox.showerror("Lỗi", f"Sinh khóa thất bại: {e}")

def rsa_encrypt():
    data = get_text(input_box)
    if not data:
        messagebox.showwarning("Cảnh báo", "Chưa nhập dữ liệu!")
        return
    try:
        n = parse_int_from(n_box, "n")
        e = parse_int_from(e_box, "e")
        m = int(data) if data.isdigit() else bytes_to_long(data.encode())
        if m >= n:
            messagebox.showerror("Lỗi", "Thông điệp quá lớn (m >= n). Hãy chia nhỏ thông điệp.")
            return
        c = pow(m, e, n)
        set_text(output_box, str(c))
    except Exception as e:
        messagebox.showerror("Lỗi", f"Mã hóa thất bại: {e}")

def rsa_decrypt():
    raw = get_text(input_box)
    if not raw:
        messagebox.showwarning("Cảnh báo", "Chưa nhập dữ liệu!")
        return
    try:
        n = parse_int_from(n_box, "n")
        d = parse_int_from(d_box, "d")
        c = int(raw)
        m = pow(c, d, n)
        b = long_to_bytes(m)
        try:
            set_text(output_box, b.decode())
        except Exception:
            set_text(output_box, str(m))
    except Exception as e:
        messagebox.showerror("Lỗi", f"Giải mã thất bại: {e}")

def clear_all():
    for w in (input_box, output_box, p_box, q_box, n_box, e_box, d_box):
        set_text(w, "")

# =============== UI ===============
root = tk.Tk()
root.title(APP_TITLE)
root.geometry("800x700")

main = ttk.Frame(root, padding=8)
main.pack(fill="both", expand=True)

ttk.Label(main, text="Input").pack(anchor="w")
input_box = tk.Text(main, height=5, font=MONO)
input_box.pack(fill="x", pady=3)

ttk.Label(main, text="Output").pack(anchor="w")
output_box = tk.Text(main, height=6, font=MONO)
output_box.pack(fill="x", pady=3)

f1 = ttk.Frame(main)
f1.pack(fill="x", pady=4)
ttk.Button(f1, text="Encode", command=encode_text).pack(side="left", padx=4)
ttk.Button(f1, text="Decode", command=decode_text).pack(side="left", padx=4)
ttk.Button(f1, text="Clear All", command=clear_all).pack(side="left", padx=4)

ttk.Separator(main, orient="horizontal").pack(fill="x", pady=8)

ttk.Label(main, text="RSA Keys").pack(anchor="w")

ttk.Label(main, text="p").pack(anchor="w")
p_box = tk.Text(main, height=2, font=MONO); p_box.pack(fill="x", pady=2)

ttk.Label(main, text="q").pack(anchor="w")
q_box = tk.Text(main, height=2, font=MONO); q_box.pack(fill="x", pady=2)

ttk.Label(main, text="n").pack(anchor="w")
n_box = tk.Text(main, height=3, font=MONO); n_box.pack(fill="x", pady=2)

ttk.Label(main, text="e").pack(anchor="w")
e_box = tk.Text(main, height=2, font=MONO); e_box.pack(fill="x", pady=2)

ttk.Label(main, text="d").pack(anchor="w")
d_box = tk.Text(main, height=3, font=MONO); d_box.pack(fill="x", pady=2)

f2 = ttk.Frame(main)
f2.pack(fill="x", pady=6)
ttk.Button(f2, text="RSA GenKey", command=gen_key).pack(side="left", padx=4)
ttk.Button(f2, text="Encrypt", command=rsa_encrypt).pack(side="left", padx=4)
ttk.Button(f2, text="Decrypt", command=rsa_decrypt).pack(side="left", padx=4)

root.mainloop()

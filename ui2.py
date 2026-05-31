import os
import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk
from tkinterdnd2 import TkinterDnD, DND_FILES
# 引入究极加密原语
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag
import ctypes

# ================= 1. 究极安全配置 (防神仙级) =================
SALT_SIZE = 64  # 256位超级随机盐
NONCE_SIZE = 12  # GCM 模式专属随机数
# Scrypt 参数：控制破解的物理成本
# n=2**18 意味着每次生成密钥需要消耗约 256MB 内存。如果你的电脑足够好，可以改成 n=2**19 (512MB)
SCRYPT_N = 2 ** 18
SCRYPT_R = 8
SCRYPT_P = 1


def get_key_from_password(password: str, salt: bytes) -> bytes:
    """使用 Scrypt 内存硬化算法，榨干内存以抵御显卡/ASIC矿机暴力破解"""
    kdf = Scrypt(
        salt=salt,
        length=32,  # 强制派生出 256-bit (32 bytes) 的密钥，用于 AES-256
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )
    return kdf.derive(password.encode())


# ================= 2. 核心逻辑与校验 =================
def process_file(mode):
    filepath = file_path_var.get()
    password = password_var.get()
    confirm_pwd = confirm_var.get()

    if not filepath or not os.path.exists(filepath):
        messagebox.showwarning("提示", "请先选择或拖入一个有效的文件！")
        return
    if not password:
        messagebox.showwarning("提示", "安全密码不能为空！")
        return

    if mode == "encrypt" and password != confirm_pwd:
        status_label.configure(text=f"⛔ 密码不一致，请重新输入。", text_color="#ff6666")
        messagebox.showerror("校验失败", "两次输入的密码不一致！\n为防止文件永久锁定，请确保密码输入正确。")
        return

    status_label.configure(text=f"🔄 正在调动内存生成究极密钥，请稍候...", text_color="#aaaaaa")
    app.update()  # 强制刷新 UI，因为计算密钥会卡顿一瞬间

    try:
        if mode == "encrypt":
            # 1. 准备随机要素
            salt = os.urandom(SALT_SIZE)
            nonce = os.urandom(NONCE_SIZE)

            # 2. 生成 AES-256 密钥并初始化 GCM 引擎
            key = get_key_from_password(password, salt)
            aesgcm = AESGCM(key)

            # 3. 加密 (自动包含身份验证标签，防篡改)
            with open(filepath, "rb") as file:
                file_data = file.read()
            ciphertext = aesgcm.encrypt(nonce, file_data, None)

            # 4. 组装文件：32字节盐 + 12字节Nonce + 密文
            with open(filepath, "wb") as file:
                file.write(salt + nonce + ciphertext)

            status_label.configure(text=f"🛡️ 文件已进入最高级别量子锁定。", text_color="#66ccff")
            messagebox.showinfo("加密成功",
                                "您的文件已采用 AES-256-GCM 锁定。\n⚠️ 警告：请记住密码！！")

        elif mode == "decrypt":
            with open(filepath, "rb") as file:
                file_content = file.read()

            if len(file_content) < (SALT_SIZE + NONCE_SIZE):
                messagebox.showerror("错误", "这不是一个有效的加密文件！")
                return

            # 1. 拆解文件头部
            salt = file_content[:SALT_SIZE]
            nonce = file_content[SALT_SIZE: SALT_SIZE + NONCE_SIZE]
            ciphertext = file_content[SALT_SIZE + NONCE_SIZE:]

            # 2. 尝试生成密钥
            key = get_key_from_password(password, salt)
            aesgcm = AESGCM(key)

            try:
                # 3. 解密并验证完整性
                decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
            except InvalidTag:
                # 如果密码错1位，或者密文被改了1个字节，都会触发 InvalidTag
                status_label.configure(text=f"⛔ 拒绝访问，防篡改机制触发。", text_color="#ff6666")
                messagebox.showerror("拒绝访问", "⛔ 密码错误，或者文件遭到篡改破坏！")
                return

            with open(filepath, "wb") as file:
                file.write(decrypted_data)

            status_label.configure(text=f"✅ 身份验证通过，文件已还原。", text_color="#66ff66")
            messagebox.showinfo("解密成功", "验证通过，您的文件已完美还原。")

    except Exception as e:
        messagebox.showerror("发生致命错误", f"操作失败，详情:\n{e}")
    finally:
        password_var.set("")
        confirm_var.set("")
        pwd_entry.focus()


def drop_file(event):
    filepath = event.data
    if filepath.startswith('{') and filepath.endswith('}'):
        filepath = filepath[1:-1]
    file_path_var.set(filepath)
    status_label.configure(text="📁 目标已锁定，等待验证指令。", text_color="white")


def toggle_password_visibility():
    current_show = pwd_entry.cget("show")
    if current_show == "●":
        pwd_entry.configure(show="")
        confirm_entry.configure(show="")
        toggle_btn.configure(text="🙈", text_color="#aaaaaa")
    else:
        pwd_entry.configure(show="●")
        confirm_entry.configure(show="●")
        toggle_btn.configure(text="👁", text_color="white")


# ================= 3. UI 初始化与高清适配 =================
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except Exception:
    pass


class CTkWithDnD(ctk.CTk, TkinterDnD.DnDWrapper):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.TkdndVersion = TkinterDnD._require(self)


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

app = CTkWithDnD()
app.title("VoidCrypt Pro")
app.geometry("760x640")
app.resizable(True, True)

font_normal = ctk.CTkFont(family="Microsoft YaHei", size=14)
font_bold = ctk.CTkFont(family="Microsoft YaHei", size=14, weight="bold")
font_title = ctk.CTkFont(family="Microsoft YaHei", size=24, weight="bold")

main_frame = ctk.CTkFrame(app, fg_color="transparent")
main_frame.pack(fill="both", expand=True, padx=30, pady=25)

title_label = ctk.CTkLabel(main_frame, text="🔒 VoidCrypt™ 虚空锁", font=font_title)
title_label.pack(pady=(0, 8))

# 标语已升级
sub_label = ctk.CTkLabel(main_frame, text="AES-256-GCM ✖️ Scrypt 内存硬化加密阵列", text_color="gray",
                         font=ctk.CTkFont(family="Microsoft YaHei", size=12))
sub_label.pack(pady=(0, 20))

status_label = ctk.CTkLabel(main_frame, text="系统待机中。请拖入文件以继续...", text_color="#aaaaaa", font=font_normal)
status_label.pack(pady=(0, 15), fill="x")

# --- 1. 拖拽区域 ---
file_path_var = tk.StringVar()
drop_frame = ctk.CTkFrame(main_frame, height=120, corner_radius=12, fg_color="#1c1c1c", border_width=2,
                          border_color="#333333")
drop_frame.pack(pady=5, fill="x")
drop_frame.pack_propagate(False)

drop_frame.drop_target_register(DND_FILES)
drop_frame.dnd_bind('<<Drop>>', drop_file)

drop_icon = ctk.CTkLabel(drop_frame, text="🌀", font=ctk.CTkFont(size=20), text_color="#555555")
drop_icon.place(relx=0.5, rely=0.35, anchor="center")

drop_text = ctk.CTkLabel(drop_frame, text="将机密文件拖拽到此处", text_color="#666666", font=font_bold)
drop_text.place(relx=0.5, rely=0.75, anchor="center")

drop_icon.drop_target_register(DND_FILES)
drop_icon.dnd_bind('<<Drop>>', drop_file)
drop_text.drop_target_register(DND_FILES)
drop_text.dnd_bind('<<Drop>>', drop_file)

# --- 2. 密码输入区域 ---
pwd_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
pwd_frame.pack(fill="x", pady=20)

row1 = ctk.CTkFrame(pwd_frame, fg_color="transparent")
row1.pack(fill="x", pady=(0, 10))

ctk.CTkLabel(row1, text="访问密钥:", font=font_bold, width=70, anchor="w").pack(side="left")
password_var = tk.StringVar()
pwd_entry = ctk.CTkEntry(row1, textvariable=password_var, show="●", height=38, corner_radius=6, border_color="#444444",
                         font=font_normal)
pwd_entry.pack(side="left", fill="x", expand=True, padx=(10, 10))

toggle_btn = ctk.CTkButton(row1, text="👁", width=40, height=38, fg_color="#333333", hover_color="#444444",
                           font=ctk.CTkFont(size=16), command=toggle_password_visibility)
toggle_btn.pack(side="right")

row2 = ctk.CTkFrame(pwd_frame, fg_color="transparent")
row2.pack(fill="x")

ctk.CTkLabel(row2, text="确认密钥:", font=font_bold, width=70, anchor="w").pack(side="left")
confirm_var = tk.StringVar()
confirm_entry = ctk.CTkEntry(row2, textvariable=confirm_var, show="●", height=38, corner_radius=6,
                             border_color="#444444", placeholder_text="加密必填，解密可留空", font=font_normal)
confirm_entry.pack(side="left", fill="x", expand=True, padx=(10, 50))

# --- 3. 操作按钮区域 ---
action_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
action_frame.pack(fill="x", pady=(10, 0))

encrypt_btn = ctk.CTkButton(action_frame, text="🛡️ 绝对锁定 (加密)", height=42, fg_color="#b30000",
                            hover_color="#cc0000", font=font_bold, command=lambda: process_file("encrypt"))
encrypt_btn.pack(side="left", expand=True, padx=(0, 10))

decrypt_btn = ctk.CTkButton(action_frame, text="🔑 授权解锁 (解密)", height=42, fg_color="#00a86b",
                            hover_color="#00c87b", font=font_bold, command=lambda: process_file("decrypt"))
decrypt_btn.pack(side="right", expand=True, padx=(10, 0))

pwd_entry.focus()
app.mainloop()
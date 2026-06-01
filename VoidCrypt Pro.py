import os
import threading
import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk
from tkinterdnd2 import TkinterDnD, DND_FILES
from PIL import Image
import sys

# --- 引入商业级流式加密组件 ---
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag
import ctypes

# ================= 1. 究极安全配置 & 流式参数 =================
SALT_SIZE = 64  # 512位超级随机盐
NONCE_SIZE = 12  # GCM 专属随机数
SCRYPT_N = 2 ** 18  # 内存硬化，每次榨干 256MB 内存
SCRYPT_R = 8
SCRYPT_P = 1
CHUNK_SIZE = 1024 * 1024  # 流式处理块大小：1MB (商业级内存控制核心)


def get_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode())


def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)


# ================= 2. 多线程与流式加密核心 =================
is_processing = False  # 防止用户疯狂连点


def update_ui(progress_val, text, text_color):
    """线程安全的 UI 刷新函数"""
    app.after(0, lambda: progress_bar.set(progress_val))
    app.after(0, lambda: percent_label.configure(text=f"{int(progress_val * 100)}%"))
    app.after(0, lambda: status_label.configure(text=text, text_color=text_color))


def process_file_worker(mode, filepath, password):
    global is_processing
    temp_path = filepath + ".vtmp"  # 建立临时加工厂

    try:
        update_ui(0, "🔄 正在榨取内存生成量子密钥 (约需1-2秒)...", "#aaaaaa")
        file_size = os.path.getsize(filepath)

        if file_size == 0:
            raise ValueError("不能处理 0 字节的空文件。")

        if mode == "encrypt":
            salt = os.urandom(SALT_SIZE)
            nonce = os.urandom(NONCE_SIZE)
            key = get_key_from_password(password, salt)

            # 初始化流式加密引擎
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
            encryptor = cipher.encryptor()

            processed_size = 0
            with open(filepath, "rb") as f_in, open(temp_path, "wb") as f_out:
                f_out.write(salt)
                f_out.write(nonce)

                # 循环切片读取（1MB 一次）
                while True:
                    chunk = f_in.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    f_out.write(encryptor.update(chunk))
                    processed_size += len(chunk)

                    # 实时计算进度并更新 UI
                    progress = processed_size / file_size
                    update_ui(progress, "🛡️ 正在进行流式加密封锁...", "#66ccff")

                f_out.write(encryptor.finalize())
                f_out.write(encryptor.tag)  # GCM 必须把认证标签写在文件最后

            # 成功后，原子级替换原文件
            os.replace(temp_path, filepath)
            update_ui(1.0, "✅ 文件已进入最高级别量子锁定。", "#66ff66")
            app.after(0, lambda: messagebox.showinfo("加密成功",
                                                     "您的文件已采用 AES-256-GCM 锁定。\n⚠️ 警告：哪怕神仙下凡也解不开，请把密码刻在脑子里！"))

        elif mode == "decrypt":
            if file_size < (SALT_SIZE + NONCE_SIZE + 16):
                raise ValueError("文件格式错误或已被破坏。")

            with open(filepath, "rb") as f_in, open(temp_path, "wb") as f_out:
                salt = f_in.read(SALT_SIZE)
                nonce = f_in.read(NONCE_SIZE)

                # 商业级技巧：跳到文件末尾读取 16 字节的防篡改标签
                f_in.seek(-16, os.SEEK_END)
                tag = f_in.read(16)

                # 光标复位到密文开始处
                f_in.seek(SALT_SIZE + NONCE_SIZE)

                key = get_key_from_password(password, salt)
                cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
                decryptor = cipher.decryptor()

                ciphertext_size = file_size - SALT_SIZE - NONCE_SIZE - 16
                processed_size = 0

                while processed_size < ciphertext_size:
                    read_len = min(CHUNK_SIZE, ciphertext_size - processed_size)
                    chunk = f_in.read(read_len)
                    f_out.write(decryptor.update(chunk))
                    processed_size += len(chunk)

                    progress = processed_size / ciphertext_size
                    update_ui(progress, "🔑 正在进行流式授权解码...", "#f39c12")

                # 验证防篡改标签
                decryptor.finalize()

            os.replace(temp_path, filepath)
            update_ui(1.0, "✅ 身份验证通过，文件已完美还原。", "#66ff66")
            app.after(0, lambda: messagebox.showinfo("解密成功", "验证通过，您的文件已完美还原。"))

    except InvalidTag:
        if os.path.exists(temp_path): os.remove(temp_path)  # 销毁残次品
        update_ui(0, "⛔ 拒绝访问：防篡改机制触发。", "#ff6666")
        app.after(0, lambda: messagebox.showerror("拒绝访问", "⛔ 密码错误，或者文件遭到篡改破坏！"))
    except Exception as e:
        if os.path.exists(temp_path): os.remove(temp_path)
        update_ui(0, "❌ 发生致命错误。", "#ff6666")
        app.after(0, lambda: messagebox.showerror("发生致命错误", f"操作失败，详情:\n{e}"))
    finally:
        # 重置 UI 状态
        is_processing = False
        app.after(0, lambda: toggle_buttons(True))
        app.after(0, lambda: password_var.set(""))
        app.after(0, lambda: confirm_var.set(""))


def trigger_process(mode):
    global is_processing
    if is_processing: return

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
        return

    is_processing = True
    toggle_buttons(False)  # 锁定按钮防止重复点击

    # 将苦力活扔给后台线程，UI 继续保持顺滑
    threading.Thread(target=process_file_worker, args=(mode, filepath, password), daemon=True).start()


def toggle_buttons(state):
    state_str = "normal" if state else "disabled"
    encrypt_btn.configure(state=state_str)
    decrypt_btn.configure(state=state_str)


def drop_file(event):
    if is_processing: return
    filepath = event.data
    if filepath.startswith('{') and filepath.endswith('}'):
        filepath = filepath[1:-1]
    file_path_var.set(filepath)
    update_ui(0, "📁 目标已锁定，等待验证指令。", "white")


def toggle_password_visibility():
    current_show = pwd_entry.cget("show")
    new_show = "" if current_show == "●" else "●"
    pwd_entry.configure(show=new_show)
    confirm_entry.configure(show=new_show)
    toggle_btn.configure(text="🙈" if new_show == "" else "👁", text_color="#aaaaaa" if new_show == "" else "white")


# ================= 3. 高清 UI 界面 =================
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
app.title("VoidCrypt™ Pro")
app.geometry("580x560")  # 稍微拉长一点给进度条腾位置
app.resizable(True, True)
# ================= 新增：左上角标题栏图标 =================
try:
    # 加载你的 1.ico 文件作为系统窗口图标
    app.iconbitmap(resource_path("1.ico"))
except Exception as e:
    print(f"窗口图标加载失败: {e}")
# ==========================================================
font_normal = ctk.CTkFont(family="Microsoft YaHei", size=14)
font_bold = ctk.CTkFont(family="Microsoft YaHei", size=14, weight="bold")
font_title = ctk.CTkFont(family="Microsoft YaHei", size=24, weight="bold")

main_frame = ctk.CTkFrame(app, fg_color="transparent")
main_frame.pack(fill="both", expand=True, padx=30, pady=25)

# --- 界面右上角图标 ---
#try:
#    img_path = resource_path("1.png")
#    logo_image = ctk.CTkImage(light_image=Image.open(img_path), dark_image=Image.open(img_path), size=(45, 45))
#    logo_label = ctk.CTkLabel(main_frame, image=logo_image, text="")
#    logo_label.place(relx=1.0, rely=0.0, anchor="ne", x=10, y=-10)
#except Exception:
#    pass

title_label = ctk.CTkLabel(main_frame, text="🌌 VoidCrypt™ 文件加密", font=font_title)
title_label.pack(pady=(0, 8))

sub_label = ctk.CTkLabel(main_frame, text="AES-256-GCM✖️Scrypt 内存硬化流式加密引擎", text_color="gray",
                         font=ctk.CTkFont(family="Microsoft YaHei", size=12))
sub_label.pack(pady=(0, 20))

status_label = ctk.CTkLabel(main_frame, text="系统待机中。请拖入文件以继续...", text_color="#aaaaaa", font=font_normal)
status_label.pack(pady=(0, 15), fill="x")

# --- 拖拽区域 ---
file_path_var = tk.StringVar()
drop_frame = ctk.CTkFrame(main_frame, height=120, corner_radius=12, fg_color="#1c1c1c", border_width=2,
                          border_color="#333333")
drop_frame.pack(pady=5, fill="x")
drop_frame.pack_propagate(False)

drop_icon = ctk.CTkLabel(drop_frame, text="🌀", font=ctk.CTkFont(size=60), text_color="#555555")
drop_icon.place(relx=0.5, rely=0.35, anchor="center")
drop_text = ctk.CTkLabel(drop_frame, text="将机密文件拖拽到此处", text_color="#666666", font=font_bold)
drop_text.place(relx=0.5, rely=0.75, anchor="center")

drop_frame.drop_target_register(DND_FILES)
drop_frame.dnd_bind('<<Drop>>', drop_file)
drop_icon.drop_target_register(DND_FILES)
drop_icon.dnd_bind('<<Drop>>', drop_file)
drop_text.drop_target_register(DND_FILES)
drop_text.dnd_bind('<<Drop>>', drop_file)

# --- 密码区域 ---
pwd_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
pwd_frame.pack(fill="x", pady=20)

row1 = ctk.CTkFrame(pwd_frame, fg_color="transparent")
row1.pack(fill="x", pady=(0, 10))
ctk.CTkLabel(row1, text="访问密钥:", font=font_bold, width=70, anchor="w").pack(side="left")
password_var = tk.StringVar()
pwd_entry = ctk.CTkEntry(row1, textvariable=password_var, show="●", height=38, corner_radius=6)
pwd_entry.pack(side="left", fill="x", expand=True, padx=(10, 10))
toggle_btn = ctk.CTkButton(row1, text="👁", width=40, height=38, fg_color="#333333", hover_color="#444444",
                           command=toggle_password_visibility)
toggle_btn.pack(side="right")

row2 = ctk.CTkFrame(pwd_frame, fg_color="transparent")
row2.pack(fill="x")
ctk.CTkLabel(row2, text="确认密钥:", font=font_bold, width=70, anchor="w").pack(side="left")
confirm_var = tk.StringVar()
confirm_entry = ctk.CTkEntry(row2, textvariable=confirm_var, show="●", height=38, corner_radius=6,
                             placeholder_text="解密可留空")
confirm_entry.pack(side="left", fill="x", expand=True, padx=(10, 50))

# --- 进度条控制台 (商业级升级核心) ---
progress_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
progress_frame.pack(fill="x", pady=(5, 15))

progress_bar = ctk.CTkProgressBar(progress_frame, mode="determinate", height=12, fg_color="#333333",
                                  progress_color="#00a86b")
progress_bar.set(0)
progress_bar.pack(side="left", fill="x", expand=True, padx=(0, 10))

percent_label = ctk.CTkLabel(progress_frame, text="0%", font=font_bold, text_color="#aaaaaa", width=40)
percent_label.pack(side="right")

# --- 操作按钮 ---
action_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
action_frame.pack(fill="x", pady=(10, 0))

encrypt_btn = ctk.CTkButton(action_frame, text="🛡️ 绝对锁定 (加密)", height=42, fg_color="#b30000",
                            hover_color="#cc0000", font=font_bold, command=lambda: trigger_process("encrypt"))
encrypt_btn.pack(side="left", expand=True, padx=(0, 10))

decrypt_btn = ctk.CTkButton(action_frame, text="🔑 授权解锁 (解密)", height=42, fg_color="#00a86b",
                            hover_color="#00c87b", font=font_bold, command=lambda: trigger_process("decrypt"))
decrypt_btn.pack(side="right", expand=True, padx=(10, 0))

pwd_entry.focus()
app.mainloop()
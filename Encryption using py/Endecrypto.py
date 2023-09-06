from pathlib import Path
import tkinter as tk

import sys

from tkinter import Tk, Canvas, Entry, Button, PhotoImage, filedialog, simpledialog, messagebox

from cryptography.fernet import Fernet

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.padding import PKCS7
import os


def tds_encrypt(data, password):
    file_bytes = data

    # Generate a random 8-byte IV
    iv = os.urandom(8)

    # Derive a 24-byte key from the password using PBKDF2
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=24,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Apply PKCS7 padding to the data
    padder = PKCS7(algorithms.TripleDES.block_size).padder()
    padded_data = padder.update(file_bytes) + padder.finalize()

    # Encrypt the data using TripleDES-CBC with the IV and key
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Store the IV, salt, and ciphertext together
    encrypted_data = iv + salt + ciphertext

    return encrypted_data


def tds_decrypt(file_path, password):
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    # Extract the IV and ciphertext from the encrypted data
    iv = encrypted_data[:8]
    salt = encrypted_data[8:24]
    ciphertext = encrypted_data[24:]

    # Derive the key from the password and salt using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=24,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Decrypt the ciphertext using TripleDES-CBC with the IV and key
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding from the decrypted data
    unpadder = PKCS7(algorithms.TripleDES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return unpadded_data


# Encrypt file function
def encrypt_file():
    file_path = path_entry.get()
    file_size = os.path.getsize(file_path)
    password = ''
    while len(password) < 6:
        password = simpledialog.askstring("Password", "Enter a password (minimum 6 characters):", show='*')
        if len(password) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters long")
        elif not password:
            return
    key = Fernet.generate_key()
    fernet = Fernet(key)

    chunk_size = 64 * 1024  # 64KB
    encrypted_file_path = file_path + '.enc'

    with open(file_path, 'rb') as infile, open(encrypted_file_path, 'wb') as outfile:
        # Write the key to the file
        key_file_path = file_path + '.key'
        with open(key_file_path, 'wb') as key_file:
            key_file.write(tds_encrypt(key, password))

        while True:
            raw_chunk = infile.read(chunk_size)
            if not raw_chunk:
                break

            enc_chunk = fernet.encrypt(raw_chunk)
            enc_chunk_size = len(enc_chunk).to_bytes(4, 'big')
            outfile.write(enc_chunk_size + enc_chunk)

    message = f'File {file_path} of size {file_size} bytes encrypted successfully.\nEncrypted file saved as {encrypted_file_path}.\nKey file saved as {key_file_path}.'
    messagebox.showinfo("Encryption Complete", message)

    path_entry.delete(0, tk.END)


def decrypt_file():
    encrypted_file_path = path_entry.get()
    password = ''
    while len(password) < 6:
        password = simpledialog.askstring("Password", "Enter Password to Decrypt the File:", show='*')
        if len(password) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters long")
        elif not password:
            return
    ask_key = tk.Tk()
    ask_key.withdraw()
    key_file_path = filedialog.askopenfilename(filetypes=[("Key Files", "*.key")],
                                               title="Choose the key for the selected File to unlock:")
    ask_key.destroy()

    key = tds_decrypt(key_file_path, password)
    fernet = Fernet(key)

    with open(encrypted_file_path, 'rb') as infile, open(os.path.splitext(encrypted_file_path)[0], 'wb') as outfile:
        while True:
            # Read 4 bytes of data (size)
            size = infile.read(4)
            if size == b'':
                break

            # Convert those 4 bytes into an integer using int.from_bytes(size, "big") (num_bytes)
            num_bytes = int.from_bytes(size, "big")

            # Read num_bytes of encrypted data
            encrypted_data = infile.read(num_bytes)

            # Decrypt this data with Fernet with no problems
            decrypted_data = fernet.decrypt(encrypted_data)
            outfile.write(decrypted_data)

    message = f'File {encrypted_file_path} decrypted successfully.'
    messagebox.showinfo("Decryption Complete", message)

    path_entry.delete(0, tk.END)


def browse_files():
    file_path = filedialog.askopenfilename(title="Select a file to Encrypt/Decrypt")
    path_entry.delete(0, tk.END)
    path_entry.insert(tk.END, file_path)
    if file_path.endswith(".enc"):
        decrypt_button.config(state="normal")
        encrypt_button.config(state="disabled")
    else:
        encrypt_button.config(state="normal")
        decrypt_button.config(state="disabled")


# OUTPUT_PATH = Path(__file__).parent
# ASSETS_PATH = OUTPUT_PATH / Path(r"assets")


# def relative_to_assets(path: str) -> Path:
#     return ASSETS_PATH / Path(path)


basedir = os.path.dirname(__file__)

try:
    from ctypes import windll  # Only exists on Windows.

    myappid = "com.Endcrypt"
    windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
except ImportError:
    pass

window = Tk()
window.iconbitmap(os.path.join(basedir, "icon.ico"))
# Set the app title
window.title("Endecrypto")
# Set the app resolution
window.geometry("640x360")
# Set background color
window.configure(bg="#000000")

canvas = Canvas(
    window,
    bg="#000000",
    height=360,
    width=640,
    bd=0,
    highlightthickness=0,
    relief="ridge"
)

canvas.place(x=0, y=0)
image_image_1 = PhotoImage(
    file=os.path.join(basedir, "image_1.png"))
image_1 = canvas.create_image(
    537.0,
    187.0,
    image=image_image_1
)

canvas.create_text(
    99.0,
    340.0,
    anchor="nw",
    text="ENDECRYPTO is a software still under development............ use it with caution!",
    fill="#FFFFFF",
    font=("Inter", 12 * -1)
)

canvas.create_text(
    208.0,
    13.0,
    anchor="nw",
    text="ENDECRYPTO",
    fill="#FFFFFF",
    font=("Inter Bold", 32 * -1)
)

canvas.create_text(
    36.0,
    83.0,
    anchor="nw",
    text="*First you need to select a file from your device to encrypt or decrypt:",
    fill="#FFFFFF",
    font=("Inter Bold", 15 * -1)
)

entry_image_1 = PhotoImage(
    file=os.path.join(basedir, "entry_1.png"))
entry_bg_1 = canvas.create_image(
    208.0,
    132.0,
    image=entry_image_1
)
path_entry = Entry(
    bd=0,
    bg="#D9D9D9",
    fg="#000716",
    highlightthickness=0,
)
path_entry.place(
    x=33.0,
    y=122.0,
    width=350.0,
    height=18.0
)

button_image_1 = PhotoImage(
    file=os.path.join(basedir, "button_1.png"))
encrypt_button = Button(
    image=button_image_1,
    borderwidth=0,
    highlightthickness=0,
    relief="flat",
    command=lambda: encrypt_file()
)
encrypt_button.place(
    x=106.0,
    y=180.0,
    width=46.0,
    height=14.0
)

button_image_2 = PhotoImage(
    file=os.path.join(basedir, "button_2.png"))
decrypt_button = Button(
    image=button_image_2,
    borderwidth=0,
    highlightthickness=0,
    relief="flat",
    command=lambda: decrypt_file()
)
decrypt_button.place(
    x=225.0,
    y=180.0,
    width=46.0,
    height=14.0
)

button_image_3 = PhotoImage(
    file=os.path.join(basedir, "button_3.png"))
browse_button = Button(
    image=button_image_3,
    borderwidth=0,
    highlightthickness=0,
    relief="flat",
    command=lambda: browse_files()
)
browse_button.place(
    x=391.0,
    y=125.0,
    width=41.0,
    height=14.0
)

canvas.create_text(
    33.0,
    230.0,
    anchor="nw",
    text="*NOTE: KEEP YOUR PASSWORD AND THE KEY FILE IN A SAFE",
    fill="#FFFFFF",
    font=("Inter Light", 12 * -1)
)

canvas.create_text(
    33.0,
    245.0,
    anchor="nw",
    text="PLACE. YOU WILL NEED THE ENCRYPTED FILE AS WELL AS THE",
    fill="#FFFFFF",
    font=("Inter Light", 12 * -1)
)

canvas.create_text(
    33.0,
    260.0,
    anchor="nw",
    text="KEY FILE ALONG WITH THE PASSWORD FOR DECRYPTION TO",
    fill="#FFFFFF",
    font=("Inter Light", 12 * -1)
)

canvas.create_text(
    33.0,
    275.0,
    anchor="nw",
    text="BE SUCCESSFUL",
    fill="#FFFFFF",
    font=("Inter Light", 12 * -1)
)
window.resizable(False, False)
window.mainloop()

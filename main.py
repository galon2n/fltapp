import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import flet as ft
from flet import FilePicker, ProgressBar

# Function to get all PDF files from the directory
def fetch_pdfs(directory):
    pdf_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.pdf'):
                pdf_files.append(os.path.join(root, file))
    return pdf_files

# AES Encryption
BLOCK_SIZE = 16

def encrypt_file(file_path, password):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        cipher = AES.new(password.encode('utf-8'), AES.MODE_CBC)
        encrypted_data = cipher.iv + cipher.encrypt(pad(data, BLOCK_SIZE))

        with open(file_path + '.enc', 'wb') as f:
            f.write(encrypted_data)
        return True
    except Exception as e:
        print(f"Error encrypting {file_path}: {e}")
        return False

def decrypt_file(file_path, password):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        iv = data[:BLOCK_SIZE]
        encrypted_data = data[BLOCK_SIZE:]

        cipher = AES.new(password.encode('utf-8'), AES.MODE_CBC, iv=iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), BLOCK_SIZE)

        original_file_path = file_path.replace('.enc', '')
        with open(original_file_path, 'wb') as f:
            f.write(decrypted_data)
        return True
    except Exception as e:
        print(f"Error decrypting {file_path}: {e}")
        return False

# Flet app

def main(page: ft.Page):
    page.title = "PDF Encrypt/Decrypt"
    page.window_width = 400
    page.window_height = 600

    password_input = ft.TextField(label="Password", password=True, width=300)
    enc_button = ft.ElevatedButton("Encrypt", width=150)
    dec_button = ft.ElevatedButton("Decrypt", width=150)
    progress_bar = ProgressBar(width=300, value=0)

    file_list = ft.ListView(height=200, width=300)
    selected_files = []

    # Fetch PDFs when permission is granted
    def fetch_files(e):
        directory = "/storage/emulated/0/"  # Root directory for Android
        files = fetch_pdfs(directory)
        file_list.controls.clear()
        selected_files.clear()
        for file in files:
            selected_files.append(file)
            file_list.controls.append(ft.Text(file, size=12))
        page.update()

    def process_files(e):
        if not password_input.value:
            page.dialog = ft.AlertDialog(title=ft.Text("Error"), content=ft.Text("Password is required!"))
            page.dialog.open = True
            page.update()
            return

        is_encrypt = e.control == enc_button
        progress_bar.value = 0
        step = 1 / len(selected_files) if selected_files else 1

        for i, file_path in enumerate(selected_files):
            if is_encrypt:
                encrypt_file(file_path, password_input.value)
            else:
                decrypt_file(file_path, password_input.value)
            progress_bar.value += step
            page.update()

        progress_bar.value = 1
        page.dialog = ft.AlertDialog(title=ft.Text("Success"), content=ft.Text("Operation completed!"))
        page.dialog.open = True
        page.update()

    # Layout
    page.add(
        password_input,
        ft.Row([enc_button, dec_button], alignment=ft.MainAxisAlignment.CENTER),
        progress_bar,
        ft.Text("PDF Files:"),
        file_list,
        ft.ElevatedButton("Fetch Files", on_click=fetch_files),
    )

    enc_button.on_click = process_files
    dec_button.on_click = process_files

ft.app(target=main)

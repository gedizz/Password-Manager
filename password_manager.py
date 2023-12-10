import tkinter as tk
from tkinter import simpledialog, messagebox
from cryptography.fernet import Fernet
import sqlite3
import os

# Path for the key file
key_file = 'encryption.key'

# Function to load or create an encryption key
def load_or_create_key():
    if os.path.exists(key_file):
        with open(key_file, 'rb') as file:
            return file.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, 'wb') as file:
            file.write(key)
        return key

# Load or create the key and instantiate a Fernet object
key = load_or_create_key()
cipher_suite = Fernet(key)

# Initialize database connection
conn = sqlite3.connect('passwords.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS passwords
             (id INTEGER PRIMARY KEY, service TEXT, encrypted_password TEXT)''')
conn.commit()


# Encryption/Decryption functions
def encrypt_password(password):
    return cipher_suite.encrypt(password.encode()).decode()


def decrypt_password(encrypted_password):
    return cipher_suite.decrypt(encrypted_password.encode()).decode()


# Database interaction functions
def add_password(service, password):
    encrypted_password = encrypt_password(password)
    c.execute("INSERT INTO passwords (service, encrypted_password) VALUES (?, ?)", (service, encrypted_password))
    conn.commit()
    update_service_list()


def get_password(service):
    c.execute("SELECT encrypted_password FROM passwords WHERE service=?", (service,))
    result = c.fetchone()
    if result:
        return decrypt_password(result[0])
    return None


def delete_password(service):
    c.execute("DELETE FROM passwords WHERE service=?", (service,))
    conn.commit()
    update_service_list()


def update_service_list():
    service_list.delete(0, tk.END)
    c.execute("SELECT service FROM passwords")
    for service in c.fetchall():
        service_list.insert(tk.END, service[0])


# UI functions
def save_password():
    service = simpledialog.askstring("Service", "Enter the name of the service:")
    if service:
        password = simpledialog.askstring("Password", "Enter the password:", show="*")
        if password:
            add_password(service, password)


def show_password():
    selected_service = service_list.get(tk.ANCHOR)
    if selected_service:
        password = get_password(selected_service)
        if password:
            messagebox.showinfo("Password Info", f"Password for {selected_service}: {password}")
        else:
            messagebox.showinfo("Password Info", "Password not found")


def remove_password():
    selected_service = service_list.get(tk.ANCHOR)
    if selected_service:
        delete_password(selected_service)


# Creating main window
root = tk.Tk()
root.title("Password Manager")

# Layout
tk.Button(root, text="Add Password", command=save_password).grid(row=0, column=0)
tk.Button(root, text="Show Password", command=show_password).grid(row=0, column=1)
tk.Button(root, text="Delete Password", command=remove_password).grid(row=0, column=2)

service_list = tk.Listbox(root)
service_list.grid(row=1, columnspan=3)
update_service_list()


root.mainloop()
conn.close()

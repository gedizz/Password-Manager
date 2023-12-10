import tkinter as tk
from tkinter import simpledialog, messagebox, ttk
from cryptography.fernet import Fernet
import sqlite3
import keyring

# Using keyring, we can access windows' default key service
def load_or_create_key():
    key = keyring.get_password('password_manager', 'encryption_key')
    if key is None:
        key = Fernet.generate_key().decode()
        keyring.set_password('password_manager', 'encryption_key', key)
    return key.encode()

# Load or create the key and instantiate a Fernet object
key = load_or_create_key()
cipher_suite = Fernet(key)

# Initialize database connection - typically this would be something secured over the web
# currently we can access it locally which is not good
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

# Styling
style = ttk.Style()
style.configure('TButton', font=('Arial', 10))
style.configure('TLabel', font=('Arial', 10))
style.configure('TListbox', font=('Arial', 10))

# Main frame
main_frame = ttk.Frame(root, padding="10")
main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

# Layout inside main frame
ttk.Button(main_frame, text="Add Password", command=save_password).grid(row=0, column=0, padx=5, pady=5)
ttk.Button(main_frame, text="Show Password", command=show_password).grid(row=0, column=1, padx=5, pady=5)
ttk.Button(main_frame, text="Delete Password", command=remove_password).grid(row=0, column=2, padx=5, pady=5)

service_list = tk.Listbox(main_frame, height=10, width=50)
service_list.grid(row=1, columnspan=3, pady=5)
update_service_list()

# Resizable configuration
root.grid_columnconfigure(0, weight=1)
root.grid_rowconfigure(0, weight=1)
main_frame.grid_columnconfigure(0, weight=1)
main_frame.grid_rowconfigure(1, weight=1)

# Start the GUI
root.mainloop()
# Ensure the connection is closed properly
conn.close()

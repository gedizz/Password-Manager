import tkinter as tk
from tkinter import simpledialog, messagebox, ttk
from cryptography.fernet import Fernet
import sqlite3
import keyring
import bcrypt


# Using keyring, we can access windows' default key service
def load_or_create_key():
    key = keyring.get_password('password_manager', 'encryption_key')
    if key is None:
        key = Fernet.generate_key().decode()
        keyring.set_password('password_manager', 'encryption_key', key)
    return key.encode()


def register_user():
    new_username = simpledialog.askstring("Register", "Choose a username:")
    if new_username:
        new_password = simpledialog.askstring("Register", "Choose a password:", show="*")
        if new_password:
            create_user(new_username, new_password)
            messagebox.showinfo("Registration", "Registration successful. Please log in.")


# Load or create the key and instantiate a Fernet object
key = load_or_create_key()
cipher_suite = Fernet(key)


current_user = None

# Encryption/Decryption functions
def encrypt_password(password):
    return cipher_suite.encrypt(password.encode()).decode()


def decrypt_password(encrypted_password):
    return cipher_suite.decrypt(encrypted_password.encode()).decode()


# Initialize database connection
# ...

# Initialize database connection
conn = sqlite3.connect('passwords.db')
c = conn.cursor()

# Create tables if they don't exist
c.execute('''CREATE TABLE IF NOT EXISTS users
             (username TEXT PRIMARY KEY, password_hash TEXT)''')

# Check if 'username' column exists in 'passwords' table and add it if it doesn't
c.execute('''SELECT count(*) FROM pragma_table_info('passwords') WHERE name='username' ''')
if c.fetchone()[0] == 0:
    c.execute('''ALTER TABLE passwords ADD COLUMN username TEXT''')

c.execute('''CREATE TABLE IF NOT EXISTS passwords
             (id INTEGER PRIMARY KEY, username TEXT, service TEXT, encrypted_password TEXT)''')

conn.commit()




def create_user(username, password):
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed))
    conn.commit()


def verify_user(username, password):
    c.execute("SELECT password_hash FROM users WHERE username=?", (username,))
    user = c.fetchone()
    if user and bcrypt.checkpw(password.encode(), user[0]):
        return True
    return False


# Database interaction functions
def add_password(username, service, password):
    encrypted_password = encrypt_password(password)
    c.execute("INSERT INTO passwords (username, service, encrypted_password) VALUES (?, ?, ?)",
              (username, service, encrypted_password))
    conn.commit()
    update_service_list(username)

def get_password(username, service):
    c.execute("SELECT encrypted_password FROM passwords WHERE username=? AND service=?",
              (username, service))
    result = c.fetchone()
    if result:
        return decrypt_password(result[0])
    return None

def delete_password(username, service):
    c.execute("DELETE FROM passwords WHERE username=? AND service=?", (username, service))
    conn.commit()
    update_service_list(username)

def update_service_list(username):
    service_list.delete(0, tk.END)
    c.execute("SELECT service FROM passwords WHERE username=?", (username,))
    for service in c.fetchall():
        service_list.insert(tk.END, service[0])


# UI functions
def save_password():
    service = simpledialog.askstring("Service", "Enter the name of the service:")
    if service:
        password = simpledialog.askstring("Password", "Enter the password:", show="*")
        if password:
            add_password(current_user, service, password)

def show_password():
    selected_service = service_list.get(tk.ANCHOR)
    if selected_service:
        password = get_password(current_user, selected_service)
        if password:
            messagebox.showinfo("Password Info", f"Password for {selected_service}: {password}")
        else:
            messagebox.showinfo("Password Info", "Password not found")

def remove_password():
    selected_service = service_list.get(tk.ANCHOR)
    if selected_service:
        delete_password(current_user, selected_service)



# Login Functionality
def login():
    global current_user
    username = username_entry.get()
    password = password_entry.get()
    if verify_user(username, password):
        current_user = username
        login_frame.grid_remove()
        main_frame.grid()
        update_service_list(current_user)  # Update the list with user-specific passwords
    else:
        messagebox.showerror("Login Failed", "Incorrect username or password")


# Creating main window
root = tk.Tk()
root.title("Password Manager")

# Styling
style = ttk.Style()
style.configure('TButton', font=('Arial', 10))
style.configure('TLabel', font=('Arial', 10))
style.configure('TListbox', font=('Arial', 10))



# Login Frame (Using grid)
login_frame = ttk.Frame(root, padding="10")
login_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

# Add a registration button to the login frame
register_button = ttk.Button(login_frame, text="Register", command=register_user)
register_button.grid(row=3, columnspan=2)

ttk.Label(login_frame, text="Username:").grid(row=0, column=0)
username_entry = ttk.Entry(login_frame)
username_entry.grid(row=0, column=1)

ttk.Label(login_frame, text="Password:").grid(row=1, column=0)
password_entry = ttk.Entry(login_frame, show="*")
password_entry.grid(row=1, column=1)

ttk.Button(login_frame, text="Login", command=login).grid(row=2, columnspan=2)

# Main frame (Using grid)
main_frame = ttk.Frame(root, padding="10")
main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

# Layout inside main frame (Using grid)
ttk.Button(main_frame, text="Add Password", command=save_password).grid(row=0, column=0, padx=5, pady=5)
ttk.Button(main_frame, text="Show Password", command=show_password).grid(row=0, column=1, padx=5, pady=5)
ttk.Button(main_frame, text="Delete Password", command=remove_password).grid(row=0, column=2, padx=5, pady=5)

service_list = tk.Listbox(main_frame, height=10, width=50)
service_list.grid(row=1, columnspan=3, pady=5)


# Resizable configuration
root.grid_columnconfigure(0, weight=1)
root.grid_rowconfigure(0, weight=1)
main_frame.grid_columnconfigure(0, weight=1)
main_frame.grid_rowconfigure(1, weight=1)

# Initially hide main frame
main_frame.grid_remove()

# ... [rest of the code]


# Start the GUI
root.mainloop()
# Ensure the connection is closed properly
conn.close()

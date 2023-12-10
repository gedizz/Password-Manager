import tkinter as tk
from tkinter import simpledialog, messagebox, ttk
from cryptography.fernet import Fernet
import sqlite3
import keyring
import bcrypt
from audit_logger import AuditLogger
import atexit

# Logging
logger = AuditLogger()

def log_event(event_type, username, details=""):
    logger.log(event_type, username, details)

# Key management
def load_or_create_key():
    key = keyring.get_password('password_manager', 'encryption_key')
    if key is None:
        key = Fernet.generate_key().decode()
        keyring.set_password('password_manager', 'encryption_key', key)
    return key.encode()

# User registration
def register_user():
    new_username = simpledialog.askstring("Register", "Choose a username:")
    if new_username:
        while True:
            new_password = simpledialog.askstring("Register",
                "Choose a password:\n\n" +
                "A strong password must have:\n" +
                "- At least 8 characters\n" +
                "- Include numbers and letters\n" +
                "- Mix of uppercase and lowercase letters\n" +
                "- Special characters (e.g., !@#$%^&*)\n",
                show="*")
            if new_password:
                password_strength = assess_password_strength(new_password)
                if password_strength == "Strong":
                    if create_user(new_username, new_password):
                        messagebox.showinfo("Registration", "Registration successful. Please log in.")
                        log_event("Registration", new_username)
                        break
                    else:
                        messagebox.showwarning("Registration Failed", "Username already exists. Please choose a different username.")
                        log_event("Registration Failed", new_username)
                        return  # Exit registration process
                else:
                    messagebox.showwarning("Weak Password", "Your password is not strong enough. Please try again.")
            else:
                break

# Key and cipher initialization
key = load_or_create_key()
cipher_suite = Fernet(key)
current_user = None

# Encryption/Decryption functions
def encrypt_password(password):
    return cipher_suite.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    return cipher_suite.decrypt(encrypted_password.encode()).decode()

# Database initialization
conn = sqlite3.connect('passwords.db')
c = conn.cursor()

# Create tables if they don't exist
c.execute('''CREATE TABLE IF NOT EXISTS users
             (username TEXT PRIMARY KEY, password_hash TEXT)''')

c.execute('''CREATE TABLE IF NOT EXISTS passwords
             (id INTEGER PRIMARY KEY, username TEXT, service TEXT, encrypted_password TEXT, strength TEXT)''')


# Utils
def update_logged_in_label():
    if current_user:
        logged_in_label.config(text=f"Logged in as: {current_user}")
    else:
        logged_in_label.config(text="")


def create_user(username, password):
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    if c.fetchone():
        log_event("User Already Exists", username)
        return False  # User already exists

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed))
    conn.commit()
    log_event("User Created", username)
    return True

def verify_user(username, password):
    c.execute("SELECT password_hash FROM users WHERE username=?", (username,))
    user = c.fetchone()
    if user and bcrypt.checkpw(password.encode(), user[0]):
        log_event("User Verified", username)
        return True
    log_event("User Verification Failed", username)
    return False

def assess_password_strength(password):
    length = len(password)
    has_numbers = any(char.isdigit() for char in password)
    has_uppercase = any(char.isupper() for char in password)
    has_lowercase = any(char.islower() for char in password)
    has_special = any(not char.isalnum() for char in password)

    if length >= 8 and has_numbers and has_uppercase and has_lowercase and has_special:
        return "Strong"
    elif length >= 8 and has_numbers and (has_uppercase or has_lowercase):
        return "Medium"
    else:
        return "Weak"

# Database interaction functions
def add_password(username, service, password):
    encrypted_password = encrypt_password(password)
    password_strength = assess_password_strength(password)
    c.execute("INSERT INTO passwords (username, service, encrypted_password, strength) VALUES (?, ?, ?, ?)",
              (username, service, encrypted_password, password_strength))
    conn.commit()
    update_service_list(username)
    log_event("Added Password to DB", username)

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
    service_list.delete(*service_list.get_children())
    c.execute("SELECT service, strength FROM passwords WHERE username=?", (username,))
    for i, (service, strength) in enumerate(c.fetchall()):
        color = '#ffcccb' if strength == 'Weak' else '#ffffcc' if strength == 'Medium' else '#ccffcc'
        tag_name = f'colored_{i}'  # Unique tag for each row
        service_list.insert('', 'end', values=(service, strength), tags=(tag_name,))
        service_list.tag_configure(tag_name, background=color)


# UI functions
def prompt_for_account_password():
    account_password = custom_askstring("Account Access", "Enter your account access password:", show="*")
    if account_password:
        return verify_user(current_user, account_password)
    return False


def save_password():
    service = custom_askstring("Service", "Enter the name of the service:")
    if service:
        password = custom_askstring("Password", "Enter the password:", show="*")
        if password:
            add_password(current_user, service, password)
            log_event("Save Password", current_user)

def show_password():
    if prompt_for_account_password():
        selected_item = service_list.selection()
        if selected_item:
            item = service_list.item(selected_item[0])
            selected_service = item['values'][0]
            c.execute("SELECT encrypted_password FROM passwords WHERE username=? AND service=?",
                      (current_user, selected_service))
            result = c.fetchone()
            if result:
                decrypted_password = decrypt_password(result[0])
                messagebox.showinfo("Password Info", f"Password for {selected_service}: {decrypted_password}")
                log_event("Password Found", selected_service)
            else:
                messagebox.showinfo("Password Info", "Password not found")

def remove_password():
    if prompt_for_account_password():
        selected_items = service_list.selection()
        if selected_items:
            selected_service = service_list.item(selected_items[0])['values'][0]
            delete_password(current_user, selected_service)
            log_event("Deleted Password", selected_service)

def custom_askstring(title, prompt, show=None):
    def on_ok():
        nonlocal user_input
        user_input = entry.get()
        dialog.destroy()

    user_input = None
    dialog = tk.Toplevel(root)
    dialog.title(title)
    dialog.grab_set()  # Makes the dialog modal

    tk.Label(dialog, text=prompt).pack(padx=10, pady=10)
    entry = ttk.Entry(dialog, show=show)
    entry.pack(padx=10, pady=10)
    entry.focus_set()

    ok_button = ttk.Button(dialog, text="OK", command=on_ok)
    ok_button.pack(pady=(0, 10))

    dialog.transient(root)  # Dialog window is related to the main app window
    dialog.wait_window()  # Wait here until the dialog is closed

    return user_input


def change_password():
    if prompt_for_account_password():
        selected_item = service_list.selection()
        if selected_item:
            selected_service = service_list.item(selected_item[0])['values'][0]
            new_password = custom_askstring("Change Password", f"Enter a new password for {selected_service}:", show="*")
            if new_password:
                encrypted_password = encrypt_password(new_password)
                c.execute("UPDATE passwords SET encrypted_password=? WHERE username=? AND service=?",
                          (encrypted_password, current_user, selected_service))
                conn.commit()
                messagebox.showinfo("Change Password", "Password changed successfully.")
                log_event("Change Password", f"{current_user} - {selected_service}")
            else:
                messagebox.showinfo("Change Password", "Password change canceled.")
        else:
            messagebox.showinfo("Change Password", "Please select a service to change its password.")




# Login/logout Functionality
def login():
    global current_user
    username = username_entry.get()
    password = password_entry.get()
    if verify_user(username, password):
        current_user = username
        login_frame.grid_remove()
        main_frame.grid()
        update_service_list(current_user)  # Update the list with user-specific passwords
        log_event("Login", current_user)
        update_logged_in_label()  # Update the label after login
    else:
        messagebox.showerror("Login Failed", "Incorrect username or password")
        log_event("Login Failed", username)

def logout():
    global current_user
    main_frame.grid_remove()
    login_frame.grid()
    username_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)
    log_event("Logout", current_user)
    current_user = None
    update_logged_in_label()  # Update the label after logout

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


# Bottom buttons and displays
change_password_button = ttk.Button(main_frame, text="Change Password", command=change_password)
change_password_button.grid(row=2, column=0, padx=5, pady=5)

logout_button = ttk.Button(main_frame, text="Logout", command=logout)
logout_button.grid(row=2, column=1, padx=5, pady=5)

# Add a label to display the logged-in username
logged_in_label = ttk.Label(main_frame, text="")
logged_in_label.grid(row=2, column=2, padx=5, pady=5)



# Layout inside main frame (Using grid)
ttk.Button(main_frame, text="Add Password", command=save_password).grid(row=0, column=0, padx=5, pady=5)
ttk.Button(main_frame, text="Show Password", command=show_password).grid(row=0, column=1, padx=5, pady=5)
ttk.Button(main_frame, text="Delete Password", command=remove_password).grid(row=0, column=2, padx=5, pady=5)

# Define columns
columns = ('service', 'strength')
service_list = ttk.Treeview(main_frame, columns=columns, show='headings')
service_list.heading('service', text='Service')
service_list.heading('strength', text='Strength')
service_list.column('service', width=150)
service_list.column('strength', width=100)

# Position the Treeview
service_list.grid(row=1, columnspan=3, pady=5, sticky='nsew')

# Resizable configuration
root.grid_columnconfigure(0, weight=1)
root.grid_rowconfigure(0, weight=1)
main_frame.grid_columnconfigure(1, weight=1)
main_frame.grid_rowconfigure(1, weight=1)

# Initially hide main frame
main_frame.grid_remove()

atexit.register(lambda: logger.close())

# Start the GUI
root.mainloop()
# Ensure the connection is closed properly
conn.close()

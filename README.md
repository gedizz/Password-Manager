# Password Manager Application

## Introduction

Welcome to the Password Manager Application! This program allows you to securely store and manage your passwords for various services. It uses encryption and hashing techniques to keep your passwords safe and follows best(ish) security practices to protect your data.

## Table of Contents

- [Getting Started](#getting-started)
- [Features](#features)
- [Security Best Practices](#security-best-practices)
- [Contributing](#contributing)

## Getting Started

To get started with the Password Manager Application, follow these steps:

1. Build the application using `pyinstaller --onefile --icon=logo.ico --name=PasswordManager password_manager.py` in your terminal
2. Execute the PasswordManager.exe located in /dist

## Features

- **User Registration**: Create a new account with a username and a strong password.
- **Password Storage**: Safely store passwords for various services.
- **Password Strength Assessment**: Check the strength of your passwords.
- **Password Encryption**: Passwords are encrypted before storage for added security.
- **Secure User Authentication**: Verify users with bcrypt hashing.
- **Audit Logging**: Log important events and actions for security monitoring.

## Security Best Practices

To ensure the security of your data while using the Password Manager Application, follow these best practices:

1. **Use Strong Passwords**: When creating an account or changing passwords, use strong passwords that include a mix of uppercase and lowercase letters, numbers, and special characters.

2. **Keep Your Master Password Secure**: The master password used to log into the application should be kept secret and not shared with anyone. Use a strong master password.

3. **Regularly Update Passwords**: Periodically change passwords for your stored services to enhance security.

4. **Log Out When Not in Use**: Always log out of the application when you're not actively using it to prevent unauthorized access.

5. **Backup Your Data**: Regularly back up your password data to ensure you don't lose access to your passwords.

6. **Secure Your Machine**: Ensure that your computer or device is secure with up-to-date antivirus and firewall software.

7. **Use Unique Service Names**: When adding passwords for different services, use unique service names to avoid confusion and prevent overwriting.

8. **Check Password Strength**: Before saving a password, assess its strength. Use strong passwords for critical accounts.

9. **Audit Logs**: Periodically review the audit logs for any suspicious activities.

## Contributing

Contributions to this project are welcome! If you have any suggestions, bug reports, or want to contribute code, please create an issue or submit a pull request on GitHub.

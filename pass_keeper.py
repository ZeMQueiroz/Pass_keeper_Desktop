import sqlite3
from cryptography.fernet import Fernet
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
import os
import bcrypt
from dotenv import load_dotenv
import subprocess

# Load environment variables from a .env file
load_dotenv()

# Initialize rich console
console = Console()

DATABASE = 'passwords.db'
KEY_FILE = 'secret.key'

def generate_key():
    """Generate a new 32-byte URL-safe base64-encoded key."""
    return Fernet.generate_key().decode()

def load_key():
    """Load the secret key from an environment variable or generate a new one."""
    key = os.getenv('ENCRYPTION_KEY')
    if not key:
        if os.path.exists(KEY_FILE):
            with open(KEY_FILE, 'r') as key_file:
                key = key_file.read().strip()
        else:
            key = generate_key()
            with open(KEY_FILE, 'w') as key_file:
                key_file.write(key)
            with open('.env', 'a') as env_file:
                env_file.write(f"\nENCRYPTION_KEY={key}")
    # Validate the key length
    try:
        Fernet(key.encode())
    except ValueError:
        console.print("[bold red]Invalid encryption key. Generating a new one.[/bold red]")
        key = generate_key()
        with open(KEY_FILE, 'w') as key_file:
            key_file.write(key)
        with open('.env', 'a') as env_file:
            env_file.write(f"\nENCRYPTION_KEY={key}")
    return key.encode()

# Load the encryption key
key = load_key()
cipher_suite = Fernet(key)

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def initialize_database():
    with get_db_connection() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        conn.commit()

def encrypt_password(password):
    return cipher_suite.encrypt(password.encode())

def decrypt_password(encrypted_password):
    return cipher_suite.decrypt(encrypted_password).decode()

def store_password(service, username, password):
    encrypted_password = encrypt_password(password)
    with get_db_connection() as conn:
        conn.execute("INSERT INTO passwords (service, username, password) VALUES (?, ?, ?)",
                     (service, username, encrypted_password))
        conn.commit()

def retrieve_password(service, username):
    with get_db_connection() as conn:
        result = conn.execute("SELECT password FROM passwords WHERE service = ? AND username = ?", 
                              (service, username)).fetchone()
        if result:
            return decrypt_password(result['password'])
        else:
            return None

def list_services():
    with get_db_connection() as conn:
        result = conn.execute("SELECT DISTINCT service FROM passwords").fetchall()
        return [row['service'] for row in result]

def list_users(service):
    with get_db_connection() as conn:
        result = conn.execute("SELECT username FROM passwords WHERE service = ?", (service,)).fetchall()
        return [row['username'] for row in result]

def edit_password(service, username, new_password):
    encrypted_password = encrypt_password(new_password)
    with get_db_connection() as conn:
        conn.execute("UPDATE passwords SET password = ? WHERE service = ? AND username = ?",
                     (encrypted_password, service, username))
        conn.commit()

def delete_service(service):
    with get_db_connection() as conn:
        conn.execute("DELETE FROM passwords WHERE service = ?", (service,))
        conn.commit()

def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

def check_password(stored_hash, provided_password):
    return bcrypt.checkpw(provided_password.encode(), stored_hash.encode())

def setup_master_password():
    master_password = Prompt.ask("Set master password", password=True)
    MASTER_PASSWORD_HASH = hash_password(master_password)
    with open('.env', 'a') as f:
        f.write(f"\nMASTER_PASSWORD_HASH={MASTER_PASSWORD_HASH}")
    return MASTER_PASSWORD_HASH

def change_master_password():
    security_answer = Prompt.ask("What's the name of my first pet?")
    if security_answer.lower() == "jackie":
        new_password = Prompt.ask("Enter new master password", password=True)
        new_password_hash = hash_password(new_password)
        with open('.env', 'r') as file:
            data = file.readlines()
        with open('.env', 'w') as file:
            for line in data:
                if line.strip().startswith("MASTER_PASSWORD_HASH"):
                    file.write(f"MASTER_PASSWORD_HASH={new_password_hash}\n")
                else:
                    file.write(line)
        console.print("[bold green]\nMaster password changed successfully![/bold green]\n")
    else:
        console.print("[bold red]\nIncorrect answer. Returning to main menu.\n[/bold red]")

def authenticate_user():
    MASTER_PASSWORD_HASH = os.getenv('MASTER_PASSWORD_HASH')
    if not MASTER_PASSWORD_HASH:
        MASTER_PASSWORD_HASH = setup_master_password()
    
    entered_password = Prompt.ask("Enter master password", password=True)
    
    if not check_password(MASTER_PASSWORD_HASH, entered_password):
        console.print("[bold red]Invalid master password. Exiting.[/bold red]")
        return False
    return True

def print_menu():
    menu = Table(title="Password Manager", title_style="bold cyan")
    menu.add_column("Option", style="bold", justify="right")
    menu.add_column("Description", style="bold cyan")

    options = [
        ("1", "Store a new password"),
        ("2", "Retrieve an existing password"),
        ("3", "List all services"),
        ("4", "Change master password"),
        ("5", "Edit a password"),
        ("6", "Delete a service"),
        ("7", "Exit"),
    ]

    for option, description in options:
        menu.add_row(option, description)
    
    console.print(menu)

def main():
    initialize_database()

    if not authenticate_user():
        return

    while True:
        print_menu()
        choice = Prompt.ask("Enter your choice", choices=["1", "2", "3", "4", "5", "6", "7"], default="7")
        if choice == '1':
            service = Prompt.ask("Enter the service name")
            username = Prompt.ask("Enter the username")
            password = Prompt.ask("Enter the password", password=True)
            store_password(service, username, password)
            console.print("[bold green]\nPassword stored successfully![/bold green]\n")
        elif choice == '2':
            services = list_services()
            if services:
                table = Table(title="Services", title_style="bold cyan")
                table.add_column("Service", style="cyan", no_wrap=True)
                for service in services:
                    table.add_row(service)
                console.print(table)
                service = Prompt.ask("Enter the service name", choices=services, show_choices=False)

                users = list_users(service)
                if users:
                    table = Table(title=f"Users for {service}", title_style="bold cyan")
                    table.add_column("Username", style="cyan", no_wrap=True)
                    for user in users:
                        table.add_row(user)
                    console.print(table)
                    username = Prompt.ask("Enter the username", choices=[user for user in users], show_choices=False)
                    password = retrieve_password(service, username)
                    if password:
                        console.print(f"[bold green]\nThe password for {username} on {service} is: {password}[/bold green]\n")
                    else:
                        console.print("[bold red]\nNo password found for this service and username.[/bold red]\n")
                else:
                    console.print("[bold red]\nNo users found for this service.[/bold red]\n")
            else:
                console.print("[bold red]\nNo services found.[/bold red]\n")
        elif choice == '3':
            services = list_services()
            table = Table(title="Services", title_style="bold cyan")
            table.add_column("Service", style="cyan", no_wrap=True)
            if services:
                for service in services:
                    table.add_row(service)
            else:
                console.print("[bold red]\nNo services found.[/bold red]")
            console.print(table)
            console.print()
        elif choice == '4':
            change_master_password()
        elif choice == '5':
            services = list_services()
            if not services:
                console.print("[bold red]\nNo services found to edit.[/bold red]\n")
                continue

            table = Table(title="Services", title_style="bold cyan")
            table.add_column("Service", style="cyan", no_wrap=True)
            for service in services:
                table.add_row(service)
            console.print(table)
            service = Prompt.ask("Enter the service name", choices=services, show_choices=False)

            if service not in services:
                console.print("[bold red]\nService not found. Returning to main menu.\n[/bold red]")
                continue

            users = list_users(service)
            if not users:
                console.print("[bold red]\nNo users found for this service.[/bold red]\n")
                continue

            table = Table(title=f"Users for {service}", title_style="bold cyan")
            table.add_column("Username", style="cyan", no_wrap=True)
            for user in users:
                table.add_row(user)
            console.print(table)
            username = Prompt.ask("Enter the username", choices=[user for user in users], show_choices=False)

            if username not in users:
                console.print("[bold red]\nUser not found. Returning to main menu.\n[/bold red]")
                continue

            new_password = Prompt.ask("Enter the new password", password=True)
            edit_password(service, username, new_password)
            console.print("[bold green]\nPassword updated successfully![/bold green]\n")
        elif choice == '6':
            services = list_services()
            if not services:
                console.print("[bold red]\nNo services found to delete.[/bold red]\n")
                continue

            table = Table(title="Services", title_style="bold cyan")
            table.add_column("Service", style="cyan", no_wrap=True)
            for service in services:
                table.add_row(service)
            console.print(table)
            service = Prompt.ask("Enter the service name to delete", choices=services, show_choices=False)

            if service not in services:
                console.print("[bold red]\nService not found. Returning to main menu.\n[/bold red]")
                continue

            delete_service(service)
            console.print("[bold green]\nService deleted successfully![/bold green]\n")
        elif choice == '7':
            console.print("[bold cyan]\nExiting Password Manager. Goodbye![/bold cyan]\n")
            subprocess.run(["osascript", "-e", 'tell application "iTerm" to close the first window'])
            break
        else:
            console.print("[bold red]\nInvalid choice, please try again.[/bold red]\n")

if __name__ == '__main__':
    main()

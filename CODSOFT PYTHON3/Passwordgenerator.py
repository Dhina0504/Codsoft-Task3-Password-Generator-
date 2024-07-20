import tkinter as tk
from tkinter import messagebox
import random
import string

class PasswordGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Generator")

        # Configure root window
        self.root.geometry("400x300")
        self.root.config(bg="#f0f0f0")

        # Title section
        self.title_frame = tk.Frame(self.root, bg="#4caf50", pady=10)
        self.title_frame.pack(fill="x")
        self.title_label = tk.Label(self.title_frame, text="Password Generator", bg="#4caf50", fg="white", font=("Helvetica", 16))
        self.title_label.pack()

        # Options section
        self.options_frame = tk.Frame(self.root, bg="#ffeb3b", pady=10)
        self.options_frame.pack(fill="x", padx=10, pady=5)

        self.length_label = tk.Label(self.options_frame, text="Length:", bg="#ffeb3b")
        self.length_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.length_var = tk.IntVar(value=12)
        self.length_entry = tk.Entry(self.options_frame, textvariable=self.length_var)
        self.length_entry.grid(row=0, column=1, padx=5, pady=5)

        self.include_uppercase = tk.BooleanVar(value=True)
        self.uppercase_check = tk.Checkbutton(self.options_frame, text="Include Uppercase", variable=self.include_uppercase, bg="#ffeb3b")
        self.uppercase_check.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky="w")

        self.include_numbers = tk.BooleanVar(value=True)
        self.numbers_check = tk.Checkbutton(self.options_frame, text="Include Numbers", variable=self.include_numbers, bg="#ffeb3b")
        self.numbers_check.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky="w")

        self.include_symbols = tk.BooleanVar(value=True)
        self.symbols_check = tk.Checkbutton(self.options_frame, text="Include Symbols", variable=self.include_symbols, bg="#ffeb3b")
        self.symbols_check.grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky="w")

        # Output section
        self.output_frame = tk.Frame(self.root, bg="#2196f3", pady=10)
        self.output_frame.pack(fill="x", padx=10, pady=5)

        self.password_label = tk.Label(self.output_frame, text="Generated Password:", bg="#2196f3", fg="white")
        self.password_label.grid(row=0, column=0, padx=5, pady=5)
        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(self.output_frame, textvariable=self.password_var, width=30, state="readonly")
        self.password_entry.grid(row=0, column=1, padx=5, pady=5)

        # Buttons section
        self.buttons_frame = tk.Frame(self.root, bg="#f44336", pady=10)
        self.buttons_frame.pack(fill="x", padx=10, pady=5)

        self.generate_button = tk.Button(self.buttons_frame, text="Generate", command=self.generate_password, bg="#4caf50", fg="white")
        self.generate_button.pack(side="left", padx=5, pady=5)

        self.copy_button = tk.Button(self.buttons_frame, text="Copy", command=self.copy_password, bg="#4caf50", fg="white")
        self.copy_button.pack(side="left", padx=5, pady=5)

    def generate_password(self):
        length = self.length_var.get()
        if length < 4:
            messagebox.showwarning("Invalid Length", "Password length should be at least 4.")
            return

        characters = string.ascii_lowercase
        if self.include_uppercase.get():
            characters += string.ascii_uppercase
        if self.include_numbers.get():
            characters += string.digits
        if self.include_symbols.get():
            characters += string.punctuation

        password = ''.join(random.choice(characters) for _ in range(length))
        self.password_var.set(password)

    def copy_password(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.password_var.get())
        messagebox.showinfo("Copied", "Password copied to clipboard.")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()

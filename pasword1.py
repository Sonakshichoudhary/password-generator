import random
import string
import tkinter as tk
from tkinter import messagebox

def generate_password():
    try:
        length = int(entry_length.get())
        if length < 6:
            messagebox.showerror("Invalid Input", "Password length should be at least 6.")
            return
    except ValueError:
        messagebox.showerror("Invalid Input", "Please enter a valid number for length.")
        return

    include_symbols = var_symbols.get()

    characters = string.ascii_letters + string.digits
    if include_symbols:
        characters += string.punctuation

    password = ''.join(random.choice(characters) for _ in range(length))
    entry_password.config(state='normal')
    entry_password.delete(0, tk.END)
    entry_password.insert(0, password)
    entry_password.config(state='readonly')

def copy_to_clipboard():
    password = entry_password.get()
    if password:
        root.clipboard_clear()
        root.clipboard_append(password)
        messagebox.showinfo("Copied", "Password copied to clipboard!")

# Setup main window
root = tk.Tk()
root.title("Password Generator")
root.geometry("400x180")
root.minsize(400, 180)
root.resizable(True, True)
root.configure(padx=20, pady=20)

# Configure grid weights for responsiveness
root.columnconfigure(0, weight=1)
root.columnconfigure(1, weight=3)
for i in range(5):
    root.rowconfigure(i, weight=1)

# Labels and input for length
tk.Label(root, text="Password Length:", font=("Helvetica", 12)).grid(row=0, column=0, sticky="w", padx=(0,10))
entry_length = tk.Entry(root, font=("Helvetica", 12))
entry_length.grid(row=0, column=1, pady=5, sticky="ew")

# Checkbox for symbols
var_symbols = tk.BooleanVar()
chk_symbols = tk.Checkbutton(root, text="Include Symbols", variable=var_symbols, font=("Helvetica", 11))
chk_symbols.grid(row=1, column=0, columnspan=2, sticky="w")

# Generate button
btn_generate = tk.Button(root, text="Generate Password", command=generate_password,
                         font=("Helvetica", 12), bg="#4CAF50", fg="white")
btn_generate.grid(row=2, column=0, columnspan=2, pady=10, sticky="ew")

# Password label and entry (readonly)
tk.Label(root, text="Generated Password:", font=("Helvetica", 12)).grid(row=3, column=0, sticky="w", padx=(0,10))
entry_password = tk.Entry(root, font=("Helvetica", 12), state='readonly')
entry_password.grid(row=3, column=1, pady=5, sticky="ew")

# Copy button
btn_copy = tk.Button(root, text="Copy to Clipboard", command=copy_to_clipboard, font=("Helvetica", 11))
btn_copy.grid(row=4, column=0, columnspan=2, pady=5, sticky="ew")

root.mainloop()

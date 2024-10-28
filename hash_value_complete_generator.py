import tkinter as tk
from tkinter import messagebox
import hashlib
import pyperclip
from Crypto.Hash import RIPEMD160
import blake3

def generate_hashes(input_text):
    # Compute SHA2-256
    sha256 = hashlib.sha256(input_text.encode()).hexdigest()
    # Compute SHA2-512
    sha512 = hashlib.sha512(input_text.encode()).hexdigest()
    # Compute SHA3-256
    sha3_256 = hashlib.sha3_256(input_text.encode()).hexdigest()
    # Compute SHA3-512
    sha3_512 = hashlib.sha3_512(input_text.encode()).hexdigest()
    # Compute Blake2
    blake2b = hashlib.blake2b(input_text.encode()).hexdigest()
    # Compute Blake3
    blake3_hash = blake3.blake3(input_text.encode()).hexdigest()
    # Compute RIPEMD-160
    ripemd160 = RIPEMD160.new(input_text.encode()).hexdigest()

    return sha256, sha512, sha3_256, sha3_512, blake2b, blake3_hash, ripemd160

def generate_and_display_hashes(event=None):
    input_text = entry.get()
    if input_text:
        try:
            hashes = generate_hashes(input_text)
            labels = [sha256_label, sha512_label, sha3_256_label, sha3_512_label, blake2_label, blake3_label, ripemd160_label]
            for label, hash_value in zip(labels, hashes):
                label.config(text=hash_value)
        except Exception as e:
            messagebox.showerror("Hash Error", f"An error occurred while hashing: {str(e)}")
    else:
        messagebox.showwarning("Input Error", "Please enter some text to hash.")

def copy_to_clipboard(hash_value):
    pyperclip.copy(hash_value)
    messagebox.showinfo("Copied", "Hash value copied to clipboard.")

# Create the main window
root = tk.Tk()
root.title("Hash Generator")
root.geometry("1200x600")  # Triple the size of the window

# Create and place the input box
entry = tk.Entry(root, width=100)
entry.pack(pady=20)
entry.bind("<Return>", generate_and_display_hashes)  # Bind the Enter key to the generate_and_display_hashes function

# Create and place the "Generate" button
generate_button = tk.Button(root, text="Generate", command=generate_and_display_hashes)
generate_button.pack(pady=10)

# Create labels and copy buttons for each hash
hash_types = ["SHA2-256", "SHA2-512", "SHA3-256", "SHA3-512", "Blake2", "Blake3", "RIPEMD-160"]
labels = []
for hash_type in hash_types:
    frame = tk.Frame(root, bd=2, relief="groove", padx=10, pady=10)  # Add a box around each hash value
    frame.pack(pady=5, fill="x")
    tk.Label(frame, text=f"{hash_type}: ").grid(row=0, column=0, sticky="w")
    label = tk.Label(frame, text="", wraplength=800, justify="left")
    label.grid(row=0, column=1, sticky="w")
    copy_button = tk.Button(frame, text="Copy", command=lambda l=label: copy_to_clipboard(l.cget("text")))
    copy_button.grid(row=0, column=2, padx=10)
    labels.append(label)

# Unpack the labels for easy access
sha256_label, sha512_label, sha3_256_label, sha3_512_label, blake2_label, blake3_label, ripemd160_label = labels

# Run the Tkinter event loop
root.mainloop()

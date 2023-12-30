import tkinter as tk
from tkinter import filedialog
from PIL import Image, ImageTk
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import tkinter.messagebox as mbox
import pyperclip
# AES block size in bytes
AES_BLOCK_SIZE = 16

class ImageEncryptor:
    def __init__(self, window):
        self.window = window
        self.window.title("Image Encryption/Decryption")
        self.window.geometry("1200x800")

        # Create AES cipher and nonce
        self.cipher = None
        self.nonce = None
        self.image_path = None

        # Custom label and button styles
        label_style = {'font': ('Arial', 16), 'fg': 'black'}
        button_style = {'font': ('Arial', 14), 'fg': 'white', 'bg': 'teal', 'width': '20', 'height': '1'}

        # Labels
        start_label = tk.Label(self.window, text="Image Encryption/Decryption", **label_style)
        original_label = tk.Label(self.window, text="Selected Image", **label_style)
        edited_label = tk.Label(self.window, text="Processed Image", **label_style)

        # Image Panels
        self.panelA = tk.Label(self.window)
        self.panelB = tk.Label(self.window)

        # Key Entry
        self.key_entry = tk.Entry(self.window, show="*")

        # Buttons
        choose_button = tk.Button(self.window, text="Choose an Image", command=self.open_file, **button_style)
        input_key_button = tk.Button(self.window, text="Input Key", command=self.input_key, **button_style)
        encrypt_button = tk.Button(self.window, text="Encrypt", command=self.encrypt_image, **button_style)
        decrypt_button = tk.Button(self.window, text="Decrypt", command=self.decrypt_image, **button_style)
        reset_button = tk.Button(self.window, text="Reset", command=self.reset, **button_style)
        generate_key_button = tk.Button(self.window, text="Generate Key", command=self.generate_key, **button_style)
        exit_button = tk.Button(self.window, text="Exit", command=self.exit_win, **button_style)

        # Copy Key Button
        copy_key_button = tk.Button(self.window, text="Copy Key", command=self.copy_key, **button_style)

        # Positioning widgets using grid
        start_label.grid(row=0, column=1, pady=10)
        original_label.grid(row=1, column=0, padx=10, pady=10)
        edited_label.grid(row=1, column=2, padx=10, pady=10)

        self.panelA.grid(row=2, column=0, padx=10, pady=10)
        self.panelB.grid(row=2, column=2, padx=10, pady=10)

        self.key_entry.grid(row=4, column=1, padx=10, pady=10)

        choose_button.grid(row=4, column=0, padx=10, pady=10)
        input_key_button.grid(row=5, column=1, padx=10, pady=10)
        encrypt_button.grid(row=5, column=2, padx=10, pady=10)

        decrypt_button.grid(row=6, column=2, padx=10, pady=10)
        reset_button.grid(row=5, column=0, padx=10, pady=10)
        generate_key_button.grid(row=6, column=1, padx=10, pady=10)

        exit_button.grid(row=6, column=0, padx=10, pady=10)

        # Copy Key Button
        copy_key_button.grid(row=4, column=2, padx=10, pady=10)

    def open_file(self):
        file_path = filedialog.askopenfilename(title="Open")
        if not file_path:
            mbox.showwarning("Warning", "No file selected")
            return

        self.image_path = file_path
        self.show_image(self.image_path, self.panelA)

    def show_image(self, path, panel):
        try:
            img = Image.open(path)
            img = img.resize((250, 250))
            img = ImageTk.PhotoImage(img)
            if panel is not None:
                panel.configure(image=img)
                panel.image = img
        except Exception as e:
            mbox.showerror("Error", f"Failed to open the image: {str(e)}")

    def encrypt_image(self):
        if not self.cipher or not self.nonce:
            mbox.showwarning("Warning", "No encryption key set")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
        if not file_path:
            return

        try:
            image_input = Image.open(self.image_path)
            encrypted_image = self.encrypt(image_input)
            encrypted_image.save(file_path)

            # Display the input image in panelA
            self.show_image(self.image_path, self.panelA)
            # Display the encrypted image in panelB
            self.show_image(file_path, self.panelB)

            mbox.showinfo("Success", "Image encrypted and saved")
        except Exception as e:
            mbox.showerror("Error", f"Failed to encrypt the image: {str(e)}")

    def decrypt_image(self):
        if not self.cipher or not self.nonce:
            mbox.showwarning("Warning", "No decryption key set")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
        if not file_path:
            return

        try:
            image_input = Image.open(self.image_path)
            decrypted_image = self.decrypt(image_input)
            decrypted_image.save(file_path)

            # Display the input image in panelA
            self.show_image(self.image_path, self.panelA)
            # Display the decrypted image in panelB
            self.show_image(file_path, self.panelB)

            mbox.showinfo("Success", "Image decrypted and saved")
        except Exception as e:
            mbox.showerror("Error", f"Failed to decrypt the image: {str(e)}")

    def reset(self):
        self.image_path = None
        self.key_entry.delete(0, tk.END)
        self.cipher = None
        self.nonce = None
        self.panelA.image = None
        self.panelB.image = None

    def input_key(self):
        custom_key = self.key_entry.get()
        try:
            key = bytes.fromhex(custom_key)
            if len(key) != 32:
                mbox.showwarning("Warning", "AES key must be 32 bytes (256 bits) long")
            else:
                self.cipher = AES.new(key, AES.MODE_EAX, nonce=self.nonce)
        except ValueError:
            mbox.showwarning("Warning", "Invalid AES key format")

    def generate_key(self):
        self.cipher = None
        self.nonce = get_random_bytes(16)  # Generate a random nonce
        key = get_random_bytes(32)
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key.hex())
        self.cipher = AES.new(key, AES.MODE_EAX, nonce=self.nonce)

    def exit_win(self):
        if mbox.askokcancel("Quit", "Do you want to quit?"):
            self.window.destroy()

    def copy_key(self):
        if not self.cipher or not self.nonce:
            mbox.showwarning("Warning", "No encryption key set")
            return

        key_to_copy = self.key_entry.get()
        mbox.showinfo("Success", "Encryption key copied to clipboard")
        pyperclip.copy(key_to_copy)

    def encrypt(self, image):
        image_bytes = image.tobytes()
        ciphertext, tag = self.cipher.encrypt_and_digest(image_bytes)
        return Image.frombytes(image.mode, image.size, ciphertext)

    def decrypt(self, image):
        image_bytes = image.tobytes()
        plaintext = self.cipher.decrypt(image_bytes)
        return Image.frombytes(image.mode, image.size, plaintext)


if __name__ == "__main__":
    window = tk.Tk()
    app = ImageEncryptor(window)
    window.mainloop()

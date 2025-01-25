import os
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
import numpy as np
from PIL import Image
import requests

# Function to send alerts via Telegram
def send_telegram_alert(message):
    bot_token = 'AAHg_DxlHPT7-aRoiEio-UG4glES5Xn6XVk'
    chat_id = '909465498'
    url = f"https://api.telegram.org/bot7775701894:AAHg_DxlHPT7-aRoiEio-UG4glES5Xn6XVk/sendMessage"
    payload = {
        'chat_id': chat_id,
        'text': message
    }
    response = requests.post(url, data=payload)
    if response.status_code != 200:
        print(f"Failed to send Telegram alert: {response.text}")

 # Function to shift rows for AES
def shift_rows(matrix):
    result = np.copy(matrix)
    for i in range(1, matrix.shape[0]):
        result[i] = np.roll(matrix[i], -i)
    return result

# Function to inverse shift rows for AES
def inv_shift_rows(matrix):
    result = np.copy(matrix)
    for i in range(1, matrix.shape[0]):
        result[i] = np.roll(matrix[i], i)
    return result 

# Function to mix columns for AES
def mix_columns(matrix):
    mix_matrix = np.array([[2, 3, 1, 1],
                           [1, 2, 3, 1],
                           [1, 1, 2, 3],
                           [3, 1, 1, 2]], dtype=np.uint8)
    result = np.zeros_like(matrix, dtype=np.uint8)
    for i in range(matrix.shape[1]):
        column = matrix[:, i].astype(int)  # Convert to int for intermediate calculations
        transformed_column = np.dot(mix_matrix, column) % 256
        result[:, i] = transformed_column.astype(np.uint8)  # Convert back to uint8
    return result


# Function to inverse mix columns for AES
def inv_mix_columns(matrix):
    inv_mix_matrix = np.array([[14, 11, 13, 9],
                                [9, 14, 11, 13],
                                [13, 9, 14, 11],
                                [11, 13, 9, 14]], dtype=np.uint8)
    result = np.zeros_like(matrix, dtype=np.uint8)
    for i in range(matrix.shape[1]):
        column = matrix[:, i].astype(int)  # Convert to int for intermediate calculations
        transformed_column = np.dot(inv_mix_matrix, column) % 256
        result[:, i] = transformed_column.astype(np.uint8)  # Convert back to uint8
    return result


# Function for encrypting the image
def encrypted_image(image_path, key, save_path):
    try:
        with open(image_path, 'rb') as file:
            image_bytes = file.read()
        cipher = AES.new(key, AES.MODE_CFB)
        encrypted_bytes = cipher.iv + cipher.encrypt(image_bytes)

        encrypted_path = os.path.join(save_path, 'encrypted_image.bin')
        with open(encrypted_path, 'wb') as enc_file:
            enc_file.write(encrypted_bytes)

        # Scramble the image for visualization
        scrambled_image_path = scramble_image(image_path, save_path)

        send_telegram_alert(f"Image encrypted successfully! Encrypted file: {encrypted_path}\nScrambled preview: {scrambled_image_path}")
        return encrypted_path, scrambled_image_path
    except Exception as e:
        send_telegram_alert(f"Error during encryption: {str(e)}")
        raise


# Function for decrypting the image
def decrypted_image(enc_path, key, save_path):
    try:
        with open(enc_path, 'rb') as enc_file:
            iv = enc_file.read(16)  # Read the IV (first 16 bytes)
            encrypted_bytes = enc_file.read()  # The rest is the encrypted data

        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        decrypted_bytes = cipher.decrypt(encrypted_bytes)

        decrypted_path = os.path.join(save_path, 'decrypted_image.jpg')
        with open(decrypted_path, 'wb') as dec_file:
            dec_file.write(decrypted_bytes)

        # Verify if it's a valid image
        try:
            Image.open(decrypted_path).verify()
        except Exception:
            os.remove(decrypted_path)
            send_telegram_alert("Decryption failed. Invalid key or corrupted file.")
            raise ValueError("Decryption failed. Invalid key or corrupted file.")

        send_telegram_alert(f"Image decrypted successfully! Decrypted file: {decrypted_path}")
        return decrypted_path
    except Exception as e:
        send_telegram_alert(f"Error during decryption: {str(e)}")
        raise


# Function to scramble the image for visualization
# Function to scramble the image for visualization
def scramble_image(image_path, save_path):
    # Open the image
    image = Image.open(image_path)

    # If the image has an alpha channel (RGBA), convert it to RGB
    if image.mode == 'RGBA':
        image = image.convert('RGB')

    # Convert the image to a numpy array
    pixels = np.array(image)

    # Generate random noise with the same shape as the image
    noise = np.random.randint(0, 256, pixels.shape, dtype=np.uint8)

    # Add noise to the image
    static_pixels = np.clip(pixels + noise, 0, 255)

    # Create a new image from the noisy pixels
    static_image = Image.fromarray(static_pixels.astype(np.uint8))

    # Save the scrambled image as JPEG
    scrambled_image_path = os.path.join(save_path, 'scrambled_image.jpg')
    static_image.save(scrambled_image_path)

    return scrambled_image_path

 

# Function to select an image for encryption
def select_image():
    file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.jpg;*.png;*.bmp")])
    image_entry.delete(0, tk.END)
    image_entry.insert(0, file_path)


# Function to select an encrypted .bin file for decryption
def select_encrypted_file():
    file_path = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.bin")])
    image_entry.delete(0, tk.END)
    image_entry.insert(0, file_path)


# Function to select a save directory
def select_save_directory():
    directory = filedialog.askdirectory()
    save_directory_entry.delete(0, tk.END)
    save_directory_entry.insert(0, directory)


# Function to validate the encryption key
def validate_key(key):
    if len(key) != 16:
        messagebox.showerror("Key Error", "The key must be exactly 16 characters long.")
        return False
    return True


# Function to handle encryption
def encrypt_image():
    image_path = image_entry.get()
    key = key_entry.get().encode('utf-8')
    save_path = save_directory_entry.get()

    if not image_path or not key or not save_path:
        messagebox.showerror("Input Error", "Please provide an image, key, and save directory.")
        return

    if not validate_key(key):
        return

    try:
        encrypted_path, scrambled_image_path = encrypted_image(image_path, key, save_path)
        messagebox.showinfo("Success", f"Image encrypted successfully!\nEncrypted file: {encrypted_path}\nScrambled preview: {scrambled_image_path}")
    except Exception as e:
        messagebox.showerror("Encryption Error", str(e))


# Function to handle decryption
def decrypt_image():
    enc_path = image_entry.get()
    key = key_entry.get().encode('utf-8')
    save_path = save_directory_entry.get()

    if not enc_path or not key or not save_path:
        messagebox.showerror("Input Error", "Please provide an encrypted file, key, and save directory.")
        return

    if not validate_key(key):
        return

    try:
        decrypted_path = decrypted_image(enc_path, key, save_path)
        messagebox.showinfo("Success", f"Image decrypted successfully!\nDecrypted file: {decrypted_path}")
    except Exception as e:
        messagebox.showerror("Decryption Error", str(e))


# Function to close the application
def exit_application():
    root.quit()


# GUI Implementation
root = tk.Tk()
root.title("Medical Image Encryption/Decryption")
root.geometry("550x600")
root.resizable(False, False)

title_label = tk.Label(root, text="Medical Image Encryption/Decryption", font=("Arial", 16, "bold"))
title_label.pack(pady=10)

author_label = tk.Label(root, text="By students: Mohamed Nasser & Hussein Ahmed", font=("Arial", 10))
author_label.pack(pady=5)

image_label = tk.Label(root, text="Select an Image or Encrypted File:")
image_label.pack(pady=(10, 0))

image_entry = tk.Entry(root, width=40)
image_entry.pack(pady=5)

browse_button = tk.Button(root, text="Browse for File", command=select_image)
browse_button.pack(pady=5)

browse_bin_button = tk.Button(root, text="Browse for Encrypted File", command=select_encrypted_file)
browse_bin_button.pack(pady=5)

save_directory_label = tk.Label(root, text="Select Save Directory:")
save_directory_label.pack(pady=(10, 0))

save_directory_entry = tk.Entry(root, width=40)
save_directory_entry.pack(pady=5)

save_directory_button = tk.Button(root, text="Browse Save Directory", command=select_save_directory)
save_directory_button.pack(pady=5)

key_label = tk.Label(root, text="Enter Key (16 characters):")
key_label.pack(pady=(10, 0))

key_entry = tk.Entry(root, width=40)
key_entry.pack(pady=5)

encrypt_button = tk.Button(root, text="Encrypt", command=encrypt_image)
encrypt_button.pack(pady=10)

decrypt_button = tk.Button(root, text="Decrypt", command=decrypt_image)
decrypt_button.pack(pady=5)

exit_button = tk.Button(root, text="Exit", command=exit_application)
exit_button.pack(pady=15)

root.mainloop()

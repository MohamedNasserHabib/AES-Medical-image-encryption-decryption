import os
import tkinter as tk
from tkinter import filedialog, messagebox
import numpy as np
from PIL import Image
import requests
import time
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

# AES Implementation Constants
S_BOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

INV_S_BOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

# AES Core Functions
def sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = S_BOX[state[i][j]]
    return state

def inv_sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = INV_S_BOX[state[i][j]]
    return state

def shift_rows(state):
    state[1][0], state[1][1], state[1][2], state[1][3] = state[1][1], state[1][2], state[1][3], state[1][0]
    state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
    state[3][0], state[3][1], state[3][2], state[3][3] = state[3][3], state[3][0], state[3][1], state[3][2]
    return state

def inv_shift_rows(state):
    state[1][0], state[1][1], state[1][2], state[1][3] = state[1][3], state[1][0], state[1][1], state[1][2]
    state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
    state[3][0], state[3][1], state[3][2], state[3][3] = state[3][1], state[3][2], state[3][3], state[3][0]
    return state

def galois_mult(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set:
            a ^= 0x1b
        b >>= 1
    return p % 256

def mix_columns(state):
    for i in range(4):
        s0 = galois_mult(0x02, state[0][i]) ^ galois_mult(0x03, state[1][i]) ^ state[2][i] ^ state[3][i]
        s1 = state[0][i] ^ galois_mult(0x02, state[1][i]) ^ galois_mult(0x03, state[2][i]) ^ state[3][i]
        s2 = state[0][i] ^ state[1][i] ^ galois_mult(0x02, state[2][i]) ^ galois_mult(0x03, state[3][i])
        s3 = galois_mult(0x03, state[0][i]) ^ state[1][i] ^ state[2][i] ^ galois_mult(0x02, state[3][i])
        
        state[0][i] = s0
        state[1][i] = s1
        state[2][i] = s2
        state[3][i] = s3
    return state

def inv_mix_columns(state):
    for i in range(4):
        s0 = galois_mult(0x0e, state[0][i]) ^ galois_mult(0x0b, state[1][i]) ^ galois_mult(0x0d, state[2][i]) ^ galois_mult(0x09, state[3][i])
        s1 = galois_mult(0x09, state[0][i]) ^ galois_mult(0x0e, state[1][i]) ^ galois_mult(0x0b, state[2][i]) ^ galois_mult(0x0d, state[3][i])
        s2 = galois_mult(0x0d, state[0][i]) ^ galois_mult(0x09, state[1][i]) ^ galois_mult(0x0e, state[2][i]) ^ galois_mult(0x0b, state[3][i])
        s3 = galois_mult(0x0b, state[0][i]) ^ galois_mult(0x0d, state[1][i]) ^ galois_mult(0x09, state[2][i]) ^ galois_mult(0x0e, state[3][i])
        
        state[0][i] = s0
        state[1][i] = s1
        state[2][i] = s2
        state[3][i] = s3
    return state

def add_round_key(state, round_key):
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]
    return state

def rot_word(word):
    return word[1:] + word[:1]

def sub_word(word):
    return [S_BOX[b] for b in word]

def key_expansion(key):
    key_schedule = [[0 for _ in range(4)] for _ in range(44)]
    
    for i in range(4):
        for j in range(4):
            key_schedule[i][j] = key[i*4 + j]
    
    for i in range(4, 44):
        temp = key_schedule[i-1].copy()
        
        if i % 4 == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= RCON[i//4 - 1]
        
        for j in range(4):
            key_schedule[i][j] = key_schedule[i-4][j] ^ temp[j]
    
    return key_schedule

def bytes_to_state(byte_array):
    state = [[0 for _ in range(4)] for _ in range(4)]
    for i in range(4):
        for j in range(4):
            state[j][i] = byte_array[i*4 + j]
    return state

def state_to_bytes(state):
    byte_array = bytearray(16)
    for i in range(4):
        for j in range(4):
            byte_array[i*4 + j] = state[j][i]
    return byte_array

def aes_encrypt_block(plaintext, key_schedule):
    state = bytes_to_state(plaintext)
    
    # Initial round
    state = add_round_key(state, key_schedule[:4])
    
    # Main rounds
    for round in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, key_schedule[round*4:(round+1)*4])
    
    # Final round
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, key_schedule[40:44])
    
    return state_to_bytes(state)

def aes_decrypt_block(ciphertext, key_schedule):
    state = bytes_to_state(ciphertext)
    
    # Initial round
    state = add_round_key(state, key_schedule[40:44])
    
    # Main rounds
    for round in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, key_schedule[round*4:(round+1)*4])
        state = inv_mix_columns(state)
    
    # Final round
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, key_schedule[:4])
    
    return state_to_bytes(state)

def pad_data(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def unpad_data(data):
    pad_len = data[-1]
    return data[:-pad_len]

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def aes_cfb_encrypt(data, key, iv):
    key_schedule = key_expansion(key)
    encrypted = bytearray()
    prev_block = iv
    
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        if len(block) < 16:
            block = block.ljust(16, b'\x00')
        
        encrypted_block = aes_encrypt_block(prev_block, key_schedule)
        encrypted_block = xor_bytes(block, encrypted_block)
        encrypted.extend(encrypted_block)
        prev_block = encrypted_block
    
    return bytes(encrypted)

def aes_cfb_decrypt(data, key, iv):
    key_schedule = key_expansion(key)
    decrypted = bytearray()
    prev_block = iv
    
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        if len(block) < 16:
            block = block.ljust(16, b'\x00')
        
        decrypted_block = aes_encrypt_block(prev_block, key_schedule)
        decrypted_block = xor_bytes(block, decrypted_block)
        decrypted.extend(decrypted_block)
        prev_block = block
    
    return bytes(decrypted)

# RSA Key Generation and Encryption
def generate_rsa_keys():
    """Generate RSA key pair (2048 bits) and return as PEM strings"""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_with_rsa(public_key_pem, data):
    """Encrypt data with RSA public key"""
    public_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_data = cipher.encrypt(data)
    return encrypted_data

def decrypt_with_rsa(private_key_pem, encrypted_data):
    """Decrypt data with RSA private key"""
    private_key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_data = cipher.decrypt(encrypted_data)
    return decrypted_data

TELEGRAM_BOT_TOKEN = "YOUR_BOT_TOKEN"
TELEGRAM_ADMIN_CHAT_IDS = ["YOUR_CHAT_ID"]

def send_telegram_alert(message):
    """Send alert message to all admin chat IDs"""
    url = f"YOUR-URL"
    
    for chat_id in TELEGRAM_ADMIN_CHAT_IDS:
        payload = {
            'chat_id': chat_id,
            'text': message
        }
        try:
            response = requests.post(url, data=payload)
            if response.status_code != 200:
                print(f"Failed to send Telegram alert to {chat_id}: {response.text}")
        except Exception as e:
            print(f"Error sending Telegram alert to {chat_id}: {str(e)}")

def generate_scrambled_preview(encrypted_data, original_size, save_path, original_ext):
    """Generate properly scrambled preview from encrypted data"""
    try:
        # Use cryptographic hash of the encrypted data for true randomness
        hash_bytes = hashlib.sha256(encrypted_data).digest()
        
        # Generate pure noise image using the hash as seed
        rng = np.random.RandomState(int.from_bytes(hash_bytes[:4], 'little'))
        
        # Create proper noise pattern matching original dimensions
        if original_ext.lower() in ['.jpg', '.jpeg', '.png']:
            # Color image
            noise = rng.randint(0, 256, (original_size[1], original_size[0], 3), dtype=np.uint8)
        else:
            # Grayscale
            noise = rng.randint(0, 256, (original_size[1], original_size[0]), dtype=np.uint8)
        
        # Create and save preview
        preview_image = Image.fromarray(noise)
        scrambled_path = os.path.join(save_path, f'encrypted_preview{original_ext}')
        preview_image.save(scrambled_path)
        return scrambled_path
    except Exception as e:
        print(f"Preview generation error: {e}")
        # Fallback: solid color image indicating encryption
        fallback = Image.new('RGB' if original_ext.lower() in ['.jpg','.jpeg','.png'] else 'L', 
                           original_size, 
                           color=(178, 34, 34))  # Dark red
        scrambled_path = os.path.join(save_path, f'encrypted_preview{original_ext}')
        fallback.save(scrambled_path)
        return scrambled_path

def encrypted_image(image_path, key, save_path):
    try:
        start_time = time.time()
        
        # Get original image info
        original_ext = os.path.splitext(image_path)[1].encode('utf-8')
        ext_length = len(original_ext).to_bytes(1, 'big')
        
        with Image.open(image_path) as img:
            original_size = img.size
            with open(image_path, 'rb') as file:
                image_bytes = file.read()
        
        # Encrypt the image
        iv = os.urandom(16)
        encrypted_bytes = aes_cfb_encrypt(image_bytes, key, iv)
        
        # Generate RSA key pair
        private_key, public_key = generate_rsa_keys()
        
        # Encrypt the AES key with RSA
        encrypted_aes_key = encrypt_with_rsa(public_key, key)
        
        # Save all components: IV + ext length + extension + encrypted AES key + encrypted image
        encrypted_bytes = iv + ext_length + original_ext + len(encrypted_aes_key).to_bytes(2, 'big') + encrypted_aes_key + encrypted_bytes

        # Save encrypted file
        encrypted_path = os.path.join(save_path, 'encrypted_image.bin')
        with open(encrypted_path, 'wb') as enc_file:
            enc_file.write(encrypted_bytes)
            
        # Save RSA private key to file
        private_key_path = os.path.join(save_path, 'private_key.pem')
        with open(private_key_path, 'wb') as key_file:
            key_file.write(private_key)

        # Generate preview from actual encrypted data (skip IV and metadata)
        encrypted_image_data = encrypted_bytes[16 + 1 + len(original_ext) + 2 + len(encrypted_aes_key):]
        scrambled_image_path = generate_scrambled_preview(
            encrypted_image_data,
            original_size,
            save_path,
            os.path.splitext(image_path)[1]
        )

        end_time = time.time()
        encryption_time = end_time - start_time

        send_telegram_alert(
            f"Image encrypted successfully!\n"
            f"Time taken: {encryption_time:.4f} seconds\n"
            f"Encrypted file: {encrypted_path}\n"
            f"Private key saved to: {private_key_path}\n"
            f"Encrypted preview: {scrambled_image_path}"
        )
        return encrypted_path, scrambled_image_path, encryption_time, private_key_path
    except Exception as e:
        send_telegram_alert(f"Error during encryption: {str(e)}")
        raise

def decrypted_image(enc_path, private_key_path, save_path):
    try:
        start_time = time.time()
        
        with open(enc_path, 'rb') as enc_file:
            iv = enc_file.read(16)
            ext_length = int.from_bytes(enc_file.read(1), 'big')
            original_ext = enc_file.read(ext_length).decode('utf-8')
            encrypted_key_length = int.from_bytes(enc_file.read(2), 'big')
            encrypted_aes_key = enc_file.read(encrypted_key_length)
            encrypted_bytes = enc_file.read()
        
        # Decrypt the AES key with RSA
        with open(private_key_path, 'rb') as key_file:
            private_key = key_file.read()
        
        aes_key = decrypt_with_rsa(private_key, encrypted_aes_key)
        
        # Decrypt the image
        decrypted_bytes = aes_cfb_decrypt(encrypted_bytes, aes_key, iv)

        decrypted_path = os.path.join(save_path, f'decrypted_image{original_ext}')
        with open(decrypted_path, 'wb') as dec_file:
            dec_file.write(decrypted_bytes)

        try:
            Image.open(decrypted_path).verify()
        except Exception:
            os.remove(decrypted_path)
            send_telegram_alert("Decryption failed. Invalid key or corrupted file.")
            raise ValueError("Decryption failed. Invalid key or corrupted file.")

        end_time = time.time()
        decryption_time = end_time - start_time

        send_telegram_alert(
            f"Image decrypted successfully!\n"
            f"Time taken: {decryption_time:.4f} seconds\n"
            f"Decrypted file: {decrypted_path}"
        )
        return decrypted_path, decryption_time
    except Exception as e:
        send_telegram_alert(f"Error during decryption: {str(e)}")
        raise

def select_image():
    file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.jpg;*.png;*.bmp")])
    image_entry.delete(0, tk.END)
    image_entry.insert(0, file_path)

def select_encrypted_file():
    file_path = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.bin")])
    image_entry.delete(0, tk.END)
    image_entry.insert(0, file_path)

def select_private_key():
    file_path = filedialog.askopenfilename(filetypes=[("Private Key Files", "*.pem")])
    private_key_entry.delete(0, tk.END)
    private_key_entry.insert(0, file_path)

def select_save_directory():
    directory = filedialog.askdirectory()
    save_directory_entry.delete(0, tk.END)
    save_directory_entry.insert(0, directory)

def validate_key(key):
    if len(key) != 16:
        messagebox.showerror("Key Error", "The key must be exactly 16 characters long.")
        return False
    return True

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
        encrypted_path, scrambled_image_path, encryption_time, private_key_path = encrypted_image(image_path, key, save_path)
        messagebox.showinfo(
            "Success", 
            f"Image encrypted successfully!\n"
            f"Time taken: {encryption_time:.4f} seconds\n"
            f"Encrypted file: {encrypted_path}\n"
            f"Private key saved to: {private_key_path}\n"
            f"Encrypted preview: {scrambled_image_path}"
        )
    except Exception as e:
        messagebox.showerror("Encryption Error", str(e))

def decrypt_image():
    enc_path = image_entry.get()
    private_key_path = private_key_entry.get()
    save_path = save_directory_entry.get()

    if not enc_path or not private_key_path or not save_path:
        messagebox.showerror("Input Error", "Please provide an encrypted file, private key, and save directory.")
        return

    try:
        decrypted_path, decryption_time = decrypted_image(enc_path, private_key_path, save_path)
        messagebox.showinfo(
            "Success", 
            f"Image decrypted successfully!\n"
            f"Time taken: {decryption_time:.4f} seconds\n"
            f"Decrypted file: {decrypted_path}"
        )
    except Exception as e:
        messagebox.showerror("Decryption Error", str(e))

def exit_application():
    root.quit()

# GUI Implementation
root = tk.Tk()
root.title("Medical Image Encryption/Decryption")
root.geometry("600x750")
root.resizable(False, False)

# Custom colors and fonts
BG_COLOR = "#f0f8ff" 
BUTTON_COLOR = "#4682b4" 
TEXT_COLOR = "#2f4f4f" 
ENTRY_BG = "#ffffff"  
FRAME_BG = "#e6e6fa"  

# Configure root window
root.configure(bg=BG_COLOR)

# Header Frame
header_frame = tk.Frame(root, bg=BG_COLOR)
header_frame.pack(pady=10)

title_label = tk.Label(
    header_frame,
    text="Medical Image Encryption/Decryption",
    font=("Arial", 16, "bold"),
    bg=BG_COLOR,
    fg=TEXT_COLOR
)
title_label.pack(pady=5)

author_label = tk.Label(
    header_frame,
    text="By students: Mohamed Nasser & Hussein Ahmed",
    font=("Arial", 10),
    bg=BG_COLOR,
    fg=TEXT_COLOR
)
author_label.pack()

# Main container frame
main_frame = tk.Frame(root, bg=FRAME_BG, padx=15, pady=15)
main_frame.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)

# File selection section
file_frame = tk.LabelFrame(
    main_frame,
    text=" File Selection ",
    bg=FRAME_BG,
    fg=TEXT_COLOR,
    font=("Arial", 10, "bold"),
    padx=10,
    pady=10
)
file_frame.pack(fill=tk.X, pady=5)

image_label = tk.Label(
    file_frame,
    text="Image/Encrypted File:",
    bg=FRAME_BG,
    fg=TEXT_COLOR
)
image_label.pack(anchor="w")

image_entry = tk.Entry(
    file_frame,
    width=50,
    bg=ENTRY_BG
)
image_entry.pack(fill=tk.X, pady=5)

button_frame = tk.Frame(file_frame, bg=FRAME_BG)
button_frame.pack(fill=tk.X)

browse_button = tk.Button(
    button_frame,
    text="Browse Image",
    command=select_image,
    bg=BUTTON_COLOR,
    fg="white"
)
browse_button.pack(side=tk.LEFT, padx=2, expand=True, fill=tk.X)

browse_bin_button = tk.Button(
    button_frame,
    text="Browse Encrypted File",
    command=select_encrypted_file,
    bg=BUTTON_COLOR,
    fg="white"
)
browse_bin_button.pack(side=tk.LEFT, padx=2, expand=True, fill=tk.X)

# Save directory section
save_frame = tk.LabelFrame(
    main_frame,
    text=" Output Location ",
    bg=FRAME_BG,
    fg=TEXT_COLOR,
    font=("Arial", 10, "bold"),
    padx=10,
    pady=10
)
save_frame.pack(fill=tk.X, pady=5)

save_directory_label = tk.Label(
    save_frame,
    text="Save Directory:",
    bg=FRAME_BG,
    fg=TEXT_COLOR
)
save_directory_label.pack(anchor="w")

save_directory_entry = tk.Entry(
    save_frame,
    width=50,
    bg=ENTRY_BG
)
save_directory_entry.pack(fill=tk.X, pady=5)

save_directory_button = tk.Button(
    save_frame,
    text="Browse Directory",
    command=select_save_directory,
    bg=BUTTON_COLOR,
    fg="white"
)
save_directory_button.pack(fill=tk.X)

# Key section
key_frame = tk.LabelFrame(
    main_frame,
    text=" Encryption/Decryption Keys ",
    bg=FRAME_BG,
    fg=TEXT_COLOR,
    font=("Arial", 10, "bold"),
    padx=10,
    pady=10
)
key_frame.pack(fill=tk.X, pady=5)

key_label = tk.Label(
    key_frame,
    text="AES Key (16 characters):",
    bg=FRAME_BG,
    fg=TEXT_COLOR
)
key_label.pack(anchor="w")

key_entry = tk.Entry(
    key_frame,
    width=50,
    bg=ENTRY_BG
)
key_entry.pack(fill=tk.X, pady=5)

private_key_label = tk.Label(
    key_frame,
    text="Private Key (for decryption):",
    bg=FRAME_BG,
    fg=TEXT_COLOR
)
private_key_label.pack(anchor="w", pady=(10, 0))

private_key_entry = tk.Entry(
    key_frame,
    width=50,
    bg=ENTRY_BG
)
private_key_entry.pack(fill=tk.X, pady=5)

browse_private_key_button = tk.Button(
    key_frame,
    text="Browse Private Key",
    command=select_private_key,
    bg=BUTTON_COLOR,
    fg="white"
)
browse_private_key_button.pack(fill=tk.X)

# Action buttons frame
action_frame = tk.Frame(main_frame, bg=FRAME_BG)
action_frame.pack(fill=tk.X, pady=10)

encrypt_button = tk.Button(
    action_frame,
    text="Encrypt Image",
    command=encrypt_image,
    bg=BUTTON_COLOR,
    fg="white"
)
encrypt_button.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)

decrypt_button = tk.Button(
    action_frame,
    text="Decrypt Image",
    command=decrypt_image,
    bg=BUTTON_COLOR,
    fg="white"
)
decrypt_button.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)

# Exit button
exit_button = tk.Button(
    root,
    text="Exit Application",
    command=exit_application,
    bg=BUTTON_COLOR,
    fg="white"
)
exit_button.pack(pady=10)

root.mainloop()

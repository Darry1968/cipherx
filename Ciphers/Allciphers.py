import base64,hashlib, itertools
from Crypto.Cipher import ChaCha20,DES,AES
from Crypto.Util.Padding import pad, unpad

class Ciphers():
    def base64_encode(self,text):
        encoded_bytes = base64.b64encode(text.encode('utf-8'))
        encoded_string = encoded_bytes.decode('utf-8')
        return encoded_string
    
    def base64_decode(self,cipher):
        decoded_bytes = base64.b64decode(cipher)
        decoded_string = decoded_bytes.decode('utf-8')
        return decoded_string
    
    def md5_encode(self, text):
        md5_hash = hashlib.md5()
        md5_hash.update(text.encode('utf-8'))
        md5_hex = md5_hash.hexdigest()
        return md5_hex
    
    def md5_decode(self,md5_hash, max_length):
        character_set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        for length in range(1, max_length + 1):
            for candidate in itertools.product(character_set, repeat=length):
                candidate_str = ''.join(candidate)
                candidate_hash = hashlib.md5(candidate_str.encode('utf-8')).hexdigest()

                if candidate_hash == md5_hash:
                    return candidate_str
        return None
    
    def caesar_encode(self,plaintext, shift):
        encrypted_text = ""
        for char in plaintext:
            if char.isalpha():
                is_upper = char.isupper()
                char = char.lower()
                shifted_char = chr(((ord(char) - ord('a') + shift) % 26) + ord('a'))
                if is_upper:
                    shifted_char = shifted_char.upper()
                encrypted_text += shifted_char
            else:
                encrypted_text += char
        return encrypted_text
    
    def caesar_decode(self,ciphertext, shift):
        return self.caesar_encode(ciphertext, -shift)
    
    def Shift_encode(self,text, shift):
        encrypted_text = ""
        for char in text:
            if char.isalpha():
                # Determine whether it's an uppercase or lowercase letter
                is_upper = char.isupper()
                char = char.lower()
                # Apply the shift and wrap around the alphabet
                char_code = ord(char) - ord('a')
                char_code = (char_code + shift) % 26
                char = chr(char_code + ord('a'))
                # Convert back to uppercase if necessary
                if is_upper:
                    char = char.upper()
            encrypted_text += char
        return encrypted_text
    
    def Shift_decode(self,encrypted_text, shift):
        decrypted_text = ""
        for char in encrypted_text:
            if char.isalpha():
                # Determine whether it's an uppercase or lowercase letter
                is_upper = char.isupper()
                char = char.lower()
                # Apply the reverse shift and wrap around the alphabet
                char_code = ord(char) - ord('a')
                char_code = (char_code - shift) % 26
                char = chr(char_code + ord('a'))
                # Convert back to uppercase if necessary
                if is_upper:
                    char = char.upper()
            decrypted_text += char
        return decrypted_text
    
    def Chacha_encode(self,text,key,nonce):
        text = bytes(text,'utf-8')

        # create ChaCha20 cipher for encryption
        cipher = ChaCha20.new(key=key, nonce=nonce)

        ciphertext = cipher.encrypt(text)
        return ciphertext.hex()

    def ChaCha_decode(self,ciphertext,key,nonce):
        cipherbytes = bytes.fromhex(ciphertext)
        # create ChaCha20 cipher for decryption
        cipher = ChaCha20.new(key=key, nonce=nonce)

        decrypted_text = cipher.decrypt(cipherbytes)
        return decrypted_text.decode('utf-8')
    
    def DES_encode(self,plaintext,key):
        if len(key) >= 8:
            key = bytes(key,'utf-8')
            key = key[:8]

            plaintext = bytes(plaintext,'utf-8')

            cipher = DES.new(key, DES.MODE_ECB)

            # encrypt
            plaintext = plaintext + b'\x00' * (8 - len(plaintext) % 8)
            ciphertext = cipher.encrypt(plaintext)

            return ciphertext.hex()
        else:
            return "Incorrect key length"

    def DES_decode(self,ciphertext,key):
        if len(key) >= 8:
            key = bytes(key,'utf-8')
            key = key[:8]

            # hex to bytes
            cipherbytes = bytes.fromhex(ciphertext)
            # cipher creation
            cipher = DES.new(key, DES.MODE_ECB)

            decrypted_text = cipher.decrypt(cipherbytes)

            # Remove the padding from the decrypted text
            original_text = decrypted_text.rstrip(b'\x00')
            print(original_text)

            return original_text.decode('utf-8')
        else:
            return "Incorrect key length"
        
    def generate_aes_key(self,key):
        padd = b'ThisIspd'
        key = bytes(key,'utf-8')
        key = key[:8]
        final_key = key+padd
        return final_key
    
    def AES_encode(self,plaintext,key):
        # plaintext to bytes
        plaintext = bytes(plaintext,'utf-8')

        # cipher creation
        cipher = AES.new(key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        final_CT = cipher.iv + ciphertext
        return final_CT.hex()

    def AES_decode(self,ciphertext,key):
        # hex to bytes
        ciphertext = bytes.fromhex(ciphertext)

        iv = ciphertext[:AES.block_size]
        ciphertext = ciphertext[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext.decode('utf-8')
    
    def text_to_hex(self,text):
        try:
            # Encode the text as bytes and convert to a hexadecimal string
            hex_string = text.encode('utf-8').hex()
            return hex_string
        except Exception as e:
            return str(e)
        
    def hex_to_text(self,hex_string):
        try:
            # Remove any leading "0x" if present
            if hex_string.startswith("0x"):
                hex_string = hex_string[2:]
            
            # Convert the hexadecimal string to bytes and decode as text
            text = bytes.fromhex(hex_string).decode('utf-8')
            return text
        except Exception as e:
            return str(e)

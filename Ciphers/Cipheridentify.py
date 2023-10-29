import re

class CipherIdentify():
    def identify_caesar_cipher(self, cipher_text):
        # Implement Caesar cipher recognition logic here
        # You can look for patterns, such as a consistent shift, to recognize it
        pattern = re.compile(r'^[A-Za-z]{1,}[BCDE]{1,}$')

        if pattern.match(cipher_text):
            match_percentage = len(pattern.match(cipher_text).group()) / len(cipher_text) * 100
            return "Caesar", match_percentage
        else:
            return "Caesar", 0

    def identify_base64_cipher(self, cipher_text):
        # Implement Vigenère cipher recognition logic here
        # You can look for key length patterns or known keywords in the text
        base64_pattern = re.compile(r'^[A-Za-z0-9+/]*={0,2}==$')
        if base64_pattern.match(cipher_text):
            match_percentage = len(base64_pattern.match(cipher_text).group()) / len(cipher_text) * 100
            return "base64_", match_percentage
        else:
            return "base64_", 0

    def identify_md5_cipher(self, cipher_text):
        # Implement MD5 cipher recognition logic here
        # You can look for the specific MD5 hash pattern
        md5_pattern = re.compile(r'^[0-9a-f]{32}$')
        if md5_pattern.match(cipher_text):
            match_percentage = len(md5_pattern.match(cipher_text).group()) / len(cipher_text) * 100
            return "MD5", match_percentage
        else:
            return "MD5", 0

    def identify_aes_cipher(self, cipher_text):
        # Implement AES cipher recognition logic here
        # You can look for the specific AES key pattern
        aes_pattern = re.compile(r'^[0-9a-fA-F]{64}$')
        if aes_pattern.match(cipher_text):
            match_percentage = len(aes_pattern.match(cipher_text).group()) / len(cipher_text) * 100
            return "AES", match_percentage
        else:
            return "AES", 0
        
    def identify_des_cipher(self, cipher_text):
    # Implement DES cipher recognition logic here
    # You can look for the specific DES key pattern
        des_pattern = re.compile(r'^[0-9a-fA-F]{16}$')
        if des_pattern.match(cipher_text):
            match_percentage = len(des_pattern.match(cipher_text).group()) / len(cipher_text) * 100
            return "DES", match_percentage
        else:
            return "DES", 0


    # Define recognition functions for other ciphers similarly

    def identify_cipher(self, cipher_text):
        cipher_recognitions = []

        cipher_recognitions.append(self.identify_base64_cipher(cipher_text))
        cipher_recognitions.append(self.identify_md5_cipher(cipher_text))
        cipher_recognitions.append(self.identify_aes_cipher(cipher_text))
        cipher_recognitions.append(self.identify_caesar_cipher(cipher_text))
        cipher_recognitions.append(self.identify_des_cipher(cipher_text))
        # Add similar functions for other ciphers

        # higher percentage to lower percentage
        cipher_recognitions.sort(key=lambda x: x[1], reverse=True)
        return cipher_recognitions

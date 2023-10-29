import re

class CipherIdentify():
    def identify_caesar_cipher(self, cipher_text):
        # Implement Caesar cipher recognition logic here
        # You can look for patterns, such as a consistent shift, to recognize it
        caesar_pattern = re.compile(r'^[A-Za-z]*[BCDE]+$')
        
        if caesar_pattern.match(cipher_text):
            match_percentage = len(caesar_pattern.match(cipher_text).group()) / len(cipher_text) * 100
            return "Caesar", match_percentage
        else:
            return "Caesar", 0

    def identify_base64_cipher(self, cipher_text):
        # Implement Vigenère cipher recognition logic here
        # You can look for key length patterns or known keywords in the text
        base64_pattern = re.compile(r'^[A-Za-z0-9+/]*={0,2}=$')
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

    def identify_shift_cipher(self, cipher_text):
    # Implement Shift cipher recognition logic here
    # Look for patterns where characters are shifted by a consistent number of positions in the alphabet
        shift_pattern = re.compile(r'^[A-Za-z]+$')

        if shift_pattern.match(cipher_text):
            # To calculate the match percentage for Shift ciphers, you can compare it to the pattern
            # and calculate the percentage of matching characters.
            pattern_match = shift_pattern.match(cipher_text).group()
            match_count = sum(1 for a, b in zip(pattern_match, cipher_text) if a == b)
            match_percentage = match_count / len(cipher_text) * 100
            return "Shift", match_percentage
        else:
            return "Shift", 0
        
    def identify_rsa_cipher(self, cipher_text):
    # Implement Shift cipher recognition logic here
    # Look for patterns where characters are shifted by a consistent number of positions in the alphabet
        rsa_pattern = re.compile(r'^\d+$')

        if rsa_pattern.match(cipher_text):
            # To calculate the match percentage for Shift ciphers, you can compare it to the pattern
            # and calculate the percentage of matching characters.
            match_percentage = len(rsa_pattern.match(cipher_text).group()) / len(cipher_text) * 100
            return "RSA", match_percentage
        else:
            return "RSA", 0

    def identify_hill_cipher(self, cipher_text):
        # Implement Hill cipher recognition logic here
        # You can look for patterns that match the characteristics of Hill ciphers
        hill_pattern = re.compile(r'^[A-Za-z]{4,16}$')  # Adjust the pattern as needed

        if hill_pattern.match(cipher_text):
            match_percentage = len(hill_pattern.match(cipher_text).group()) / len(cipher_text) * 100
            return "Hill", match_percentage
        else:
            return "Hill", 0

    # Define recognition functions for other ciphers similarly
    def identify_cipher(self, cipher_text):
        cipher_recognitions = []

        cipher_recognitions.append(self.identify_base64_cipher(cipher_text))
        cipher_recognitions.append(self.identify_md5_cipher(cipher_text))
        cipher_recognitions.append(self.identify_aes_cipher(cipher_text))
        cipher_recognitions.append(self.identify_caesar_cipher(cipher_text))
        cipher_recognitions.append(self.identify_des_cipher(cipher_text))
        cipher_recognitions.append(self.identify_shift_cipher(cipher_text))
        cipher_recognitions.append(self.identify_rsa_cipher(cipher_text))
        cipher_recognitions.append(self.identify_hill_cipher(cipher_text))
        # Add similar functions for other ciphers

        # higher percentage to lower percentage
        cipher_recognitions.sort(key=lambda x: x[1], reverse=True)
        return cipher_recognitions

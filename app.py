from flask import Flask, render_template, request, url_for, redirect
import base64,hashlib, itertools
from rsa import rsa
app = Flask(__name__)

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

obj = Ciphers()
obj_rsa = rsa()

@app.route('/')
def HomePage():
    return render_template("index.html")

@app.route('/base64_',methods=['GET','POST'])
def base64_():
    if request.method == "POST":
        text = request.form["text"]
        if 'encrypt' in request.form:
            output = obj.base64_encode(text)
        elif 'decrypt' in request.form:
            output = obj.base64_decode(text)
        else:
            output = "Invalid request"

        return render_template("base64_.html", output=output)
    else:
        return render_template("base64_.html")
    
@app.route('/rsa',methods=['GET','POST'])
def rsa():
    keys = {'public': '', 'private': ''}
    if request.method == "POST":
        p = int(request.form["p"])
        q = int(request.form["q"])
        e = int(request.form["e"])

        if 'calc' in request.form:
            public, private = obj_rsa.generate_key_pair(p=p, q=q, e=e)
            keys['public'] = public
            keys['private'] = private
            return render_template("rsa.html", keys=keys)
        
        else:
            output = "Invalid request"

    else:
        return render_template('rsa.html')

@app.route('/Ceaser',methods=['GET','POST'])
def Ceaser():
    if request.method == "POST":
        text = request.form["text"]
        shift = int(request.form["shift"])
        if 'encrypt' in request.form:
            output = obj.caesar_encode(text,shift)
        elif 'decrypt' in request.form:
            output = obj.caesar_decode(text,shift)
        else:
            output = "Invalid request"

        return render_template("Ceaser.html", output=output)
    else:
        return render_template('Ceaser.html')
    

@app.route('/Hill',methods=['GET','POST'])
def Hill():
    return render_template('Hill.html')

@app.route('/Shift',methods=['GET','POST'])
def Shift():
    if request.method == "POST":
        text = request.form["text"]
        shift = int(request.form["shift"])
        if 'encrypt' in request.form:
            output = obj.Shift_encode(text,shift)
        elif 'decrypt' in request.form:
            output = obj.Shift_decode(text,shift)
        else:
            output = "Invalid request"

        return render_template("Shift.html", output=output)
    else:
        return render_template('Shift.html')
    

@app.route('/aes',methods=['GET','POST'])
def aes():
    return render_template('aes.html')

@app.route('/des',methods=['GET','POST'])
def des():
    return render_template('des.html')

@app.route('/chacha',methods=['GET','POST'])
def chacha():
    return render_template('chacha.html')

@app.route('/md5',methods=['GET','POST'])
def md5():
    if request.method == "POST":
        text = request.form["text"]
        if 'encrypt' in request.form:
            output = obj.md5_encode(text)
        elif 'decrypt' in request.form:
            output = obj.md5_decode(text,5)
        else:
            output = "Invalid request"

        return render_template('md5.html',output=output)
    else:
        return render_template('md5.html')

if __name__ == '__main__':
    app.run(debug=True,port=8080)
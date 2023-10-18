from flask import Flask, render_template, request, url_for, redirect
import base64,hashlib, itertools
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
    
    def md5_encrypt(self, text):
        md5_hash = hashlib.md5()
        md5_hash.update(text.encode('utf-8'))
        md5_hex = md5_hash.hexdigest()
        return md5_hex
    
    def md5_decrypt(self,md5_hash,character_set,max_length):
        for length in range(1, max_length + 1):
            for candidate in itertools.product(character_set, repeat=length):
                candidate_str = ''.join(candidate)
                candidate_hash = hashlib.md5(candidate_str.encode('utf-8')).hexdigest()

                if candidate_hash == md5_hash:
                    return candidate_str

obj = Ciphers()

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
    return render_template('rsa.html')

@app.route('/Ceaser',methods=['GET','POST'])
def Ceaser():
    return render_template('Ceaser.html')

@app.route('/Hill',methods=['GET','POST'])
def Hill():
    return render_template('Hill.html')

@app.route('/Shift',methods=['GET','POST'])
def Shift():
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
            output = obj.md5_encrypt(text)
        elif 'decrypt' in request.form:
            output = obj.base64_decode(text)
        else:
            output = "Invalid request"

        return render_template('md5.html',output=output)
    else:
        return render_template('md5.html')

if __name__ == '__main__':
    app.run(debug=True,port=8080)
from flask import Flask, render_template, request, url_for, redirect
from Ciphers.rsa import rsa
from Ciphers.HillCipher import HillCipher
from Ciphers.Allciphers import Ciphers
app = Flask(__name__)

obj = Ciphers()
obj_rsa = rsa()
obj_hill = HillCipher()

@app.route('/')
def HomePage():
    if request.method == 'POST':
        Ciphertext = request.form['CT']
        output = obj.identify_cipher(Ciphertext)
        return render_template('index.html',output=output)
    else:
        return render_template('index.html')

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
        if 'calc' in request.form:
            p = int(request.form["p"])
            q = int(request.form["q"])
            e = int(request.form["e"])
            if e < 1 and e > p * q:
                print("hello")
                return f"Value of e should be in between 1 < e < {p*q}"
            public, private = obj_rsa.generate_key_pair(p=p, q=q, e=e)
            keys['public'] = public
            keys['private'] = private
            return render_template("rsa.html", keys=keys)
        else:
            output = "Invalid request"

    else:
        return render_template('rsa.html')

@app.route('/rsa/encode',methods=['POST'])
def rsa_encode():
    key = {'public':''}
    global encrypted_msg
    if 'encrypt' in request.form:
        text = request.form["text"]
        public = request.form["PubK"]

        # make pair
        a,b = public.split(',')
        temp = (int(a),int(b))
        key['public'] = temp
        
        #encrypt 
        encrypted_msg = obj_rsa.encrypt(key['public'],text)
        output = ''.join(map(lambda x: str(x), encrypted_msg))

        return render_template("rsa.html",Encrypted=output)
    
@app.route('/rsa/decode',methods=['POST'])
def rsa_decode():
    key = {'private':''}
    if 'decrypt' in request.form:
        text = request.form["text"]
        # convert text into list to make it iteraable
        # text = [int(x) for x in text]
        # print(text)
        private = request.form["PriK"]

        # make pair
        a,b = private.split(',')
        temp = (int(a),int(b))
        key['private'] = temp

        output = obj_rsa.decrypt(key['private'],encrypted_msg)

        return render_template("rsa.html",Decrypted=output)
    
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
    key = [[0,0],[0,0]]
    if request.method == "POST":
        text = request.form["text"]
        key[0][0] = int(request.form["0"])
        key[0][1] = int(request.form["1"])
        key[1][0] = int(request.form["2"])
        key[1][1] = int(request.form["3"])

        if 'encrypt' in request.form:
            output = obj_hill.encrypt(text,key)
        elif 'decrypt' in request.form:
            output = obj_hill.decrypt(text,key)
        else:
            output = "Invalid request"

        return render_template("Hill.html", output=output)
    else:
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
    if request.method == "POST":
        text = request.form["text"]
        temp_key = request.form["key"]

        key = obj.generate_aes_key(temp_key)
        
        if 'encrypt' in request.form:
            output = obj.AES_encode(text,key)
        elif 'decrypt' in request.form:
            output = obj.AES_decode(text,key)
        else:
            output = "Invalid request"

        return render_template("aes.html", output=output)
    else:
        return render_template("aes.html")

@app.route('/des',methods=['GET','POST'])
def des():
    if request.method == "POST":
        text = request.form["text"]
        key = request.form["key"]
        if 'encrypt' in request.form:
            output = obj.DES_encode(text,key)
        elif 'decrypt' in request.form:
            output = obj.DES_decode(text,key)
        else:
            output = "Invalid request"

        return render_template("des.html", output=output)
    else:
        return render_template("des.html")

@app.route('/chacha',methods=['GET','POST'])
def chacha():
    key = b'\x13g\xb9~G\xa90\xeb\xe5\xd5\xc0\xec\xcc}yh\xa7\x86ad)\xb1)\x16"\xec\xf0\xa1\x82T\x98\x0e'
    nonce = b'{\xddS\x812\xc7(\xf2ly\xaa\x00'

    if request.method == "POST":
        text = request.form["text"]
        if 'encrypt' in request.form:
            output = obj.Chacha_encode(text,key,nonce)
        elif 'decrypt' in request.form:
            output = obj.ChaCha_decode(text,key,nonce)
        else:
            output = "Invalid request"

        return render_template("chacha.html", output=output)
    else:
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
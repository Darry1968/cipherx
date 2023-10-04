from flask import Flask, render_template, request, url_for, redirect
import base64
app = Flask(__name__)

def base64_decode(cipher):
   decoded_bytes = base64.b64decode(cipher)
   decoded_string = decoded_bytes.decode('utf-8')
   return decoded_string

@app.route('/')
def HomePage():
    return render_template("index.html")

@app.route('/encode', methods=['GET','POST'])
def encode():
    if request.method == "POST":
        text = request.form["text"]
        if 'encrypt' in request.form:
            output = base64.b64encode(text.encode("utf-8"))
        elif 'decrypt' in request.form:
            output = base64_decode(text)
        else:
            output = "Invalid request"

        return render_template("base64.html", output=output)
    else:
        return render_template("base64.html")

if __name__ == '__main__':
    app.run(debug=True)
from flask import Flask, request, render_template_string, redirect, url_for, session
from lxml import etree  # Vulnerable parser

app = Flask(__name__)
app.secret_key = "secret_key_for_session"  # Needed for session management

@app.route('/')
def index():
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Register</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                background: #f4f4f4;
                margin: 0;
            }
            .container {
                background: white;
                padding: 20px;
                border-radius: 10px;
                box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.1);
                text-align: center;
                width: 350px;
            }
            h2 {
                margin-bottom: 20px;
            }
            input {
                width: 90%;
                padding: 10px;
                margin: 10px 0;
                border: 1px solid #ccc;
                border-radius: 5px;
                font-size: 16px;
            }
            button {
                width: 100%;
                padding: 10px;
                background: #007bff;
                color: white;
                border: none;
                border-radius: 5px;
                font-size: 18px;
                cursor: pointer;
                transition: 0.3s;
            }
            button:hover {
                background: #0056b3;
            }
        </style>
        <script>
            function registerUser() {
                var firstName = document.getElementById("first_name").value;
                var lastName = document.getElementById("last_name").value;

                var xmlPayload = `<user><first_name>${firstName}</first_name><last_name>${lastName}</last_name></user>`;

                var xhr = new XMLHttpRequest();
                xhr.open("POST", "/register", true);
                xhr.setRequestHeader("Content-Type", "application/xml");

                xhr.onreadystatechange = function () {
                    if (xhr.readyState === 4 && xhr.status === 200) {
                        window.location.href = "/welcome";
                    }
                };
                xhr.send(xmlPayload);
            }
        </script>
    </head>
    <body>
        <div class="container">
            <h2>Register</h2>
            <input type="text" id="first_name" placeholder="Enter First Name">
            <input type="text" id="last_name" placeholder="Enter Last Name">
            <button onclick="registerUser()">Register</button>
        </div>
    </body>
    </html>
    '''

@app.route('/register', methods=['POST'])
def register():
    try:
        # Get raw XML data from the request
        xml_data = request.data.decode("utf-8")

        # **XXE Vulnerability: Parsing untrusted XML with external entity resolution enabled**
        parser = etree.XMLParser(resolve_entities=True)  # Allows XXE
        root = etree.fromstring(xml_data.encode(), parser)  # Convert to bytes to avoid encoding error

        first_name = root.find('first_name').text
        last_name = root.find('last_name').text
        session['full_name'] = f"{first_name} {last_name}"  # Store in session for redirection

        return "Registration successful! <br> Welcome, "+first_name+" "+last_name, 200

    except Exception as e:
        return f"Error: {str(e)}", 400

@app.route('/welcome')
def welcome():
    full_name = session.get('full_name', 'Guest')
    return f"<h2 style='text-align: center; font-family: Arial;'>Registration successful! <br> Welcome, {full_name}!</h2>"

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=2020)

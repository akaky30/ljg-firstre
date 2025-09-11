from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    data = request.json or {}
    username = data.get("username", "demo")
    password = data.get("password", "pass")
    return jsonify({
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.demo.signature",
        "email": f"{username}@example.com",
        "phone": "13800138000"
    })

@app.route('/profile', methods=['GET'])
def profile():
    return jsonify({
        "name": "Demo User",
        "id": 12345
    })

if __name__ == '__main__':
    app.run(host="172.20.10.4", port=5000, debug=True)

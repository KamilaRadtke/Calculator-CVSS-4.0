from flask import Flask, request, jsonify, send_from_directory
from backend.cvss import VectorInput

app = Flask(__name__, static_folder='frontend/static', static_url_path='/static')
@app.route('/')
def index():
    return send_from_directory('frontend', 'index.html')

@app.route('/calculate', methods=['POST'])
def calculate():
    data = request.get_json()
    vector = data.get("vector", "")

    score, severity = VectorInput(vector)

    return jsonify({
        "score": score,
        "severity": severity
    })

if __name__ == '__main__':
    app.run(debug=True)

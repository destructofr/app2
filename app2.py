from flask import Flask, request, jsonify
import hashlib
import base64

app = Flask(__name__)

@app.route('/generate_hmac', methods=['POST'])
def generate_hmac():
    data = request.json
    
    str2 = data.get('json_structure')
    valueOf = data.get('time_value')
    mac_key = data.get('mac_value')

    data_to_hash = f"{str2}:{valueOf}:{mac_key}"
    hashed_data = hashlib.sha256(data_to_hash.encode()).digest()
    hmac_sha256_base64 = base64.b64encode(hashed_data).decode()

    response_data = {
        "input_str2": str2,
        "input_valueOf": valueOf,
        "input_mac_key": mac_key,
        "generated_hmac": hmac_sha256_base64
    }
    
    return jsonify(response_data)

if __name__ == '__main__':
    app.run(debug=True)

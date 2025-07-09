from predictor import Predictor
from flask import Flask, request, jsonify

app = Flask(__name__)
predictor = Predictor()

@app.route('/predict', methods=['POST'])
def predict():
    '''
    format of input data:
    input:
            sample = {
                "source_port": 49188,
                "destination_port": 800,
                "protocol": "http",  # 必须是训练中出现过的协议
                "Total Fwd Packets": 25746564557546,
                "Fwd Packet Length Mean": 6654600.0,
                "Flow IAT Mean": 425754.0，
                "timestamp": "2023-10-01T12:00:00Z",
                "source_ip": <>,
                destination_ip: <>

            }
    output:
    {
        "timestamp": packet_json.get("timestamp"),
        "src_ip": packet_json.get("source_ip"),
        "dst_ip": packet_json.get("destination_ip"),
        "category": pred_label,
        }
    '''
    data = request.json
    result = predictor.predict(data)
    return jsonify(result)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5001)
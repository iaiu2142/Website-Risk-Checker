from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

model = pickle.load(open("model.pkl", "rb"))
vectorizer = pickle.load(open("vectorizer.pkl", "rb"))

@app.route("/predict", methods=["POST"])

def predict():
    data = request.json["text"]
    vectorized = vectorizer.transform([data])
    prob = model.predict_proba(vectorized)[0][1]

    return jsonify({
        "risk_score": float(prob),
        "label": "Malicious" if prob > 0.5 else "Safe"
    })

if __name__ == "__main__":
    app.run(port=5000)
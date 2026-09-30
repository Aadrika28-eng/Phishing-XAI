from flask import Flask, render_template, request, jsonify
import sys
import os
import joblib
import pandas as pd
import shap

# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SRC_DIR = os.path.join(BASE_DIR, "src")
MODEL_DIR = os.path.join(BASE_DIR, "models")

if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

# ============================================================
# IMPORT FEATURE EXTRACTION
# ============================================================

from feature_extraction import extract_features

# ============================================================
# FLASK APP
# ============================================================

app = Flask(__name__)

# ============================================================
# LOAD XGBOOST MODEL
# ============================================================

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "xgboost_model.pkl"
)

xgb_model = joblib.load(MODEL_PATH)

print("XGBoost model loaded successfully!")

# ============================================================
# FEATURE NAMES
# ============================================================

FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "num_dots",
    "num_hyphens",
    "num_slashes",
    "num_digits",
    "num_letters",
    "num_special_chars",
    "num_at",
    "num_question",
    "num_equal",
    "num_percent",
    "has_ip",
    "has_https",
    "num_subdomains",
    "domain_length",
    "suspicious_keyword_count",
    "is_url_shortener",
    "digit_ratio",
    "special_char_ratio",
    "url_entropy"
]

# ============================================================
# SHAP EXPLAINER
# ============================================================

explainer = shap.TreeExplainer(xgb_model)

print("SHAP explainer created successfully!")

# ============================================================
# HOME PAGE
# ============================================================

@app.route("/")
def home():
    return render_template("index.html")


# ============================================================
# URL ANALYSIS API
# ============================================================

@app.route("/analyze", methods=["POST"])
def analyze():

    try:

        data = request.get_json()

        url = data.get("url", "").strip()

        if not url:
            return jsonify({
                "success": False,
                "error": "Please enter a URL."
            })

        # ----------------------------------------------------
        # FEATURE EXTRACTION
        # ----------------------------------------------------

        features = extract_features(url)

        feature_df = pd.DataFrame([features])

        # Ensure exact feature order
        feature_df = feature_df[FEATURE_NAMES]

        # ----------------------------------------------------
        # PREDICTION
        # ----------------------------------------------------

        prediction = int(
            xgb_model.predict(feature_df)[0]
        )

        probabilities = xgb_model.predict_proba(
            feature_df
        )[0]

        legitimate_probability = float(
            probabilities[0] * 100
        )

        phishing_probability = float(
            probabilities[1] * 100
        )

        if prediction == 1:
            result = "PHISHING"
            confidence = phishing_probability
        else:
            result = "LEGITIMATE"
            confidence = legitimate_probability

        # ----------------------------------------------------
        # SHAP
        # ----------------------------------------------------

        shap_result = explainer(feature_df)

        shap_values = shap_result.values[0]

        # ----------------------------------------------------
        # FEATURE CONTRIBUTIONS
        # ----------------------------------------------------

        contributions = []

        for feature, value, shap_value in zip(
            FEATURE_NAMES,
            feature_df.iloc[0].values,
            shap_values
        ):

            contributions.append({
                "feature": feature,
                "value": float(value),
                "impact": float(shap_value),
                "absolute_impact": float(abs(shap_value))
            })

        # Sort by importance
        contributions.sort(
            key=lambda x: x["absolute_impact"],
            reverse=True
        )

        # Top 10
        contributions = contributions[:10]

        return jsonify({

            "success": True,

            "url": url,

            "prediction": result,

            "confidence": round(confidence, 2),

            "legitimate_probability":
                round(legitimate_probability, 2),

            "phishing_probability":
                round(phishing_probability, 2),

            "features": contributions

        })

    except Exception as e:

        print("ERROR:", str(e))

        return jsonify({
            "success": False,
            "error": str(e)
        })


# ============================================================
# RUN SERVER
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("        PHISHING-XAI WEB APPLICATION")
    print("=" * 60)

    print("\nServer running at:")
    print("http://127.0.0.1:5000")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
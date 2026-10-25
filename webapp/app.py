from flask import Flask, render_template, request, jsonify
import joblib
import pandas as pd
import numpy as np
import sys
import os
import shap
from urllib.parse import urlparse


# ============================================================
# PATH SETUP
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SRC_DIR = os.path.join(BASE_DIR, "..", "src")

sys.path.append(SRC_DIR)

from feature_extraction import extract_features


# ============================================================
# FLASK APP
# ============================================================

app = Flask(__name__)


# ============================================================
# LOAD MODELS
# ============================================================

MODEL_DIR = os.path.join(BASE_DIR, "..", "models")

lr_model = joblib.load(
    os.path.join(MODEL_DIR, "logistic_regression_model.pkl")
)

rf_model = joblib.load(
    os.path.join(MODEL_DIR, "random_forest_model_deploy.pkl")
)

xgb_model = joblib.load(
    os.path.join(MODEL_DIR, "xgboost_model.pkl")
)

print("All three models loaded successfully!")


# ============================================================
# SHAP EXPLAINER
# ============================================================

explainer = shap.TreeExplainer(xgb_model)

print("SHAP explainer created successfully!")


# ============================================================
# FEATURE NAMES
# ============================================================

feature_names = [
    'url_length',
    'hostname_length',
    'path_length',
    'num_dots',
    'num_hyphens',
    'num_slashes',
    'num_digits',
    'num_letters',
    'num_special_chars',
    'num_at',
    'num_question',
    'num_equal',
    'num_percent',
    'has_ip',
    'has_https',
    'num_subdomains',
    'domain_length',
    'suspicious_keyword_count',
    'is_url_shortener',
    'digit_ratio',
    'special_char_ratio',
    'url_entropy'
]


# ============================================================
# TRUSTED DOMAINS
# ============================================================

TRUSTED_DOMAINS = {
    "google.com",
    "github.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "python.org",
    "wikipedia.org",
    "youtube.com",
    "linkedin.com"
}


# ============================================================
# HUMAN-READABLE EXPLANATION MAPPING
# ============================================================

FEATURE_DESCRIPTIONS = {

    "suspicious_keyword_count":
        "Suspicious words or patterns in the URL influenced the phishing risk.",

    "has_ip":
        "The use of an IP address instead of a conventional domain influenced the phishing risk.",

    "num_dots":
        "The number of dots in the URL influenced the phishing risk.",

    "num_at":
        "The presence of '@' characters influenced the phishing risk.",

    "num_digits":
        "The number of numerical characters in the URL influenced the phishing risk.",

    "num_slashes":
        "The number of '/' characters in the URL influenced the phishing risk.",

    "num_hyphens":
        "The number of hyphens in the URL influenced the phishing risk.",

    "num_special_chars":
        "The presence of special characters influenced the phishing risk.",

    "url_length":
        "The overall length of the URL influenced the phishing risk.",

    "hostname_length":
        "The length of the hostname influenced the phishing risk.",

    "path_length":
        "The length of the URL path influenced the phishing risk.",

    "has_https":
        "The use of HTTPS influenced the phishing risk.",

    "num_subdomains":
        "The number of subdomains influenced the phishing risk.",

    "domain_length":
        "The length of the domain influenced the phishing risk.",

    "is_url_shortener":
        "The use of a URL-shortening service influenced the phishing risk.",

    "digit_ratio":
        "The proportion of digits in the URL influenced the phishing risk.",

    "special_char_ratio":
        "The proportion of special characters influenced the phishing risk.",

    "url_entropy":
        "The randomness and structural complexity of the URL influenced the phishing risk.",

    "num_question":
        "The number of question marks in the URL influenced the phishing risk.",

    "num_equal":
        "The number of '=' characters in the URL influenced the phishing risk.",

    "num_percent":
        "The number of percent-encoded characters influenced the phishing risk.",

    "num_letters":
        "The number of alphabetic characters in the URL influenced the phishing risk."
}


def create_human_explanation(feature, impact):

    description = FEATURE_DESCRIPTIONS.get(
        feature,
        f"The URL feature '{feature}' influenced the model's prediction."
    )

    if impact > 0:
        direction = "This feature increased the predicted phishing risk."
    else:
        direction = "This feature decreased the predicted phishing risk."

    return f"{description} {direction}"


# ============================================================
# HOME PAGE
# ============================================================

@app.route("/")
def home():

    return render_template("index.html")


# ============================================================
# ANALYZE URL
# ============================================================

@app.route("/analyze", methods=["POST"])
def analyze():

    try:

        data = request.get_json()

        if not data:

            return jsonify({
                "error": "No data received."
            }), 400

        url = data.get("url", "").strip()

        if not url:

            return jsonify({
                "error": "Please enter a URL."
            }), 400


        # ====================================================
        # NORMALIZE URL
        # ====================================================

        check_url = url

        if "://" not in check_url:

            check_url = "https://" + check_url

        parsed = urlparse(check_url)

        hostname = parsed.hostname.lower() if parsed.hostname else ""

        if hostname.startswith("www."):

            hostname = hostname[4:]


        # ====================================================
        # TRUSTED DOMAIN CHECK
        # ====================================================

        if hostname in TRUSTED_DOMAINS:

            return jsonify({

                "url": url,

                "final_prediction": "LEGITIMATE",

                "final_probability": 0.0,

                "trusted": True,

                "message":
                    "Recognized trusted domain.",

                "models": [

                    {
                        "name": "Logistic Regression",
                        "prediction": "LEGITIMATE",
                        "probability": 0.0
                    },

                    {
                        "name": "Random Forest",
                        "prediction": "LEGITIMATE",
                        "probability": 0.0
                    },

                    {
                        "name": "XGBoost",
                        "prediction": "LEGITIMATE",
                        "probability": 0.0
                    }

                ],

                "shap": [],

                "human_explanations": []

            })


        # ====================================================
        # FEATURE EXTRACTION
        # ====================================================

        features = extract_features(url)

        X_url = pd.DataFrame(
            [features],
            columns=feature_names
        )


        # ====================================================
        # MODEL PREDICTIONS
        # ====================================================

        models = {

            "Logistic Regression": lr_model,

            "Random Forest": rf_model,

            "XGBoost": xgb_model

        }

        model_results = []


        for name, model in models.items():

            prediction = int(
                model.predict(X_url)[0]
            )

            probabilities = model.predict_proba(X_url)[0]

            phishing_index = list(
                model.classes_
            ).index(1)

            phishing_probability = float(
                probabilities[phishing_index]
            )


            model_results.append({

                "name": name,

                "prediction":
                    "PHISHING"
                    if prediction == 1
                    else "LEGITIMATE",

                "probability":
                    round(
                        phishing_probability,
                        4
                    )

            })


        # ====================================================
        # CONSENSUS DECISION
        # ====================================================

        predictions = [

            result["prediction"]

            for result in model_results

        ]

        mean_probability = np.mean([

            result["probability"]

            for result in model_results

        ])


        if len(set(predictions)) > 1:

            final_prediction = "NEEDS REVIEW"

            message = (
                "The machine learning models disagree "
                "on this URL."
            )


        elif 0.35 <= mean_probability <= 0.65:

            final_prediction = "NEEDS REVIEW"

            message = (
                "The prediction is uncertain because "
                "the phishing probability is near the "
                "decision threshold."
            )


        elif mean_probability > 0.65:

            final_prediction = "PHISHING"

            message = (
                "The models agree that this URL "
                "appears suspicious."
            )


        else:

            final_prediction = "LEGITIMATE"

            message = (
                "The models agree that this URL "
                "appears legitimate."
            )


        # ====================================================
        # SHAP EXPLANATION
        # ====================================================

        shap_output = explainer.shap_values(X_url)


        # Handle different SHAP output formats
        if isinstance(shap_output, list):

            shap_values = shap_output[1][0]

        else:

            shap_values = shap_output[0]


        shap_results = []


        for feature, value in zip(
            feature_names,
            shap_values
        ):

            shap_results.append({

                "feature": feature,

                "impact": round(
                    float(value),
                    4
                )

            })


        # Sort by absolute contribution
        shap_results = sorted(

            shap_results,

            key=lambda x: abs(
                x["impact"]
            ),

            reverse=True

        )[:10]


        # ====================================================
        # HUMAN-READABLE EXPLANATIONS
        # ====================================================

        human_explanations = []


        for item in shap_results:

            human_explanations.append({

                "feature":
                    item["feature"],

                "impact":
                    item["impact"],

                "explanation":
                    create_human_explanation(
                        item["feature"],
                        item["impact"]
                    )

            })


        # ====================================================
        # FINAL RESPONSE
        # ====================================================

        return jsonify({

            "url": url,

            "final_prediction":
                final_prediction,

            "final_probability":
                round(
                    float(mean_probability),
                    4
                ),

            "trusted": False,

            "message":
                message,

            "models":
                model_results,

            "shap":
                shap_results,

            "human_explanations":
                human_explanations

        })


    except Exception as e:

        print("ERROR:", str(e))

        return jsonify({

            "error":
                "An error occurred while analyzing the URL.",

            "details":
                str(e)

        }), 500


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":

    print("Webapp server running...")

    app.run(

        debug=True,

        host="127.0.0.1",

        port=5000

    )
// ============================================================
// SET EXAMPLE URL
// ============================================================

function setURL(url) {

    document.getElementById("urlInput").value = url;

}


// ============================================================
// ANALYZE URL
// ============================================================

async function analyzeURL() {


    const url =
        document.getElementById("urlInput")
            .value
            .trim();


    if (!url) {

        alert("Please enter a URL.");

        return;

    }


    // Show loading
    document.getElementById("loading")
        .style.display = "block";


    // Hide old results
    document.getElementById("results")
        .style.display = "none";


    try {


        const response = await fetch(
            "/analyze",
            {

                method: "POST",

                headers: {

                    "Content-Type":
                        "application/json"

                },

                body: JSON.stringify({

                    url: url

                })

            }
        );


        const data =
            await response.json();


        // Backend error
        if (!response.ok || data.error) {

            alert(
                data.error ||
                "Unable to analyze the URL."
            );

            return;

        }


        displayResults(data);


    }

    catch (error) {


        console.error(error);


        alert(
            "Something went wrong. " +
            "Make sure Flask is running."
        );


    }

    finally {


        document.getElementById("loading")
            .style.display = "none";


    }

}


// ============================================================
// DISPLAY RESULTS
// ============================================================

function displayResults(data) {


    // Show results
    document.getElementById("results")
        .style.display = "grid";


    const prediction =
        document.getElementById("prediction");


    const message =
        document.getElementById("message");


    const icon =
        document.getElementById("statusIcon");


    const probabilityText =
        document.getElementById(
            "probabilityText"
        );


    const progressBar =
        document.getElementById(
            "progressBar"
        );


    // ========================================================
    // MAIN PREDICTION
    // ========================================================


    prediction.innerText =
        data.final_prediction;


    message.innerText =
        data.message;


    const probability =
        data.final_probability * 100;


    probabilityText.innerText =
        probability.toFixed(2) + "%";


    // Reset bar
    progressBar.style.width =
        probability + "%";


    // ========================================================
    // LEGITIMATE
    // ========================================================

    if (
        data.final_prediction ===
        "LEGITIMATE"
    ) {


        icon.innerText = "🛡️";


        prediction.style.color =
            "#34d399";


        progressBar.style.background =
            "#34d399";


    }


    // ========================================================
    // PHISHING
    // ========================================================

    else if (
        data.final_prediction ===
        "PHISHING"
    ) {


        icon.innerText = "🚨";


        prediction.style.color =
            "#f87171";


        progressBar.style.background =
            "#ef4444";


    }


    // ========================================================
    // NEEDS REVIEW
    // ========================================================

    else {


        icon.innerText = "⚠️";


        prediction.style.color =
            "#fbbf24";


        progressBar.style.background =
            "#fbbf24";


    }


    // ========================================================
    // MODEL CONSENSUS
    // ========================================================

    const modelsDiv =
        document.getElementById(
            "models"
        );


    modelsDiv.innerHTML = "";


    data.models.forEach(
        model => {


            let className =
                "legitimate";


            if (
                model.prediction ===
                "PHISHING"
            ) {

                className =
                    "phishing";

            }


            if (
                model.prediction ===
                "NEEDS REVIEW"
            ) {

                className =
                    "review";

            }


            modelsDiv.innerHTML += `

                <div class="model">

                    <span>

                        ${model.name}

                    </span>


                    <span class="badge ${className}">

                        ${model.prediction}

                        (${(
                            model.probability * 100
                        ).toFixed(1)}%)

                    </span>

                </div>

            `;

        }
    );


    // ========================================================
    // SHAP RESULTS
    // ========================================================

    const shapDiv =
        document.getElementById(
            "shapResults"
        );


    shapDiv.innerHTML = "";


    if (data.trusted) {


        shapDiv.innerHTML = `

            <div class="explanation-safe">

                🛡️ This URL belongs to a
                recognized trusted domain.
                The trusted-domain validation
                layer classified it as legitimate.

            </div>

        `;


    }

    else {


        data.shap.forEach(
            item => {


                const impact =
                    item.impact;


                const width =
                    Math.min(
                        Math.abs(impact) * 150,
                        100
                    );


                const label =
                    impact > 0
                    ? "Increases phishing risk"
                    : "Decreases phishing risk";


                const fillColor =
                    impact > 0
                    ? "#ef4444"
                    : "#34d399";


                shapDiv.innerHTML += `

                    <div class="shap-row">


                        <div class="shap-label">

                            <span>

                                ${item.feature}

                            </span>


                            <span>

                                ${impact.toFixed(3)}

                            </span>

                        </div>


                        <div class="shap-bar">


                            <div

                                class="shap-fill"

                                style="
                                    width:${width}%;
                                    background:${fillColor};
                                "

                            >

                            </div>


                        </div>


                        <small>

                            ${label}

                        </small>


                    </div>

                `;

            }
        );

    }


    // ========================================================
    // HUMAN-READABLE AI EXPLANATIONS
    // ========================================================

    const explanationDiv =
        document.getElementById(
            "humanExplanations"
        );


    explanationDiv.innerHTML = "";


    if (data.trusted) {


        explanationDiv.innerHTML = `

            <div class="explanation-safe">

                🛡️ <strong>Trusted Domain</strong>

                <br><br>

                This URL belongs to a domain
                recognized by the trusted-domain
                validation layer.

                <br><br>

                Therefore, the system classified
                it as legitimate without requiring
                SHAP-based risk analysis.

            </div>

        `;


    }

    else if (
        data.human_explanations &&
        data.human_explanations.length > 0
    ) {


        data.human_explanations
            .slice(0, 5)
            .forEach(
                item => {


                    const icon =
                        item.impact > 0
                        ? "⚠️"
                        : "✅";


                    explanationDiv.innerHTML += `

                        <div class="explanation-item">


                            <span
                                class="explanation-icon"
                            >

                                ${icon}

                            </span>


                            <span>

                                ${item.explanation}

                            </span>


                        </div>

                    `;

                }
            );


    }

    else {


        explanationDiv.innerHTML = `

            <div class="explanation-safe">

                No major explanatory features
                were identified.

            </div>

        `;

    }

}

let totalEmails = 0;
let phishingEmails = 0;
let suspiciousEmails = 0;
let safeEmails = 0;

// Display a list of items
function showList(id, items) {
    const list = document.getElementById(id);
    list.innerHTML = "";

    (items || []).forEach(item => {
        const li = document.createElement("li");
        li.textContent = item;
        list.appendChild(li);
    });
}

// Generate analyst recommendations
function getRecommendations(verdict) {
    if (verdict === "HIGH RISK") {
        return [
            "Do not click any links or open attachments.",
            "Report the email to the security team.",
            "Quarantine the email for further investigation."
        ];
    }

    if (verdict === "SUSPICIOUS") {
        return [
            "Verify the sender through a trusted channel.",
            "Inspect suspicious URLs carefully.",
            "Do not share passwords or sensitive information."
        ];
    }

    return [
        "No major threat indicators were detected.",
        "Remain cautious with unexpected emails.",
        "Verify unusual requests before taking action."
    ];
}

// Display investigation details
function displayResults(data) {
    document.getElementById("emptyMessage").hidden = true;
    document.getElementById("results").hidden = false;

    document.getElementById("riskScore").textContent =
        data.risk_score + "/100";

    document.getElementById("verdict").textContent = data.verdict;
    document.getElementById("sender").textContent = data.sender;
    document.getElementById("subject").textContent = data.subject;

    document.getElementById("emailBody").textContent =
        data.body || "No email body available.";

    showList("emailUrls", data.urls);
    showList("emailKeywords", data.keywords);
    showList("urlWarnings", data.url_warnings);
    showList("senderWarnings", data.sender_warnings);
    showList("replyWarnings", data.reply_warnings);
    showList("authChecks", data.auth_checks);

    // Threat indicators
    const indicators = [
        ...(data.keywords || []).map(
            item => "Suspicious keyword: " + item
        ),
        ...(data.url_warnings || []),
        ...(data.sender_warnings || []),
        ...(data.reply_warnings || [])
    ];

    if (indicators.length === 0) {
        showList("indicators", [
            "No major threat indicators detected."
        ]);
    } else {
        showList("indicators", indicators);
    }

    // Analyst recommendations
    showList(
        "recommendationList",
        getRecommendations(data.verdict)
    );

    // Risk bar
    document.getElementById("riskBar").style.width =
        Math.min(Number(data.risk_score) || 0, 100) + "%";
}

// Update Threat Analytics Dashboard
function updateAnalytics(records) {

    const total = records.length;

    // Threat distribution
    const highRisk = records.filter(
        record => record.verdict === "HIGH RISK"
    ).length;

    const suspicious = records.filter(
        record => record.verdict === "SUSPICIOUS"
    ).length;

    const lowRisk = records.filter(
        record => record.verdict === "LOW RISK"
    ).length;

    // Risk score distribution
    const critical = records.filter(
        record => Number(record.risk_score) >= 60
    ).length;

    const medium = records.filter(
        record =>
            Number(record.risk_score) >= 25 &&
            Number(record.risk_score) < 60
    ).length;

    const low = records.filter(
        record => Number(record.risk_score) < 25
    ).length;

    function percentage(count) {
        return total === 0 ? 0 : (count / total) * 100;
    }

    // Display threat counts
    document.getElementById("highRiskCount").textContent = highRisk;
    document.getElementById("suspiciousCount").textContent = suspicious;
    document.getElementById("lowRiskCount").textContent = lowRisk;

    // Display risk score counts
    document.getElementById("criticalCount").textContent = critical;
    document.getElementById("mediumCount").textContent = medium;
    document.getElementById("lowCount").textContent = low;

    // Update chart bars
    document.getElementById("highRiskBar").style.width =
        percentage(highRisk) + "%";

    document.getElementById("suspiciousBar").style.width =
        percentage(suspicious) + "%";

    document.getElementById("lowRiskBar").style.width =
        percentage(lowRisk) + "%";

    document.getElementById("criticalBar").style.width =
        percentage(critical) + "%";

    document.getElementById("mediumBar").style.width =
        percentage(medium) + "%";

    document.getElementById("lowBar").style.width =
        percentage(low) + "%";
}

// Analyze uploaded email
document.getElementById("analyzeBtn").addEventListener(
    "click",
    async function () {

        const file = document.getElementById("emailFile").files[0];

        if (!file) {
            alert("Please select an email file first.");
            return;
        }

        const formData = new FormData();
        formData.append("email", file);

        try {
            const response = await fetch("/analyze", {
                method: "POST",
                body: formData
            });

            const data = await response.json();

            if (!response.ok) {
                alert(data.error || "Email analysis failed.");
                return;
            }

            // Display analysis results
            displayResults(data);

            // Refresh saved history, statistics and charts
            await loadHistory();

        } catch (error) {
            console.error(error);
            alert("Unable to process the email.");
        }
    }
);

// Load saved analysis history from SQLite
async function loadHistory() {

    try {
        const response = await fetch("/history");

        if (!response.ok) {
            throw new Error("Unable to load history.");
        }

        const records = await response.json();

        // Dashboard statistics
        totalEmails = records.length;

        phishingEmails = records.filter(
            record => record.verdict === "HIGH RISK"
        ).length;

        suspiciousEmails = records.filter(
            record => record.verdict === "SUSPICIOUS"
        ).length;

        safeEmails = records.filter(
            record => record.verdict === "LOW RISK"
        ).length;

        document.getElementById("totalEmails").textContent =
            totalEmails;

        document.getElementById("phishingEmails").textContent =
            phishingEmails;

        document.getElementById("suspiciousEmails").textContent =
            suspiciousEmails;

        document.getElementById("safeEmails").textContent =
            safeEmails;

        // Update analytics charts
        updateAnalytics(records);

        // Display history table
        const historyTable = document.getElementById("historyTable");
        historyTable.innerHTML = "";

        if (records.length === 0) {
            historyTable.innerHTML =
                '<tr><td colspan="5">No analysis records yet.</td></tr>';
            return;
        }

        records.forEach(record => {

            const row = document.createElement("tr");

            const values = [
                record.sender,
                record.subject,
                record.risk_score + "/100",
                record.verdict,
                record.analyzed_at
            ];

            values.forEach((value, index) => {

                const cell = document.createElement("td");

                if (index === 2) {

                    const score = document.createElement("span");
                    score.className = "history-score";
                    score.textContent = value;
                    cell.appendChild(score);

                } else if (index === 3) {

                    const badge = document.createElement("span");
                    badge.className = "verdict-badge";

                    if (value === "HIGH RISK") {
                        badge.classList.add("high-risk");
                    } else if (value === "SUSPICIOUS") {
                        badge.classList.add("suspicious");
                    } else {
                        badge.classList.add("low-risk");
                    }

                    badge.textContent = value;
                    cell.appendChild(badge);

                } else {
                    cell.textContent = value || "";
                }

                row.appendChild(cell);
            });

            // Open previous investigation when row is clicked
            row.style.cursor = "pointer";

            row.addEventListener("click", function () {

                displayResults(record);

                document.getElementById("analyzer").scrollIntoView({
                    behavior: "smooth"
                });
            });

            historyTable.appendChild(row);
        });

    } catch (error) {
        console.error("History loading error:", error);
    }
}

// Download Investigation Report
document.getElementById("exportReportBtn").addEventListener(
    "click",
    function () {

        const report = `
PHISHGUARD - EMAIL INVESTIGATION REPORT
=======================================

Sender: ${document.getElementById("sender").textContent}
Subject: ${document.getElementById("subject").textContent}

Risk Score: ${document.getElementById("riskScore").textContent}
Verdict: ${document.getElementById("verdict").textContent}

EMAIL BODY
----------
${document.getElementById("emailBody").textContent}

THREAT INDICATORS
-----------------
${document.getElementById("indicators").innerText}

EXTRACTED URLS
--------------
${document.getElementById("emailUrls").innerText}

SUSPICIOUS KEYWORDS
-------------------
${document.getElementById("emailKeywords").innerText}

URL WARNINGS
------------
${document.getElementById("urlWarnings").innerText}

SENDER WARNINGS
---------------
${document.getElementById("senderWarnings").innerText}

REPLY-TO WARNINGS
-----------------
${document.getElementById("replyWarnings").innerText}

AUTHENTICATION RESULTS
----------------------
${document.getElementById("authChecks").innerText}

ANALYST RECOMMENDATIONS
-----------------------
${document.getElementById("recommendationList").innerText}

=======================================
Generated by PhishGuard
`;

        const blob = new Blob([report], {
            type: "text/plain"
        });

        const link = document.createElement("a");

        link.href = URL.createObjectURL(blob);
        link.download = "PhishGuard_Investigation_Report.txt";

        link.click();

        URL.revokeObjectURL(link.href);
    }
);

// Load history when dashboard opens
loadHistory();

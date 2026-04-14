document.getElementById("scanBtn").addEventListener("click", scanURL);

async function scanURL() {
    const urlInput = document.getElementById("urlInput");
    const resultText = document.getElementById("result");
    const reasonsList = document.getElementById("reasons");

    let url = urlInput.value.trim();

    resultText.innerText = "";
    reasonsList.innerHTML = "";

    if (!url) {
        resultText.innerText = "Please enter a URL.";
        return;
    }

    if (!url.startsWith("http://") && !url.startsWith("https://")) {
        url = "https://" + url;
    }

    resultText.innerText = "Scanning...";
    resultText.style.color = "yellow";

    try {
        const response = await fetch("/scan", {  
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: url })
        });

        if (!response.ok) {
            throw new Error("Server error");
        }

        const data = await response.json();

        resultText.innerText =
            `Safe: ${data.safe_percent}% | Malicious: ${data.malicious_percent}%`;

        if (data.label === "Malicious") {
            resultText.style.color = "red";
        } else if (data.label === "Suspicious") {
            resultText.style.color = "orange";
        } else {
            resultText.style.color = "green";
        }

        reasonsList.innerHTML = "";

        if (!data.reasons || data.reasons.length === 0) {
            const li = document.createElement("li");
            li.innerText = "No suspicious patterns found";
            reasonsList.appendChild(li);
        } else {
            data.reasons.forEach(reason => {
                const li = document.createElement("li");
                li.innerText = reason;
                reasonsList.appendChild(li);
            });
        }

    } catch (error) {
        console.error(error);
        resultText.innerText = "Error: Could not connect to server.";
        resultText.style.color = "orange";
    }
}

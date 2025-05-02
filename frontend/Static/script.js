document.addEventListener('DOMContentLoaded', function () {
    const form = document.getElementById('cvssForm');
    const resultDiv = document.getElementById('result');
    const showVectorBtn = document.getElementById('showVectorBtn');

    // Funkcja pomocnicza – generowanie wektora z formularza
    function getCVSSVector() {
        const formData = new FormData(form);
        const vectorParts = [];

        for (const [key, value] of formData.entries()) {
            if (value !== "") {
                vectorParts.push(`${key}:${value}`);
            }
        }

        return vectorParts.join('/');
    }

    // 🔹 Tylko wyświetl wektor (bez wysyłania)
    showVectorBtn.addEventListener('click', function () {
        const vector = getCVSSVector();
        resultDiv.innerHTML = `<p class="text-info">Wektor CVSS: <code>${vector}</code></p>`;
    });

    // 🔹 Wyślij i oblicz wynik
    form.addEventListener('submit', function (e) {
        e.preventDefault();
        const vector = getCVSSVector();

        fetch('/calculate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ vector })
        })
        .then(res => res.json())
        .then(data => {
            resultDiv.innerHTML = `
                <p class="text-info">Wektor CVSS: <code>${vector}</code></p>
                <p class="text-success">Wynik: <strong>${data.score}</strong></p>
                <p>Poziom zagrożenia: <strong>${data.severity}</strong></p>
            `;
        })
        .catch(err => {
            resultDiv.innerHTML = `<p class="text-danger">Błąd: ${err.message}</p>`;
        });
    });
});

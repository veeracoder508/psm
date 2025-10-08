document.addEventListener('DOMContentLoaded', () => {
    // Command Form (Original kill-by-token)
    const commandForm = document.getElementById('commandForm');
    const resultDiv = document.getElementById('result');
    
    // NEW Manager API elements
    const startServerForm = document.getElementById('startServerForm');
    const startResultDiv = document.getElementById('startResult');
    const killByPortForm = document.getElementById('killByPortForm');
    const killResultDiv = document.getElementById('killResult');
    const listServersButton = document.getElementById('listServersButton');
    const listResultDiv = document.getElementById('listResult');

    if (!commandForm || !resultDiv || !startServerForm || !startResultDiv || !killByPortForm || !killResultDiv || !listServersButton || !listResultDiv) {
        console.error("Critical dashboard elements not found.");
        return;
    }

    // --- 1. EXISTING: KILL BY TOKEN (Internal Server API) ---
    commandForm.addEventListener('submit', function(event) {
        // Prevent the page from reloading
        event.preventDefault();

        resultDiv.innerHTML = "Sending command...";
        
        const token = document.getElementById('token').value.trim();
        const command = document.getElementById('command').value.trim();

        if (!token || !command) {
            resultDiv.innerHTML = "<span style='color: red;'>Error: Token and Command cannot be empty.</span>";
            return;
        }

        const formData = new URLSearchParams();
        formData.append('token', token);
        formData.append('command', command);

        // Use fetch to communicate with the Python server
        fetch('/submit', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: formData.toString()
        })
        .then(response => {
            return response.text();
        })
        .then(htmlText => {
            resultDiv.innerHTML = `
                <hr>
                <strong>Server Response:</strong>
                <div style='background-color: #2e4747; padding: 10px; border: 1px solid #ccc; color: white;'>
                    ${htmlText}
                </div>
            `;
            document.getElementById('command').value = '';
        })
        .catch(error => {
            console.error('Fetch error:', error);
            resultDiv.innerHTML = `<span style='color: red;'>Network Error: Could not reach the server.</span>`;
        });
    });

    // --- 2. NEW: START SERVER (Manager API) ---
    startServerForm.addEventListener('submit', function(event) {
        event.preventDefault();

        startResultDiv.innerHTML = "Attempting to start new server...";
        
        const newPort = document.getElementById('newPort').value.trim();
        const newId = document.getElementById('newId').value.trim();

        if (!newPort || !newId) {
            startResultDiv.innerHTML = "<span style='color: red;'>Error: Port and ID cannot be empty.</span>";
            return;
        }
        
        // Combine port and id into a single identifier string: 'port:id'
        const identifier = `${newPort}:${newId}`;

        const formData = new URLSearchParams();
        formData.append('action', 'start');
        formData.append('identifier', identifier);

        fetch('/manager-action', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: formData.toString()
        })
        .then(response => {
            return response.text();
        })
        .then(htmlText => {
            startResultDiv.innerHTML = htmlText;
            document.getElementById('newPort').value = '';
            document.getElementById('newId').value = '';
        })
        .catch(error => {
            console.error('Fetch error:', error);
            startResultDiv.innerHTML = `<span style='color: red;'>Network Error: Could not reach the server.</span>`;
        });
    });

    // --- 3. NEW: KILL SERVER BY PORT/TOKEN (Manager API) ---
    killByPortForm.addEventListener('submit', function(event) {
        event.preventDefault();

        killResultDiv.innerHTML = "Sending kill command...";
        
        const identifierToKill = document.getElementById('portToKill').value.trim();

        if (!identifierToKill) {
            killResultDiv.innerHTML = "<span style='color: red;'>Error: Port or Token cannot be empty.</span>";
            return;
        }

        const formData = new URLSearchParams();
        formData.append('action', 'kill');
        formData.append('identifier', identifierToKill); // Can be port (e.g., '8000') or token (e.g., 'XyZ1aBcD2e')

        fetch('/manager-action', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: formData.toString()
        })
        .then(response => {
            return response.text();
        })
        .then(htmlText => {
            killResultDiv.innerHTML = htmlText;
            document.getElementById('portToKill').value = '';
        })
        .catch(error => {
            console.error('Fetch error:', error);
            killResultDiv.innerHTML = `<span style='color: red;'>Network Error: Could not reach the server.</span>`;
        });
    });

    // --- 4. NEW: LIST SERVERS (Manager API) ---
    listServersButton.addEventListener('click', () => {
        listResultDiv.innerHTML = "Fetching active servers...";

        const formData = new URLSearchParams();
        formData.append('action', 'list');
        formData.append('identifier', ''); // Identifier is not needed for list action

        fetch('/manager-action', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: formData.toString()
        })
        .then(response => {
            return response.text();
        })
        .then(htmlText => {
            listResultDiv.innerHTML = htmlText;
        })
        .catch(error => {
            console.error('Fetch error:', error);
            listResultDiv.innerHTML = `<span style='color: red;'>Network Error: Could not reach the server.</span>`;
        });
    });
});
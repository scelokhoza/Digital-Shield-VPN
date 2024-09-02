function toggleVPN() {
    const statusElement = document.getElementById('vpn-status');
    const statusCircle = document.getElementById('status-circle');
    const toggleButton = document.getElementById('vpn-toggle');

    if (statusElement.textContent === 'VPN is OFF') {
        // Send request to Flask server to connect to VPN
        fetch('http://localhost:5000/start-vpn', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        })
        .then(response => {
            if (response.ok) {
                statusElement.textContent = 'VPN is ON';
                statusCircle.style.backgroundColor = '#28a745'; // Green color for ON
                toggleButton.textContent = 'Disconnect';
            } else {
                throw new Error('Failed to connect to VPN');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            statusElement.textContent = 'Connection Failed';
            statusCircle.style.backgroundColor = '#ff4d4f'; // Red color for failed connection
        });
    } else {
        // Send request to Flask server to disconnect from VPN
        fetch('http://localhost:5000/stop-vpn', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        })
        .then(response => {
            if (response.ok) {
                statusElement.textContent = 'VPN is OFF';
                statusCircle.style.backgroundColor = '#ff4d4f'; // Red color for OFF
                toggleButton.textContent = 'Connect';
            } else {
                throw new Error('Failed to disconnect from VPN');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            statusElement.textContent = 'Disconnection Failed';
            statusCircle.style.backgroundColor = '#ff4d4f'; // Red color for failed disconnection
        });
    }
}

function toggleVPN() {
    const statusElement = document.getElementById('vpn-status');
    const toggleButton = document.getElementById('vpn-toggle');

    if (statusElement.textContent === 'Disconnected') {
        // Send request to Flask server to connect to VPN
        fetch('http://localhost:5000/start-vpn', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        })
        .then(response => {
            if (response.ok) {
                statusElement.textContent = 'Connected';
                statusElement.style.color = 'green';
                toggleButton.textContent = 'Disconnect';
            } else {
                throw new Error('Failed to connect to VPN');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            statusElement.textContent = 'Connection Failed';
            statusElement.style.color = 'red';
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
                statusElement.textContent = 'Disconnected';
                statusElement.style.color = 'red';
                toggleButton.textContent = 'Connect';
            } else {
                throw new Error('Failed to disconnect from VPN');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            statusElement.textContent = 'Disconnection Failed';
            statusElement.style.color = 'red';
        });
    }
}

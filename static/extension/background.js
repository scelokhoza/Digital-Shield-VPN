let vpnConnected = false;

// Listen for messages from the popup script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'toggleVPN') {
        if (vpnConnected) {
            // Send a request to disconnect the VPN
            fetch('http://localhost:5000/stop-vpn', {
                method: 'POST'
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    vpnConnected = false;
                    sendResponse({status: 'disconnected'});
                }
            })
            .catch(error => console.error('Error:', error));
        } else {
            // Send a request to connect to the VPN
            fetch('http://localhost:5000/start-vpn', {
                method: 'POST'
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    vpnConnected = true;
                    sendResponse({status: 'connected'});
                }
            })
            .catch(error => console.error('Error:', error));
        }
        return true; // Keep the messaging channel open for asynchronous response
    }
});

// Handle extension installation or updates
chrome.runtime.onInstalled.addListener((details) => {
    if (details.reason === 'install') {
        console.log('Extension installed');
    } else if (details.reason === 'update') {
        console.log('Extension updated');
    }
});

// Optional: Periodically check VPN status
chrome.alarms.create('vpnCheck', { periodInMinutes: 5 });
chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === 'vpnCheck') {
        // Implement a status check or reconnect if necessary
        console.log('Checking VPN status...');
    }
});

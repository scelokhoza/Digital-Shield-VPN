function toggleVPN() {
    const statusElement = document.getElementById('vpn-status');
    const toggleButton = document.getElementById('vpn-toggle');

    if (statusElement.textContent === 'Disconnected') {
        statusElement.textContent = 'Connected';
        statusElement.style.color = 'green';
        toggleButton.textContent = 'Disconnect';
    } else {
        statusElement.textContent = 'Disconnected';
        statusElement.style.color = 'red';
        toggleButton.textContent = 'Connect';
    }
}

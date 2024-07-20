function onSuccess(googleUser) {
    const id_token = googleUser.getAuthResponse().id_token;

    fetch('/google-login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ id_token: id_token })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            console.log('User logged in with Google. User ID:', data.user_id);
            window.location.href = '/start_vpn';
        } else {
            console.error('Google login failed:', data.message);
            // Handle error cases
        }
    })
    .catch(error => {
        console.error('Error logging in with Google:', error);
    });
}

function onFailure(error) {
    console.error('Google Sign-In failed:', error);
    // Handle failure cases
}

function renderButton() {
    gapi.signin2.render('my-signin2', {
        'scope': 'profile email',
        'width': 240,
        'height': 50,
        'longtitle': true,
        'theme': 'dark',
        'onsuccess': onSuccess,
        'onfailure': onFailure
    });
}

const { startRegistration, startAuthentication } = SimpleWebAuthnBrowser;

// DOM Elements
const usernameInput = document.getElementById('username');
const btnRegister = document.getElementById('btn-register');
const btnLogin = document.getElementById('btn-login');
const btnLogout = document.getElementById('btn-logout');
const messageContainer = document.getElementById('message-container');
const authContainer = document.getElementById('auth-container');
const profileContainer = document.getElementById('profile-container');
const profileUsername = document.getElementById('profile-username');
const profileInitial = document.getElementById('profile-initial');

// State
let currentUsername = '';

// Helper to show messages
function showMessage(msg, isError = false) {
    messageContainer.textContent = msg;
    messageContainer.className = `message ${isError ? 'error' : 'success'}`;
    messageContainer.classList.remove('hidden');
    
    // Auto-hide success messages after 5s
    if (!isError) {
        setTimeout(() => {
            messageContainer.classList.add('hidden');
        }, 5000);
    }
}

function hideMessage() {
    messageContainer.classList.add('hidden');
}

// Check if browser supports WebAuthn
if (!window.PublicKeyCredential) {
    showMessage('Error: WebAuthn is not supported in this browser.', true);
    btnRegister.disabled = true;
    btnLogin.disabled = true;
}

// Show Profile
function showProfile(username) {
    authContainer.classList.add('hidden');
    profileContainer.classList.remove('hidden');
    profileUsername.textContent = username;
    profileInitial.textContent = username.charAt(0).toUpperCase();
    hideMessage();
}

// Show Auth
function showAuth() {
    authContainer.classList.remove('hidden');
    profileContainer.classList.add('hidden');
    usernameInput.value = '';
}

// REGISTRATION FLOW
btnRegister.addEventListener('click', async () => {
    const username = usernameInput.value.trim();
    if (!username) {
        showMessage('Please enter a username first', true);
        return;
    }
    
    btnRegister.disabled = true;
    btnRegister.innerHTML = 'Registering...';
    hideMessage();

    try {
        // 1. Get registration options from server
        const resp = await fetch('/api/register/generate-options', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username }),
        });

        if (!resp.ok) {
            const error = await resp.json();
            throw new Error(error.error || 'Failed to get registration options');
        }

        const options = await resp.json();

        // 2. Start WebAuthn Registration (prompts user for fingerprint)
        let attResp;
        try {
            attResp = await startRegistration({ optionsJSON: options });
        } catch (error) {
            // User cancelled or error occurred in browser
            if (error.name === 'InvalidStateError') {
                throw new Error('Authenticator was probably already registered by user');
            }
            throw error;
        }

        // 3. Send registration response to server to verify
        const verificationResp = await fetch('/api/register/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username,
                response: attResp,
            }),
        });

        const verificationJSON = await verificationResp.json();

        if (verificationJSON && verificationJSON.verified) {
            showMessage(`Registration successful! You can now log in.`, false);
        } else {
            throw new Error(verificationJSON.error || 'Verification failed');
        }
    } catch (error) {
        console.error(error);
        showMessage(error.message, true);
    } finally {
        btnRegister.disabled = false;
        btnRegister.innerHTML = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="19" y1="8" x2="19" y2="14"/><line x1="22" y1="11" x2="16" y2="11"/></svg> Register Fingerprint';
    }
});

// LOGIN FLOW
btnLogin.addEventListener('click', async () => {
    const username = usernameInput.value.trim();
    if (!username) {
        showMessage('Please enter a username first', true);
        return;
    }

    btnLogin.disabled = true;
    btnLogin.innerHTML = 'Logging in...';
    hideMessage();

    try {
        // 1. Get authentication options from server
        const resp = await fetch('/api/login/generate-options', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username }),
        });

        if (!resp.ok) {
            const error = await resp.json();
            throw new Error(error.error || 'Failed to get login options');
        }

        const options = await resp.json();

        // 2. Start WebAuthn Authentication (prompts user for fingerprint)
        let asseResp;
        try {
            asseResp = await startAuthentication({ optionsJSON: options });
        } catch (error) {
            throw error;
        }

        // 3. Send authentication response to server to verify
        const verificationResp = await fetch('/api/login/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username,
                response: asseResp,
            }),
        });

        const verificationJSON = await verificationResp.json();

        if (verificationJSON && verificationJSON.verified) {
            showProfile(verificationJSON.username);
        } else {
            throw new Error(verificationJSON.error || 'Login verification failed');
        }
    } catch (error) {
        console.error(error);
        showMessage(error.message, true);
    } finally {
        btnLogin.disabled = false;
        btnLogin.innerHTML = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg> Login';
    }
});

// Logout
btnLogout.addEventListener('click', () => {
    showAuth();
});

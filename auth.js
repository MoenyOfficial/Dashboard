/**
 * Sacred Studios Discord Bot Dashboard
 * Authentication System
 */

class AuthManager {
    constructor() {
        // Configuration
        this.clientId = '1350043733760147548'; // Your Discord application client ID
        
        // Set explicit GitHub Pages redirect URL instead of dynamic one
        // Important: This must match exactly what you register in Discord Developer Portal
        this.redirectUri = encodeURIComponent('https://moenyofficial.github.io/Dashboard/callback.html');
        this.scope = 'identify guilds';
        
        // Authorized user IDs (Discord user IDs that are allowed access)
        this.authorizedUsers = [
            '628236400361340959', // Your authorized Discord ID
            // Add more authorized users as needed
        ];
        
        // Authorized roles (Discord role IDs that are allowed access)
        this.authorizedRoles = [
            '345678901234567890', // Example: Admin role ID
            '456789012345678901', // Example: Moderator role ID
            // Add more authorized roles as needed
        ];
        
        // Initialize
        this.init();
    }
    
    init() {
        // Check if we're on the login page
        if (window.location.pathname.endsWith('login.html')) {
            this.setupLoginButton();
            this.checkLoginStatus();
        } 
        // If we're on the dashboard, verify authentication
        else if (!window.location.pathname.endsWith('callback.html')) {
            this.verifyAuth();
        }
        
        // Check for logout actions
        document.addEventListener('click', (e) => {
            if (e.target.id === 'logout-button' || e.target.closest('#logout-button')) {
                this.logout();
            }
        });
    }
    
    setupLoginButton() {
        const loginButton = document.getElementById('discord-login');
        if (loginButton) {
            loginButton.addEventListener('click', () => this.redirectToDiscordAuth());
        }
    }
    
    redirectToDiscordAuth() {
        const authUrl = `https://discord.com/api/oauth2/authorize?client_id=${this.clientId}&redirect_uri=${this.redirectUri}&response_type=token&scope=${this.scope}`;
        window.location.href = authUrl;
    }
    
    checkLoginStatus() {
        const token = this.getToken();
        const statusElement = document.getElementById('login-status');
        
        if (token) {
            statusElement.classList.remove('hidden');
            statusElement.classList.add('bg-discord-green', 'bg-opacity-20');
            statusElement.innerHTML = '<p><i class="fas fa-spinner fa-spin mr-2"></i> Already authenticated. Redirecting to dashboard...</p>';
            
            // Verify permissions and redirect to dashboard if authorized
            this.fetchUserData(token)
                .then(userData => {
                    if (this.isAuthorized(userData)) {
                        window.location.href = 'index.html';
                    } else {
                        this.showUnauthorizedMessage(statusElement);
                        this.logout();
                    }
                })
                .catch(error => {
                    console.error('Authentication error:', error);
                    statusElement.classList.remove('bg-discord-green', 'bg-opacity-20');
                    statusElement.classList.add('bg-discord-red', 'bg-opacity-20');
                    statusElement.innerHTML = '<p><i class="fas fa-exclamation-triangle mr-2"></i> Authentication failed. Please try again.</p>';
                });
        }
    }
    
    verifyAuth() {
        const token = this.getToken();
        
        if (!token) {
            this.redirectToLogin();
            return;
        }
        
        this.fetchUserData(token)
            .then(userData => {
                if (!this.isAuthorized(userData)) {
                    this.redirectToLogin();
                } else {
                    // User is authorized, update UI
                    this.updateUserInterface(userData);
                }
            })
            .catch(error => {
                console.error('Authentication verification error:', error);
                this.redirectToLogin();
            });
    }
    
    fetchUserData(token) {
        return Promise.all([
            fetch('https://discord.com/api/users/@me', {
                headers: { Authorization: `Bearer ${token}` }
            }),
            fetch('https://discord.com/api/users/@me/guilds', {
                headers: { Authorization: `Bearer ${token}` }
            })
        ])
        .then(([userResponse, guildsResponse]) => 
            Promise.all([userResponse.json(), guildsResponse.json()])
        )
        .then(([user, guilds]) => {
            return { user, guilds };
        });
    }
    
    isAuthorized({ user, guilds }) {
        // Check if user ID is in the authorized list
        if (this.authorizedUsers.includes(user.id)) {
            return true;
        }
        
        // Check if user has any of the authorized roles in any guild
        // Note: The API doesn't provide role info directly; you'd need a backend to check this
        // This is just a placeholder for the concept
        return false;
    }
    
    updateUserInterface(userData) {
        const user = userData.user;
        
        // Update user avatar and name in the navbar
        const userAvatar = document.querySelector('.user-avatar');
        const userName = document.querySelector('.user-name');
        
        if (userAvatar) {
            const avatarUrl = user.avatar 
                ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png`
                : `https://cdn.discordapp.com/embed/avatars/${parseInt(user.discriminator) % 5}.png`;
            userAvatar.src = avatarUrl;
        }
        
        if (userName) {
            userName.textContent = user.username;
        }
        
        // Store user data in session storage
        sessionStorage.setItem('discord_user', JSON.stringify(user));
    }
    
    showUnauthorizedMessage(element) {
        element.classList.remove('bg-discord-green', 'bg-opacity-20');
        element.classList.add('bg-discord-red', 'bg-opacity-20');
        element.innerHTML = '<p><i class="fas fa-ban mr-2"></i> You are not authorized to access this dashboard.</p>';
    }
    
    redirectToLogin() {
        window.location.href = 'login.html';
    }
    
    getToken() {
        // First check localStorage
        let token = localStorage.getItem('discord_token');
        
        // If no token in storage, check URL hash (for when returning from OAuth)
        if (!token && window.location.hash) {
            const fragment = new URLSearchParams(window.location.hash.slice(1));
            token = fragment.get('access_token');
            
            if (token) {
                const expiresIn = fragment.get('expires_in');
                this.saveToken(token, expiresIn);
            }
        }
        
        return token;
    }
    
    saveToken(token, expiresIn) {
        localStorage.setItem('discord_token', token);
        
        // Store expiration time
        const expirationTime = Date.now() + (parseInt(expiresIn) * 1000);
        localStorage.setItem('discord_token_expiration', expirationTime);
    }
    
    logout() {
        localStorage.removeItem('discord_token');
        localStorage.removeItem('discord_token_expiration');
        sessionStorage.removeItem('discord_user');
        window.location.href = 'login.html';
    }
}

// Initialize authentication
const auth = new AuthManager();
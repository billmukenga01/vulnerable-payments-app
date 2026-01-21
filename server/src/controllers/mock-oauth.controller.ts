import { Request, Response } from 'express';

/**
 * Mock OAuth Provider - Simulates Google/GitHub OAuth
 * This simulates the OAuth provider's authorization and token endpoints
 */

// Store authorization codes temporarily (in-memory for demo)
const authCodes: Map<string, any> = new Map();

/**
 * Mock Authorization Endpoint
 * Simulates Google/GitHub authorization page
 */
export const mockAuthorize = async (req: Request, res: Response) => {
    try {
        const { client_id, redirect_uri, state, response_type, scope } = req.query;
        const provider = req.params.provider;

        if (!redirect_uri) {
            return res.status(400).json({ message: 'redirect_uri required' });
        }

        // Generate mock authorization code
        const code = `MOCK_CODE_${provider}_${Date.now()}_${Math.random().toString(36).substring(7)}`;

        // Store code with associated data
        authCodes.set(code, {
            provider,
            email: `mockuser_${Date.now()}@example.com`,
            name: `Mock ${provider} User`,
            createdAt: Date.now()
        });

        // In a real OAuth flow, this would show a consent screen
        // For our mock, we'll return HTML that auto-redirects

        const redirectUrl = `${redirect_uri}?code=${code}&state=${state}&provider=${provider}`;

        res.send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Mock ${provider.toUpperCase()} OAuth</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        max-width: 500px;
                        margin: 100px auto;
                        padding: 20px;
                        text-align: center;
                    }
                    .provider {
                        font-size: 24px;
                        font-weight: bold;
                        margin-bottom: 20px;
                        color: ${provider === 'google' ? '#4285f4' : '#333'};
                    }
                    .consent-box {
                        border: 1px solid #ddd;
                        padding: 20px;
                        border-radius: 8px;
                        background: #f9f9f9;
                        margin: 20px 0;
                    }
                    button {
                        background: ${provider === 'google' ? '#4285f4' : '#24292e'};
                        color: white;
                        border: none;
                        padding: 12px 24px;
                        font-size: 16px;
                        border-radius: 4px;
                        cursor: pointer;
                        margin: 10px;
                    }
                    button:hover {
                        opacity: 0.9;
                    }
                    .cancel {
                        background: #666;
                    }
                    .warning {
                        background: #fff3cd;
                        border: 1px solid #ffc107;
                        padding: 10px;
                        border-radius: 4px;
                        margin: 20px 0;
                        font-size: 12px;
                    }
                </style>
            </head>
            <body>
                <div class="provider">Mock ${provider.toUpperCase()} OAuth</div>
                
                <div class="consent-box">
                    <p><strong>Vulnerable Payments App</strong> wants to:</p>
                    <ul style="text-align: left; display: inline-block;">
                        <li>View your email address</li>
                        <li>View your basic profile info</li>
                    </ul>
                </div>

                <div class="warning">
                    ⚠️ <strong>Mock OAuth Provider</strong><br>
                    This is a simulated OAuth flow for testing vulnerabilities.
                </div>

                <button onclick="allow()">Allow</button>
                <button class="cancel" onclick="cancel()">Cancel</button>

                <script>
                    function allow() {
                        window.location.href = '${redirectUrl}';
                    }
                    function cancel() {
                        alert('OAuth cancelled');
                        window.close();
                    }
                    
                    // Auto-redirect after 3 seconds for convenience
                    setTimeout(() => {
                        document.body.innerHTML += '<p style="color: #666; margin-top: 20px;">Auto-redirecting in 3 seconds...</p>';
                        setTimeout(allow, 3000);
                    }, 1000);
                </script>
            </body>
            </html>
        `);

    } catch (error) {
        console.error('Mock authorize error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * Mock Token Endpoint
 * Exchanges authorization code for access token
 */
export const mockToken = async (req: Request, res: Response) => {
    try {
        const { code, client_id, client_secret, redirect_uri, grant_type } = req.body;
        const provider = req.params.provider;

        if (!code) {
            return res.status(400).json({ error: 'invalid_request', error_description: 'code required' });
        }

        // Retrieve stored auth code data
        const authData = authCodes.get(code);

        if (!authData) {
            return res.status(400).json({ error: 'invalid_grant', error_description: 'Invalid authorization code' });
        }

        // Check if code is expired (5 minutes)
        if (Date.now() - authData.createdAt > 5 * 60 * 1000) {
            authCodes.delete(code);
            return res.status(400).json({ error: 'invalid_grant', error_description: 'Authorization code expired' });
        }

        // Delete code (one-time use)
        authCodes.delete(code);

        // Generate mock tokens
        const accessToken = `MOCK_ACCESS_TOKEN_${provider}_${Date.now()}`;
        const idToken = `MOCK_ID_TOKEN_${provider}_${Date.now()}`;

        res.json({
            access_token: accessToken,
            token_type: 'Bearer',
            expires_in: 3600,
            id_token: idToken,
            scope: 'email profile',
            // Include user data (in real OAuth, this would be in id_token JWT)
            user_data: {
                email: authData.email,
                name: authData.name,
                provider: authData.provider
            }
        });

    } catch (error) {
        console.error('Mock token error:', error);
        res.status(500).json({ error: 'server_error' });
    }
};

/**
 * Mock UserInfo Endpoint
 * Returns user information for given access token
 */
export const mockUserInfo = async (req: Request, res: Response) => {
    try {
        const authHeader = req.headers.authorization;
        const provider = req.params.provider;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'invalid_token' });
        }

        const accessToken = authHeader.substring(7);

        // In a real implementation, we'd validate the token
        // For mock, we'll extract info from the token string
        res.json({
            sub: `${provider}_user_${Date.now()}`,
            email: `mockuser@example.com`,
            email_verified: true,
            name: `Mock ${provider} User`,
            picture: `https://via.placeholder.com/150?text=${provider}`,
            provider
        });

    } catch (error) {
        console.error('Mock userinfo error:', error);
        res.status(500).json({ error: 'server_error' });
    }
};

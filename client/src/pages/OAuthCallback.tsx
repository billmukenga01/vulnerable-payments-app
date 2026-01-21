import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/Card';
import api from '../lib/api';

export default function OAuthCallback() {
    const [searchParams] = useSearchParams();
    const [error, setError] = useState('');
    const [vulnerabilities, setVulnerabilities] = useState<string[]>([]);
    const [loading, setLoading] = useState(true);
    const navigate = useNavigate();

    useEffect(() => {
        const handleCallback = async () => {
            try {
                const code = searchParams.get('code');
                const state = searchParams.get('state');
                const provider = searchParams.get('provider');

                if (!code) {
                    setError('No authorization code received');
                    setLoading(false);
                    return;
                }

                // Exchange code for token
                const res = await api.get('/oauth/callback', {
                    params: { code, state, provider }
                });

                if (res.data.success) {
                    // Store token and user
                    localStorage.setItem('token', res.data.token);
                    localStorage.setItem('user', JSON.stringify(res.data.user));

                    // Show vulnerabilities
                    if (res.data.vulnerabilities) {
                        setVulnerabilities(res.data.vulnerabilities);
                        setTimeout(() => navigate('/dashboard'), 3000);
                    } else {
                        navigate('/dashboard');
                    }
                } else {
                    setError('OAuth authentication failed');
                }

                setLoading(false);
            } catch (err: any) {
                console.error('OAuth callback error:', err);
                setError(err.response?.data?.message || 'OAuth authentication failed');
                setLoading(false);
            }
        };

        handleCallback();
    }, [searchParams, navigate]);

    return (
        <div className="min-h-screen flex items-center justify-center bg-background p-4">
            <Card className="w-full max-w-md">
                <CardHeader>
                    <CardTitle>OAuth Authentication</CardTitle>
                    <CardDescription>
                        {loading ? 'Processing OAuth callback...' : 'Authentication complete'}
                    </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                    {loading && (
                        <div className="flex items-center justify-center py-8">
                            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
                        </div>
                    )}

                    {error && (
                        <div className="text-red-500 text-sm bg-red-50 p-3 rounded-md">
                            {error}
                        </div>
                    )}

                    {vulnerabilities.length > 0 && (
                        <div className="bg-red-50 border border-red-200 rounded-lg p-3 space-y-2">
                            <h4 className="text-sm font-semibold text-red-900 flex items-center gap-2">
                                <span>🔓</span> OAuth Vulnerabilities Detected:
                            </h4>
                            <ul className="text-xs text-red-800 space-y-1">
                                {vulnerabilities.map((vuln, idx) => (
                                    <li key={idx} className="flex items-start gap-2">
                                        <span className="text-red-500">•</span>
                                        <span>{vuln}</span>
                                    </li>
                                ))}
                            </ul>
                            <p className="text-xs text-red-700 mt-2">
                                Redirecting to dashboard in 3 seconds...
                            </p>
                        </div>
                    )}
                </CardContent>
            </Card>
        </div>
    );
}

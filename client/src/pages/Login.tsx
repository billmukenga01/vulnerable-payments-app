import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';
import { Label } from '../components/ui/Label';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '../components/ui/Card';
import api from '../lib/api';

export default function Login() {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [otp, setOtp] = useState('');
    const [generatedOtp, setGeneratedOtp] = useState('');
    const [requiresOTP, setRequiresOTP] = useState(false);
    const [error, setError] = useState('');
    const [vulnerabilities, setVulnerabilities] = useState<string[]>([]);
    const navigate = useNavigate();

    const handlePasswordLogin = async () => {
        try {
            setError('');
            const res = await api.post('/auth/login', { email, password });

            // Check if 2FA/OTP is required
            if (res.data.requiresOTP) {
                // Password verified, now need OTP
                setGeneratedOtp(res.data.otp);
                setRequiresOTP(true);
                setVulnerabilities(res.data.vulnerabilities || []);
            } else {
                // Old flow - direct login (shouldn't happen with new implementation)
                localStorage.setItem('token', res.data.token);
                localStorage.setItem('user', JSON.stringify(res.data.user));
                navigate('/dashboard');
            }
        } catch (err: any) {
            setError(err.response?.data?.message || 'Login failed');
        }
    };

    const handleVerifyOTP = async () => {
        try {
            setError('');
            const res = await api.post('/auth/verify-otp', { email, otp });
            localStorage.setItem('token', res.data.token);
            localStorage.setItem('user', JSON.stringify(res.data.user));

            // Show vulnerabilities before navigating
            if (res.data.vulnerabilities) {
                setVulnerabilities(res.data.vulnerabilities);
                setTimeout(() => navigate('/dashboard'), 2000);
            } else {
                navigate('/dashboard');
            }
        } catch (err: any) {
            setError(err.response?.data?.message || 'OTP verification failed');
        }
    };

    const handleOAuthLogin = async (provider: 'google' | 'github') => {
        try {
            setError('');
            // Get OAuth authorization URL from backend
            const res = await api.get(`/oauth/initiate/${provider}`, {
                params: {
                    redirect_uri: `${window.location.origin}/oauth/callback`
                }
            });

            // Show vulnerabilities
            if (res.data.vulnerabilities) {
                setVulnerabilities(res.data.vulnerabilities);
            }

            // Redirect to OAuth authorization URL (mock provider)
            window.location.href = res.data.authUrl;
        } catch (err: any) {
            setError(err.response?.data?.message || 'OAuth initiation failed');
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-background p-4">
            <Card className="w-full max-w-md">
                <CardHeader>
                    <CardTitle>Login</CardTitle>
                    <CardDescription>
                        {!requiresOTP
                            ? 'Enter your credentials to access your account'
                            : 'Enter the OTP sent to verify your identity'}
                    </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                    {error && <div className="text-red-500 text-sm bg-red-50 p-3 rounded-md">{error}</div>}

                    {/* Step 1: Email and Password */}
                    {!requiresOTP && (
                        <>
                            <div className="space-y-2">
                                <Label htmlFor="email">Email</Label>
                                <Input
                                    id="email"
                                    type="email"
                                    placeholder="m@example.com"
                                    value={email}
                                    onChange={(e) => setEmail(e.target.value)}
                                />
                            </div>
                            <div className="space-y-2">
                                <Label htmlFor="password">Password</Label>
                                <Input
                                    id="password"
                                    type="password"
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                />
                                <div className="text-right">
                                    <Link to="/forgot-password" className="text-xs text-primary hover:underline">
                                        Forgot password?
                                    </Link>
                                </div>
                            </div>
                        </>
                    )}

                    {/* Step 2: OTP Verification */}
                    {requiresOTP && generatedOtp && (
                        <>
                            {/* VULNERABILITY SHOWCASE: Displaying OTP */}
                            <div className="bg-yellow-50 border-2 border-yellow-400 rounded-lg p-4 space-y-2">
                                <div className="flex items-center gap-2">
                                    <span className="text-2xl">⚠️</span>
                                    <h3 className="font-bold text-yellow-900">Mock Email/SMS Display</h3>
                                </div>
                                <p className="text-sm text-yellow-800">
                                    In a real application, this OTP would be sent to your email or phone.
                                    For testing purposes, it's displayed here:
                                </p>
                                <div className="bg-white p-3 rounded border border-yellow-300">
                                    <p className="text-xs text-gray-600 mb-1">Your OTP Code:</p>
                                    <p className="text-3xl font-mono font-bold text-center tracking-widest">
                                        {generatedOtp}
                                    </p>
                                </div>
                                <p className="text-xs text-yellow-700 italic">
                                    🔓 Vulnerability: OTP exposed in API response
                                </p>
                            </div>

                            <div className="space-y-2">
                                <Label htmlFor="otp-input">Enter OTP</Label>
                                <Input
                                    id="otp-input"
                                    type="text"
                                    placeholder="Enter 4-digit OTP"
                                    value={otp}
                                    onChange={(e) => setOtp(e.target.value)}
                                    maxLength={4}
                                    className="text-center text-2xl tracking-widest font-mono"
                                />
                            </div>

                            <Button className="w-full" onClick={handleVerifyOTP}>
                                Verify OTP & Login
                            </Button>

                            <button
                                onClick={() => {
                                    setRequiresOTP(false);
                                    setGeneratedOtp('');
                                    setOtp('');
                                    setPassword('');
                                }}
                                className="text-sm text-muted-foreground hover:underline w-full"
                            >
                                ← Back to login
                            </button>
                        </>
                    )}

                    {/* Vulnerabilities List */}
                    {vulnerabilities.length > 0 && (
                        <div className="bg-red-50 border border-red-200 rounded-lg p-3 space-y-2">
                            <h4 className="text-sm font-semibold text-red-900 flex items-center gap-2">
                                <span>🔓</span> Active Vulnerabilities:
                            </h4>
                            <ul className="text-xs text-red-800 space-y-1">
                                {vulnerabilities.map((vuln, idx) => (
                                    <li key={idx} className="flex items-start gap-2">
                                        <span className="text-red-500">•</span>
                                        <span>{vuln}</span>
                                    </li>
                                ))}
                            </ul>
                        </div>
                    )}
                </CardContent>
                <CardFooter className="flex flex-col space-y-2">
                    {!requiresOTP && (
                        <Button className="w-full" onClick={handlePasswordLogin}>Login</Button>
                    )}

                    {/* OAuth Login Buttons */}
                    {!requiresOTP && (
                        <>
                            <div className="relative w-full">
                                <div className="absolute inset-0 flex items-center">
                                    <span className="w-full border-t" />
                                </div>
                                <div className="relative flex justify-center text-xs uppercase">
                                    <span className="bg-background px-2 text-muted-foreground">
                                        Or continue with
                                    </span>
                                </div>
                            </div>

                            <div className="grid grid-cols-2 gap-2 w-full">
                                <Button
                                    variant="outline"
                                    onClick={() => handleOAuthLogin('google')}
                                    className="w-full"
                                >
                                    <svg className="mr-2 h-4 w-4" viewBox="0 0 24 24">
                                        <path
                                            fill="currentColor"
                                            d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                                        />
                                        <path
                                            fill="currentColor"
                                            d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                                        />
                                        <path
                                            fill="currentColor"
                                            d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
                                        />
                                        <path
                                            fill="currentColor"
                                            d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
                                        />
                                    </svg>
                                    Google
                                </Button>

                                <Button
                                    variant="outline"
                                    onClick={() => handleOAuthLogin('github')}
                                    className="w-full"
                                >
                                    <svg className="mr-2 h-4 w-4" fill="currentColor" viewBox="0 0 24 24">
                                        <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
                                    </svg>
                                    GitHub
                                </Button>
                            </div>
                        </>
                    )}

                    <div className="text-sm text-center text-muted-foreground">
                        Don't have an account? <Link to="/register" className="text-primary hover:underline">Register</Link>
                    </div>
                    <div className="mt-4 pt-4 border-t w-full text-xs text-center text-muted-foreground font-mono">
                        API: {api.defaults.baseURL}
                    </div>
                </CardFooter>
            </Card>
        </div>
    );
}

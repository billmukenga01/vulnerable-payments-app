import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';
import { Label } from '../components/ui/Label';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '../components/ui/Card';
import api from '../lib/api';

export default function ForgotPassword() {
    const [email, setEmail] = useState('');
    const [otp, setOtp] = useState('');
    const [message, setMessage] = useState('');
    const [error, setError] = useState('');
    const navigate = useNavigate();

    const handleForgot = async () => {
        try {
            setError('');
            setMessage('');
            const res = await api.post('/auth/forgot-password', { email });
            setMessage(res.data.message);
            // Vulnerable: Displaying the Leaked OTP
            if (res.data.otp) {
                setOtp(res.data.otp);
            }
        } catch (err: any) {
            setError(err.response?.data?.message || 'Request failed');
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-background p-4">
            <Card className="w-full max-w-md">
                <CardHeader>
                    <CardTitle>Forgot Password</CardTitle>
                    <CardDescription>Enter your email to receive an OTP</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                    {error && <div className="text-red-500 text-sm">{error}</div>}
                    {message && <div className="text-green-500 text-sm">{message}</div>}

                    {otp && (
                        <div className="p-4 bg-yellow-100 dark:bg-yellow-900 border border-yellow-500 rounded text-center">
                            <p className="text-sm font-bold text-yellow-800 dark:text-yellow-100">
                                🚧 DEV MODE: OTP INTERCEPTED 🚧
                            </p>
                            <p className="text-2xl font-mono tracking-widest mt-2">{otp}</p>
                            <Button
                                variant="link"
                                className="mt-2"
                                onClick={() => navigate(`/reset-password?email=${email}&otp=${otp}`)}
                            >
                                Proceed to Reset &rarr;
                            </Button>
                        </div>
                    )}

                    {!otp && (
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
                    )}
                </CardContent>
                <CardFooter className="flex flex-col space-y-2">
                    {!otp && <Button className="w-full" onClick={handleForgot}>Send OTP</Button>}
                    <div className="text-sm text-center text-muted-foreground">
                        Remembered? <Link to="/login" className="text-primary hover:underline">Back to Login</Link>
                    </div>
                </CardFooter>
            </Card>
        </div>
    );
}

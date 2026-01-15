import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';
import { Label } from '../components/ui/Label';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '../components/ui/Card';
import api from '../lib/api';

export default function SendMoney() {
    const [email, setEmail] = useState('');
    const [amount, setAmount] = useState('');
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');
    const navigate = useNavigate();

    const handleSend = async () => {
        setError('');
        setSuccess('');
        try {
            await api.post('/transactions/send', { receiverEmail: email, amount: parseFloat(amount) });
            setSuccess('Money sent successfully!');
            setTimeout(() => navigate('/dashboard'), 1500);
        } catch (err: any) {
            setError(err.response?.data?.message || 'Transaction failed');
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-background p-4">
            <Card className="w-full max-w-md">
                <CardHeader>
                    <CardTitle>Send Money</CardTitle>
                    <CardDescription>Transfer funds to another user</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                    {error && <div className="text-red-500 text-sm">{error}</div>}
                    {success && <div className="text-green-500 text-sm">{success}</div>}
                    <div className="space-y-2">
                        <Label htmlFor="email">Receiver Email</Label>
                        <Input
                            id="email"
                            type="email"
                            placeholder="friend@example.com"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                        />
                    </div>
                    <div className="space-y-2">
                        <Label htmlFor="amount">Amount</Label>
                        <Input
                            id="amount"
                            type="number"
                            placeholder="0.00"
                            value={amount}
                            onChange={(e) => setAmount(e.target.value)}
                        />
                    </div>
                </CardContent>
                <CardFooter className="flex justify-between">
                    <Button variant="outline" onClick={() => navigate('/dashboard')}>Cancel</Button>
                    <Button onClick={handleSend}>Send</Button>
                </CardFooter>
            </Card>
        </div>
    );
}

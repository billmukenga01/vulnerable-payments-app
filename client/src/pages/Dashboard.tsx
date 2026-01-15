import { useEffect, useState } from 'react';
import { Button } from '../components/ui/Button';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/Card';
import api from '../lib/api';
import { useNavigate } from 'react-router-dom';

export default function Dashboard() {
    const [balance, setBalance] = useState<number | null>(null);
    const [history, setHistory] = useState<any[]>([]);
    const navigate = useNavigate();
    const user = JSON.parse(localStorage.getItem('user') || '{}');

    useEffect(() => {
        const fetchData = async () => {
            try {
                const balanceRes = await api.get(`/users/${user.id}/balance`);
                setBalance(balanceRes.data.balance);

                const historyRes = await api.get('/transactions/history');
                setHistory(historyRes.data);
            } catch (error) {
                console.error('Failed to fetch data', error);
            }
        };

        if (user.id) {
            fetchData();
        } else {
            navigate('/login');
        }
    }, [user.id, navigate]);

    return (
        <div className="p-8 space-y-8 min-h-screen bg-background text-foreground">
            <div className="flex justify-between items-center">
                <h2 className="text-3xl font-bold tracking-tight">Dashboard</h2>
                <div className="flex items-center space-x-2">
                    <Button onClick={() => navigate('/send')}>Send Money</Button>
                    <Button variant="outline" onClick={() => {
                        localStorage.removeItem('token');
                        localStorage.removeItem('user');
                        navigate('/login');
                    }}>Logout</Button>
                </div>
            </div>
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Total Balance</CardTitle>
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">
                            {balance !== null ? `$${balance.toFixed(2)}` : 'Loading...'}
                        </div>
                        <p className="text-xs text-muted-foreground">Available funds</p>
                    </CardContent>
                </Card>
            </div>

            <div className="grid gap-4 md:grid-cols-1">
                <Card>
                    <CardHeader>
                        <CardTitle>Recent Transactions</CardTitle>
                    </CardHeader>
                    <CardContent>
                        <div className="space-y-4">
                            {history.length === 0 ? (
                                <p className="text-muted-foreground">No transactions yet.</p>
                            ) : (
                                history.map((tx) => (
                                    <div key={tx.id} className="flex items-center justify-between border-b pb-2 last:border-0">
                                        <div>
                                            <p className="font-medium">
                                                {tx.senderId === user.id ? `Sent to ${tx.receiver.name}` : `Received from ${tx.sender.name}`}
                                            </p>
                                            <p className="text-xs text-muted-foreground">{new Date(tx.createdAt).toLocaleDateString()}</p>
                                        </div>
                                        <div className={`font-bold ${tx.senderId === user.id ? 'text-red-500' : 'text-green-500'}`}>
                                            {tx.senderId === user.id ? '-' : '+'}${tx.amount.toFixed(2)}
                                        </div>
                                    </div>
                                ))
                            )}
                        </div>
                    </CardContent>
                </Card>
            </div>
        </div>
    );
}

import React, { useState } from 'react';
import VulnerabilityTestCard from '../components/VulnerabilityTestCard';
import VulnerabilityNav from '../components/VulnerabilityNav';
import axios from 'axios';
import '../styles/vulnerability-tests.css';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000';

const PasswordResetFlaws: React.FC = () => {
    const [results, setResults] = useState<{ [key: string]: any }>({});
    const [loading, setLoading] = useState<{ [key: string]: boolean }>({});

    const handleTest = async (testName: string, endpoint: string, data: any) => {
        setLoading({ ...loading, [testName]: true });
        try {
            const response = await axios.post(`${API_URL}${endpoint}`, data, {
                withCredentials: true
            });
            setResults({ ...results, [testName]: response.data });
        } catch (error: any) {
            setResults({ ...results, [testName]: { error: error.response?.data || error.message } });
        } finally {
            setLoading({ ...loading, [testName]: false });
        }
    };

    return (
        <div className="page-container">
            <VulnerabilityNav />
            <h1>Password Reset Vulnerabilities</h1>
            <p className="page-description">
                Test 4 password reset vulnerabilities based on HackerOne reports and OWASP research.
            </p>

            {/* Test 1: Multiple Valid Tokens */}
            <VulnerabilityTestCard
                title="1. Multiple Valid Reset Tokens"
                description="Multiple password reset tokens remain valid simultaneously. Old tokens not invalidated when new ones are generated."
                severity="Critical"
                source="HackerOne Password Reset Reports"
            >
                <div className="test-form">
                    <h4>Request Multiple Tokens</h4>
                    <form onSubmit={(e) => {
                        e.preventDefault();
                        const formData = new FormData(e.currentTarget);
                        handleTest('multiToken', '/api/additional-auth/request-password-reset-multiple', {
                            email: formData.get('email')
                        });
                    }}>
                        <input type="email" name="email" placeholder="Email" required />
                        <button type="submit" disabled={loading['multiToken']}>
                            {loading['multiToken'] ? 'Requesting...' : 'Request Reset Token'}
                        </button>
                    </form>
                    <p className="hint">💡 Request multiple times - all tokens remain valid!</p>
                    {results['multiToken'] && (
                        <div className="result">
                            <pre>{JSON.stringify(results['multiToken'], null, 2)}</pre>
                        </div>
                    )}
                </div>
            </VulnerabilityTestCard>

            {/* Test 2: Race Condition */}
            <VulnerabilityTestCard
                title="2. Password Reset Race Condition"
                description="Concurrent password reset requests can be exploited due to lack of concurrency control"
                severity="High"
                source="HackerOne & Medium Reports"
            >
                <div className="test-form">
                    <form onSubmit={async (e) => {
                        e.preventDefault();
                        const formData = new FormData(e.currentTarget);
                        const email = formData.get('email');
                        const token = formData.get('token');

                        // Send 10 concurrent reset requests
                        const promises = Array(10).fill(null).map((_, i) =>
                            axios.post(`${API_URL}/api/additional-auth/reset-password-race-condition`, {
                                email,
                                token,
                                newPassword: `hacked${i}`
                            }, { withCredentials: true })
                        );

                        try {
                            const responses = await Promise.all(promises);
                            setResults({ ...results, 'resetRace': responses.map(r => r.data) });
                        } catch (error: any) {
                            setResults({ ...results, 'resetRace': { error: error.message } });
                        }
                    }}>
                        <input type="email" name="email" placeholder="Email" required />
                        <input type="text" name="token" placeholder="Reset Token" required />
                        <button type="submit">Send 10 Concurrent Resets</button>
                    </form>
                    <p className="hint">💡 Race condition allows multiple password changes!</p>
                    {results['resetRace'] && (
                        <div className="result">
                            <pre>{JSON.stringify(results['resetRace'], null, 2)}</pre>
                        </div>
                    )}
                </div>
            </VulnerabilityTestCard>

            {/* Test 3: 0-Click ATO */}
            <VulnerabilityTestCard
                title="3. 0-Click Account Takeover via Reset Flaw"
                description="Race condition in password reset sends token to both victim and attacker emails"
                severity="Critical"
                source="HackerOne #2024 Critical ATO Report"
            >
                <div className="test-form">
                    <form onSubmit={(e) => {
                        e.preventDefault();
                        const formData = new FormData(e.currentTarget);
                        handleTest('zeroClick', '/api/additional-auth/forgot-password-0click', {
                            email: formData.get('email'),
                            attackerEmail: formData.get('attackerEmail')
                        });
                    }}>
                        <input type="email" name="email" placeholder="Victim Email" required />
                        <input type="email" name="attackerEmail" placeholder="Attacker Email" required />
                        <button type="submit" disabled={loading['zeroClick']}>
                            {loading['zeroClick'] ? 'Exploiting...' : 'Exploit Race Condition'}
                        </button>
                    </form>
                    <p className="hint">💡 Token sent to both emails!</p>
                    {results['zeroClick'] && (
                        <div className="result">
                            <pre>{JSON.stringify(results['zeroClick'], null, 2)}</pre>
                        </div>
                    )}
                </div>
            </VulnerabilityTestCard>

            {/* Test 4: Token in URL */}
            <VulnerabilityTestCard
                title="4. Password Reset Token in URL (Referer Leakage)"
                description="Reset token in URL query parameters leaks via Referer header when user clicks external links"
                severity="High"
                source="OWASP Best Practices"
            >
                <div className="test-form">
                    <form onSubmit={(e) => {
                        e.preventDefault();
                        const formData = new FormData(e.currentTarget);
                        handleTest('urlToken', '/api/additional-auth/reset-password-url-token', {
                            email: formData.get('email')
                        });
                    }}>
                        <input type="email" name="email" placeholder="Email" required />
                        <button type="submit" disabled={loading['urlToken']}>
                            {loading['urlToken'] ? 'Generating...' : 'Generate Reset Link'}
                        </button>
                    </form>
                    <p className="hint">💡 Token in URL leaks via Referer header!</p>
                    {results['urlToken'] && (
                        <div className="result">
                            <pre>{JSON.stringify(results['urlToken'], null, 2)}</pre>
                            {results['urlToken'].resetLink && (
                                <div className="warning">
                                    <p><strong>⚠️ Vulnerable Reset Link:</strong></p>
                                    <code>{results['urlToken'].resetLink}</code>
                                    <p>If user clicks external links on this page, the token leaks via Referer header!</p>
                                </div>
                            )}
                        </div>
                    )}
                </div>
            </VulnerabilityTestCard>
        </div>
    );
};

export default PasswordResetFlaws;

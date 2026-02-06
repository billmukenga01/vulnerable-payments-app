import React, { useState } from 'react';
import VulnerabilityTestCard from '../components/VulnerabilityTestCard';
import VulnerabilityNav from '../components/VulnerabilityNav';
import axios from 'axios';
import '../styles/vulnerability-tests.css';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000';

const RateLimitingBypass: React.FC = () => {
    const [results, setResults] = useState<{ [key: string]: any }>({});
    const [loading, setLoading] = useState<{ [key: string]: boolean }>({});
    const [attemptCount, setAttemptCount] = useState<{ [key: string]: number }>({});

    const handleTest = async (testName: string, endpoint: string, data: any, headers: any = {}) => {
        setLoading({ ...loading, [testName]: true });
        try {
            const response = await axios.post(`${API_URL}${endpoint}`, data, {
                withCredentials: true,
                headers
            });
            setResults({ ...results, [testName]: response.data });
            setAttemptCount({ ...attemptCount, [testName]: (attemptCount[testName] || 0) + 1 });
        } catch (error: any) {
            setResults({ ...results, [testName]: { error: error.response?.data || error.message } });
            setAttemptCount({ ...attemptCount, [testName]: (attemptCount[testName] || 0) + 1 });
        } finally {
            setLoading({ ...loading, [testName]: false });
        }
    };

    return (
        <div className="page-container">
            <VulnerabilityNav />
            <h1>Rate Limiting Bypass Vulnerabilities</h1>
            <p className="page-description">
                Test 4 rate limiting bypass techniques based on security research and WAF bypass methods.
            </p>

            {/* Test 1: X-Forwarded-For Bypass */}
            <VulnerabilityTestCard
                title="1. Rate Limit Bypass via X-Forwarded-For Header"
                description="IP-based rate limiting trusts the X-Forwarded-For header without validation"
                severity="High"
                source="Security Research & HackerOne"
            >
                <div className="test-form">
                    <p><strong>Attempts:</strong> {attemptCount['xffBypass'] || 0}</p>
                    <form onSubmit={(e) => {
                        e.preventDefault();
                        const formData = new FormData(e.currentTarget);
                        const randomIP = `192.168.1.${Math.floor(Math.random() * 255)}`;
                        handleTest('xffBypass', '/api/additional-auth/login-rate-limit-xff', {
                            email: formData.get('email'),
                            password: formData.get('password')
                        }, {
                            'X-Forwarded-For': randomIP
                        });
                    }}>
                        <input type="email" name="email" placeholder="Email" required />
                        <input type="password" name="password" placeholder="Password" required />
                        <button type="submit" disabled={loading['xffBypass']}>
                            {loading['xffBypass'] ? 'Testing...' : 'Test Login (Random X-Forwarded-For)'}
                        </button>
                    </form>
                    <p className="hint">💡 Each request uses different X-Forwarded-For IP!</p>
                    {results['xffBypass'] && (
                        <div className="result">
                            <pre>{JSON.stringify(results['xffBypass'], null, 2)}</pre>
                        </div>
                    )}
                </div>
            </VulnerabilityTestCard>

            {/* Test 2: User-Agent Rotation */}
            <VulnerabilityTestCard
                title="2. Rate Limit Bypass via User-Agent Rotation"
                description="Rate limiting includes User-Agent header in the rate limit key"
                severity="Medium"
                source="Security Research"
            >
                <div className="test-form">
                    <p><strong>Attempts:</strong> {attemptCount['uaBypass'] || 0}</p>
                    <form onSubmit={(e) => {
                        e.preventDefault();
                        const formData = new FormData(e.currentTarget);
                        const userAgents = [
                            'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
                            'Mozilla/5.0 (X11; Linux x86_64)',
                            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)'
                        ];
                        const randomUA = userAgents[Math.floor(Math.random() * userAgents.length)] + `-${Date.now()}`;

                        handleTest('uaBypass', '/api/additional-auth/login-rate-limit-ua', {
                            email: formData.get('email'),
                            password: formData.get('password')
                        }, {
                            'User-Agent': randomUA
                        });
                    }}>
                        <input type="email" name="email" placeholder="Email" required />
                        <input type="password" name="password" placeholder="Password" required />
                        <button type="submit" disabled={loading['uaBypass']}>
                            {loading['uaBypass'] ? 'Testing...' : 'Test Login (Random User-Agent)'}
                        </button>
                    </form>
                    <p className="hint">💡 Each request uses different User-Agent!</p>
                    {results['uaBypass'] && (
                        <div className="result">
                            <pre>{JSON.stringify(results['uaBypass'], null, 2)}</pre>
                        </div>
                    )}
                </div>
            </VulnerabilityTestCard>

            {/* Test 3: Parameter Pollution */}
            <VulnerabilityTestCard
                title="3. Rate Limit Bypass via Parameter Pollution"
                description="Rate limiting uses full URL including query parameters, making each URL unique"
                severity="Medium"
                source="Security Research"
            >
                <div className="test-form">
                    <p><strong>Attempts:</strong> {attemptCount['paramBypass'] || 0}</p>
                    <form onSubmit={async (e) => {
                        e.preventDefault();
                        const formData = new FormData(e.currentTarget);
                        const randomParam = Math.random().toString(36).substring(7);

                        setLoading({ ...loading, 'paramBypass': true });
                        try {
                            const response = await axios.post(
                                `${API_URL}/api/additional-auth/login-rate-limit-params?rand=${randomParam}&cache=${Date.now()}`,
                                {
                                    email: formData.get('email'),
                                    password: formData.get('password')
                                },
                                { withCredentials: true }
                            );
                            setResults({ ...results, 'paramBypass': response.data });
                            setAttemptCount({ ...attemptCount, 'paramBypass': (attemptCount['paramBypass'] || 0) + 1 });
                        } catch (error: any) {
                            setResults({ ...results, 'paramBypass': { error: error.response?.data || error.message } });
                            setAttemptCount({ ...attemptCount, 'paramBypass': (attemptCount['paramBypass'] || 0) + 1 });
                        } finally {
                            setLoading({ ...loading, 'paramBypass': false });
                        }
                    }}>
                        <input type="email" name="email" placeholder="Email" required />
                        <input type="password" name="password" placeholder="Password" required />
                        <button type="submit" disabled={loading['paramBypass']}>
                            {loading['paramBypass'] ? 'Testing...' : 'Test Login (Random Parameters)'}
                        </button>
                    </form>
                    <p className="hint">💡 Each request has unique query parameters!</p>
                    {results['paramBypass'] && (
                        <div className="result">
                            <pre>{JSON.stringify(results['paramBypass'], null, 2)}</pre>
                        </div>
                    )}
                </div>
            </VulnerabilityTestCard>

            {/* Test 4: HTTP Method Switching */}
            <VulnerabilityTestCard
                title="4. Rate Limit Bypass via HTTP Method Switching"
                description="Rate limiting only applied to POST requests, not GET or other methods"
                severity="Medium"
                source="Security Research & WAF Bypass Techniques"
            >
                <div className="test-form">
                    <p><strong>POST Attempts:</strong> {attemptCount['methodPost'] || 0}</p>
                    <p><strong>GET Attempts:</strong> {attemptCount['methodGet'] || 0}</p>

                    <h4>Test with POST (Gets Rate Limited)</h4>
                    <form onSubmit={(e) => {
                        e.preventDefault();
                        const formData = new FormData(e.currentTarget);
                        handleTest('methodPost', '/api/additional-auth/login-rate-limit-method', {
                            email: formData.get('email'),
                            password: formData.get('password')
                        });
                    }}>
                        <input type="email" name="email" placeholder="Email" required />
                        <input type="password" name="password" placeholder="Password" required />
                        <button type="submit" disabled={loading['methodPost']}>
                            {loading['methodPost'] ? 'Testing...' : 'Test Login (POST)'}
                        </button>
                    </form>

                    <h4>Test with GET (Bypasses Rate Limit)</h4>
                    <form onSubmit={async (e) => {
                        e.preventDefault();
                        const formData = new FormData(e.currentTarget);
                        const email = formData.get('email');
                        const password = formData.get('password');

                        setLoading({ ...loading, 'methodGet': true });
                        try {
                            const response = await axios.get(
                                `${API_URL}/api/additional-auth/login-rate-limit-method?email=${email}&password=${password}`,
                                { withCredentials: true }
                            );
                            setResults({ ...results, 'methodGet': response.data });
                            setAttemptCount({ ...attemptCount, 'methodGet': (attemptCount['methodGet'] || 0) + 1 });
                        } catch (error: any) {
                            setResults({ ...results, 'methodGet': { error: error.response?.data || error.message } });
                            setAttemptCount({ ...attemptCount, 'methodGet': (attemptCount['methodGet'] || 0) + 1 });
                        } finally {
                            setLoading({ ...loading, 'methodGet': false });
                        }
                    }}>
                        <input type="email" name="email" placeholder="Email" required />
                        <input type="password" name="password" placeholder="Password" required />
                        <button type="submit" disabled={loading['methodGet']}>
                            {loading['methodGet'] ? 'Testing...' : 'Test Login (GET)'}
                        </button>
                    </form>

                    <p className="hint">💡 POST gets rate limited, GET doesn't!</p>
                    {results['methodPost'] && (
                        <div className="result">
                            <strong>POST Result:</strong>
                            <pre>{JSON.stringify(results['methodPost'], null, 2)}</pre>
                        </div>
                    )}
                    {results['methodGet'] && (
                        <div className="result">
                            <strong>GET Result:</strong>
                            <pre>{JSON.stringify(results['methodGet'], null, 2)}</pre>
                        </div>
                    )}
                </div>
            </VulnerabilityTestCard>
        </div>
    );
};

export default RateLimitingBypass;

import React, { useState } from 'react';
import VulnerabilityTestCard from '../components/VulnerabilityTestCard';
import VulnerabilityNav from '../components/VulnerabilityNav';
import axios from 'axios';
import '../styles/vulnerability-tests.css';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000';

const EmailVerificationBypass: React.FC = () => {
    const [results, setResults] = useState<{ [key: string]: any }>({});
    const [loading, setLoading] = useState<{ [key: string]: boolean }>({});

    const handleTest = async (testName: string, endpoint: string, data: any, method: string = 'POST') => {
        setLoading({ ...loading, [testName]: true });
        try {
            const response = method === 'GET'
                ? await axios.get(`${API_URL}${endpoint}`, { withCredentials: true })
                : await axios.post(`${API_URL}${endpoint}`, data, { withCredentials: true });
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
            <h1>Email Verification Bypass Vulnerabilities</h1>
            <p className="page-description">
                Test 4 email verification bypass techniques based on bug bounty reports.
            </p>

            {/* Test 1: Direct API Bypass */}
            <VulnerabilityTestCard
                title="1. Email Verification API Endpoint Bypass"
                description="Direct API endpoint access allows account activation without email verification token"
                severity="Critical"
                source="Medium Bug Bounty Reports"
            >
                <div className="test-form">
                    <form onSubmit={(e) => {
                        e.preventDefault();
                        const formData = new FormData(e.currentTarget);
                        handleTest('directActivation', '/api/additional-auth/activate-account-direct', {
                            email: formData.get('email')
                        });
                    }}>
                        <input type="email" name="email" placeholder="Email" required />
                        <button type="submit" disabled={loading['directActivation']}>
                            {loading['directActivation'] ? 'Activating...' : 'Activate Account (No Token)'}
                        </button>
                    </form>
                    <p className="hint">💡 No verification token required!</p>
                    {results['directActivation'] && (
                        <div className="result">
                            <pre>{JSON.stringify(results['directActivation'], null, 2)}</pre>
                        </div>
                    )}
                </div>
            </VulnerabilityTestCard>

            {/* Test 2: Email Change Without Verification */}
            <VulnerabilityTestCard
                title="2. Email Change Without Re-verification"
                description="Users can change their email address without verifying ownership of the new email"
                severity="High"
                source="HackerOne Reports"
            >
                <div className="test-form">
                    <form onSubmit={(e) => {
                        e.preventDefault();
                        const formData = new FormData(e.currentTarget);
                        handleTest('emailChange', '/api/additional-auth/change-email-no-verification', {
                            currentEmail: formData.get('currentEmail'),
                            newEmail: formData.get('newEmail')
                        });
                    }}>
                        <input type="email" name="currentEmail" placeholder="Current Email" required />
                        <input type="email" name="newEmail" placeholder="New Email" required />
                        <button type="submit" disabled={loading['emailChange']}>
                            {loading['emailChange'] ? 'Changing...' : 'Change Email (No Verification)'}
                        </button>
                    </form>
                    <p className="hint">💡 New email not verified!</p>
                    {results['emailChange'] && (
                        <div className="result">
                            <pre>{JSON.stringify(results['emailChange'], null, 2)}</pre>
                        </div>
                    )}
                </div>
            </VulnerabilityTestCard>

            {/* Test 3: Race Condition */}
            <VulnerabilityTestCard
                title="3. Email Verification Race Condition"
                description="Race condition allows same OTP to verify both attacker and victim email addresses"
                severity="High"
                source="HackerOne #2024 Email Verification Bypass"
            >
                <div className="test-form">
                    <h4>Step 1: Request Email Change</h4>
                    <form onSubmit={(e) => {
                        e.preventDefault();
                        const formData = new FormData(e.currentTarget);
                        handleTest('requestChange', '/api/additional-auth/request-email-change', {
                            email: formData.get('email'),
                            newEmail: formData.get('newEmail')
                        });
                    }}>
                        <input type="email" name="email" placeholder="Current Email" required />
                        <input type="email" name="newEmail" placeholder="New Email" required />
                        <button type="submit" disabled={loading['requestChange']}>
                            {loading['requestChange'] ? 'Requesting...' : 'Request Email Change'}
                        </button>
                    </form>

                    <h4>Step 2: Concurrent Verification (Race Condition)</h4>
                    <form onSubmit={async (e) => {
                        e.preventDefault();
                        const formData = new FormData(e.currentTarget);
                        const otp = formData.get('otp');
                        const email1 = formData.get('email1');
                        const email2 = formData.get('email2');

                        // Send concurrent requests
                        try {
                            const [response1, response2] = await Promise.all([
                                axios.post(`${API_URL}/api/additional-auth/verify-email-change`,
                                    { email: email1, otp },
                                    { withCredentials: true }
                                ),
                                axios.post(`${API_URL}/api/additional-auth/verify-email-change`,
                                    { email: email2, otp },
                                    { withCredentials: true }
                                )
                            ]);
                            setResults({ ...results, 'raceCondition': [response1.data, response2.data] });
                        } catch (error: any) {
                            setResults({ ...results, 'raceCondition': { error: error.message } });
                        }
                    }}>
                        <input type="text" name="otp" placeholder="OTP" required />
                        <input type="email" name="email1" placeholder="Email 1" required />
                        <input type="email" name="email2" placeholder="Email 2" required />
                        <button type="submit">Verify Both Emails (Concurrent)</button>
                    </form>

                    <p className="hint">💡 Same OTP verifies both emails!</p>
                    {results['requestChange'] && (
                        <div className="result">
                            <pre>{JSON.stringify(results['requestChange'], null, 2)}</pre>
                        </div>
                    )}
                    {results['raceCondition'] && (
                        <div className="result">
                            <pre>{JSON.stringify(results['raceCondition'], null, 2)}</pre>
                        </div>
                    )}
                </div>
            </VulnerabilityTestCard>

            {/* Test 4: Front-end Only Verification */}
            <VulnerabilityTestCard
                title="4. Front-end Only Email Verification"
                description="Email verification enforced client-side only, not validated server-side"
                severity="High"
                source="Medium Security Research"
            >
                <div className="test-form">
                    <p>This test requires a valid JWT token. First login, then test accessing protected resources without email verification.</p>
                    <button
                        onClick={() => handleTest('frontendOnly', '/api/additional-auth/access-without-email-verification', {}, 'GET')}
                        disabled={loading['frontendOnly']}
                    >
                        {loading['frontendOnly'] ? 'Accessing...' : 'Access Without Email Verification'}
                    </button>
                    <p className="hint">💡 Server doesn't check email verification status!</p>
                    {results['frontendOnly'] && (
                        <div className="result">
                            <pre>{JSON.stringify(results['frontendOnly'], null, 2)}</pre>
                        </div>
                    )}
                </div>
            </VulnerabilityTestCard>
        </div>
    );
};

export default EmailVerificationBypass;

import React, { useState } from 'react';
import VulnerabilityTestCard from '../components/VulnerabilityTestCard';
import VulnerabilityNav from '../components/VulnerabilityNav';
import axios from 'axios';
import '../styles/vulnerability-tests.css';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000';

const AdvancedOTPBypass: React.FC = () => {
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
            <h1>Advanced OTP/2FA Bypasses</h1>
            <p className="page-description">
                Test 8 advanced OTP and 2FA bypass vulnerabilities based on real HackerOne reports.
            </p>

            {/* Test 1: Account Deactivation Bypass */}
            <VulnerabilityTestCard
                title="1. Account Deactivation → Password Reset Bypass"
                description="Deactivating an account then resetting the password allows login without 2FA prompt"
                severity="Critical"
                source="HackerOne 2023-2024 Reports"
            >
                <div className="test-form">
                    <h4>Step 1: Deactivate Account</h4>
                    <form onSubmit={(e) => {
                        e.preventDefault();
                        const formData = new FormData(e.currentTarget);
                        handleTest('deactivate', '/api/additional-auth/deactivate-account', {
                            email: formData.get('email')
                        });
                    }}>
                        <input type="email" name="email" placeholder="Email" required />
                        <button type="submit" disabled={loading['deactivate']}>
                            {loading['deactivate'] ? 'Deactivating...' : 'Deactivate Account'}
                        </button>
                    </form>

                    <h4>Step 2: Login After Deactivation</h4>
                    <form onSubmit={(e) => {
                        e.preventDefault();
                        const formData = new FormData(e.currentTarget);
                        handleTest('loginDeactivated', '/api/additional-auth/login-after-deactivation', {
                            email: formData.get('email'),
                            password: formData.get('password')
                        });
                    }}>
                        <input type="email" name="email" placeholder="Email" required />
                        <input type="password" name="password" placeholder="Password" required />
                        <button type="submit" disabled={loading['loginDeactivated']}>
                            {loading['loginDeactivated'] ? 'Logging in...' : 'Login (Bypasses 2FA)'}
                        </button>
                    </form>

                    {results['deactivate'] && (
                        <div className="result">
                            <pre>{JSON.stringify(results['deactivate'], null, 2)}</pre>
                        </div>
                    )}
                    {results['loginDeactivated'] && (
                        <div className="result">
                            <pre>{JSON.stringify(results['loginDeactivated'], null, 2)}</pre>
                        </div>
                    )}
                </div>
            </VulnerabilityTestCard>

            {/* Test 2: Reusable OTP */}
            <VulnerabilityTestCard
                title="2. Reusable OTP (No Invalidation After Use)"
                description="OTPs remain valid after successful use, allowing replay attacks"
                severity="Critical"
                source="HackerOne #2024 Microsoft Authenticator Report"
            >
                <div className="test-form">
                    <form onSubmit={(e) => {
                        e.preventDefault();
                        const formData = new FormData(e.currentTarget);
                        handleTest('reusableOTP', '/api/additional-auth/verify-otp-reusable', {
                            email: formData.get('email'),
                            otp: formData.get('otp')
                        });
                    }}>
                        <input type="email" name="email" placeholder="Email" required />
                        <input type="text" name="otp" placeholder="OTP" required />
                        <button type="submit" disabled={loading['reusableOTP']}>
                            {loading['reusableOTP'] ? 'Verifying...' : 'Verify OTP'}
                        </button>
                    </form>
                    <p className="hint">💡 Try using the same OTP multiple times!</p>
                    {results['reusableOTP'] && (
                        <div className="result">
                            <pre>{JSON.stringify(results['reusableOTP'], null, 2)}</pre>
                        </div>
                    )}
                </div>
            </VulnerabilityTestCard>

            {/* Test 3: Early Session Cookie */}
            <VulnerabilityTestCard
                title="3. Email OTP Bypass via Early Session Cookie"
                description="Session cookie issued before OTP verification completes"
                severity="Critical"
                source="HackerOne #2024 Drugs.com Report"
            >
                <div className="test-form">
                    <form onSubmit={(e) => {
                        e.preventDefault();
                        const formData = new FormData(e.currentTarget);
                        handleTest('earlySession', '/api/additional-auth/login-early-session-cookie', {
                            email: formData.get('email'),
                            password: formData.get('password')
                        });
                    }}>
                        <input type="email" name="email" placeholder="Email" required />
                        <input type="password" name="password" placeholder="Password" required />
                        <button type="submit" disabled={loading['earlySession']}>
                            {loading['earlySession'] ? 'Logging in...' : 'Login (Gets Session Before OTP)'}
                        </button>
                    </form>
                    <p className="hint">💡 Check cookies - session issued before OTP verification!</p>
                    {results['earlySession'] && (
                        <div className="result">
                            <pre>{JSON.stringify(results['earlySession'], null, 2)}</pre>
                        </div>
                    )}
                </div>
            </VulnerabilityTestCard>

            {/* Test 4: MFA Cookie Deletion */}
            <VulnerabilityTestCard
                title="4. 2FA Bypass via Cookie Deletion"
                description="Deleting MFA cookie bypasses 2FA requirement"
                severity="Critical"
                source="HackerOne #2024 MFA Bypass Report"
            >
                <div className="test-form">
                    <h4>Step 1: Login with MFA Cookie</h4>
                    <form onSubmit={(e) => {
                        e.preventDefault();
                        const formData = new FormData(e.currentTarget);
                        handleTest('mfaCookie', '/api/additional-auth/login-mfa-cookie', {
                            email: formData.get('email'),
                            password: formData.get('password')
                        });
                    }}>
                        <input type="email" name="email" placeholder="Email" required />
                        <input type="password" name="password" placeholder="Password" required />
                        <button type="submit" disabled={loading['mfaCookie']}>
                            {loading['mfaCookie'] ? 'Logging in...' : 'Login (Sets MFA Cookie)'}
                        </button>
                    </form>

                    <h4>Step 2: Access Without MFA</h4>
                    <button
                        onClick={() => {
                            // Delete mfa_required cookie
                            document.cookie = 'mfa_required=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
                            handleTest('accessNoMFA', '/api/additional-auth/access-without-mfa', {});
                        }}
                        disabled={loading['accessNoMFA']}
                    >
                        {loading['accessNoMFA'] ? 'Accessing...' : 'Delete MFA Cookie & Access'}
                    </button>

                    <p className="hint">💡 Delete mfa_required cookie but keep sessionId!</p>
                    {results['mfaCookie'] && (
                        <div className="result">
                            <pre>{JSON.stringify(results['mfaCookie'], null, 2)}</pre>
                        </div>
                    )}
                    {results['accessNoMFA'] && (
                        <div className="result">
                            <pre>{JSON.stringify(results['accessNoMFA'], null, 2)}</pre>
                        </div>
                    )}
                </div>
            </VulnerabilityTestCard>

            {/* Test 5: Expired TOTP */}
            <VulnerabilityTestCard
                title="5. Expired TOTP Code Acceptance"
                description="TOTP codes accepted beyond valid time window (>1 minute)"
                severity="High"
                source="HackerOne #2024 hackerone.com Report"
            >
                <div className="test-form">
                    <form onSubmit={(e) => {
                        e.preventDefault();
                        const formData = new FormData(e.currentTarget);
                        const timestamp = Date.now() - (parseInt(formData.get('age') as string) * 1000);
                        handleTest('expiredTOTP', '/api/additional-auth/verify-totp-expired', {
                            email: formData.get('email'),
                            totp: formData.get('totp'),
                            timestamp
                        });
                    }}>
                        <input type="email" name="email" placeholder="Email" required />
                        <input type="text" name="totp" placeholder="TOTP Code" required />
                        <input type="number" name="age" placeholder="Age in seconds (e.g., 120)" required />
                        <button type="submit" disabled={loading['expiredTOTP']}>
                            {loading['expiredTOTP'] ? 'Verifying...' : 'Verify Expired TOTP'}
                        </button>
                    </form>
                    <p className="hint">💡 Try TOTP codes older than 60 seconds!</p>
                    {results['expiredTOTP'] && (
                        <div className="result">
                            <pre>{JSON.stringify(results['expiredTOTP'], null, 2)}</pre>
                        </div>
                    )}
                </div>
            </VulnerabilityTestCard>

            {/* Test 6: Phone Number Bypass */}
            <VulnerabilityTestCard
                title="6. Bypassing Phone Number OTP in Account Recovery"
                description="Can add phone number without SMS verification"
                severity="High"
                source="HackerOne #2024 Report"
            >
                <div className="test-form">
                    <form onSubmit={(e) => {
                        e.preventDefault();
                        const formData = new FormData(e.currentTarget);
                        handleTest('phoneBypass', '/api/additional-auth/add-recovery-phone', {
                            email: formData.get('email'),
                            phoneNumber: formData.get('phoneNumber')
                        });
                    }}>
                        <input type="email" name="email" placeholder="Email" required />
                        <input type="tel" name="phoneNumber" placeholder="Phone Number" required />
                        <button type="submit" disabled={loading['phoneBypass']}>
                            {loading['phoneBypass'] ? 'Adding...' : 'Add Recovery Phone (No SMS)'}
                        </button>
                    </form>
                    <p className="hint">💡 No SMS OTP verification required!</p>
                    {results['phoneBypass'] && (
                        <div className="result">
                            <pre>{JSON.stringify(results['phoneBypass'], null, 2)}</pre>
                        </div>
                    )}
                </div>
            </VulnerabilityTestCard>

            {/* Test 7: 2FA Race Condition */}
            <VulnerabilityTestCard
                title="7. 2FA Race Condition (Multiple Reset Requests)"
                description="Multiple 2FA reset requests remain active even if one is canceled"
                severity="High"
                source="HackerOne #2024 2FA Reset Report"
            >
                <div className="test-form">
                    <h4>Step 1: Request Multiple 2FA Resets</h4>
                    <form onSubmit={async (e) => {
                        e.preventDefault();
                        const formData = new FormData(e.currentTarget);
                        const email = formData.get('email');

                        // Send 5 concurrent requests
                        const promises = Array(5).fill(null).map(() =>
                            axios.post(`${API_URL}/api/additional-auth/request-2fa-reset`, { email }, { withCredentials: true })
                        );

                        try {
                            const responses = await Promise.all(promises);
                            setResults({ ...results, '2faRace': responses.map(r => r.data) });
                        } catch (error: any) {
                            setResults({ ...results, '2faRace': { error: error.message } });
                        }
                    }}>
                        <input type="email" name="email" placeholder="Email" required />
                        <button type="submit">Request 5 Concurrent 2FA Resets</button>
                    </form>

                    <h4>Step 2: Cancel One Request</h4>
                    <form onSubmit={(e) => {
                        e.preventDefault();
                        const formData = new FormData(e.currentTarget);
                        handleTest('2faCancel', '/api/additional-auth/cancel-2fa-reset', {
                            email: formData.get('email'),
                            resetToken: formData.get('token')
                        });
                    }}>
                        <input type="email" name="email" placeholder="Email" required />
                        <input type="text" name="token" placeholder="Token to Cancel" required />
                        <button type="submit" disabled={loading['2faCancel']}>
                            {loading['2faCancel'] ? 'Canceling...' : 'Cancel One Request'}
                        </button>
                    </form>

                    <p className="hint">💡 Other requests remain active!</p>
                    {results['2faRace'] && (
                        <div className="result">
                            <pre>{JSON.stringify(results['2faRace'], null, 2)}</pre>
                        </div>
                    )}
                    {results['2faCancel'] && (
                        <div className="result">
                            <pre>{JSON.stringify(results['2faCancel'], null, 2)}</pre>
                        </div>
                    )}
                </div>
            </VulnerabilityTestCard>

            {/* Test 8: Session Rotation */}
            <VulnerabilityTestCard
                title="8. OTP Brute Force via Session ID Rotation"
                description="Rate limiting tied to session ID; unlimited session creation bypasses rate limit"
                severity="Critical"
                source="Security Research - Session ID Manipulation"
            >
                <div className="test-form">
                    <h4>Step 1: Get New Session</h4>
                    <button
                        onClick={async () => {
                            try {
                                const response = await axios.get(`${API_URL}/api/additional-auth/new-session`, { withCredentials: true });
                                setResults({ ...results, 'newSession': response.data });
                            } catch (error: any) {
                                setResults({ ...results, 'newSession': { error: error.message } });
                            }
                        }}
                    >
                        Get New Session
                    </button>

                    <h4>Step 2: Try OTP with Session Limit</h4>
                    <form onSubmit={(e) => {
                        e.preventDefault();
                        const formData = new FormData(e.currentTarget);
                        handleTest('sessionOTP', '/api/additional-auth/verify-otp-session-limit', {
                            email: formData.get('email'),
                            otp: formData.get('otp')
                        });
                    }}>
                        <input type="email" name="email" placeholder="Email" required />
                        <input type="text" name="otp" placeholder="OTP" required />
                        <button type="submit" disabled={loading['sessionOTP']}>
                            {loading['sessionOTP'] ? 'Verifying...' : 'Verify OTP'}
                        </button>
                    </form>

                    <p className="hint">💡 Get new session every 5 attempts to bypass rate limit!</p>
                    {results['newSession'] && (
                        <div className="result">
                            <pre>{JSON.stringify(results['newSession'], null, 2)}</pre>
                        </div>
                    )}
                    {results['sessionOTP'] && (
                        <div className="result">
                            <pre>{JSON.stringify(results['sessionOTP'], null, 2)}</pre>
                        </div>
                    )}
                </div>
            </VulnerabilityTestCard>
        </div>
    );
};

export default AdvancedOTPBypass;

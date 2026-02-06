import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';
import SendMoney from './pages/SendMoney';
import ForgotPassword from './pages/ForgotPassword';
import ResetPassword from './pages/ResetPassword';
import OAuthCallback from './pages/OAuthCallback';
import AdvancedOTPBypass from './pages/AdvancedOTPBypass';
import EmailVerificationBypass from './pages/EmailVerificationBypass';
import PasswordResetFlaws from './pages/PasswordResetFlaws';
import RateLimitingBypass from './pages/RateLimitingBypass';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/forgot-password" element={<ForgotPassword />} />
        <Route path="/reset-password" element={<ResetPassword />} />
        <Route path="/oauth/callback" element={<OAuthCallback />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/send" element={<SendMoney />} />

        {/* Vulnerability Test Pages */}
        <Route path="/test/advanced-otp-bypass" element={<AdvancedOTPBypass />} />
        <Route path="/test/email-verification-bypass" element={<EmailVerificationBypass />} />
        <Route path="/test/password-reset-flaws" element={<PasswordResetFlaws />} />
        <Route path="/test/rate-limiting-bypass" element={<RateLimitingBypass />} />

        <Route path="/" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </Router>
  );
}

export default App;

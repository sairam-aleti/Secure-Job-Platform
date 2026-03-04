import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { authAPI } from '../services/api';
import VirtualKeyboard from '../components/VirtualKeyboard';
import './Auth.css';

function ForgotPassword() {
  const [step, setStep] = useState(1); // Step 1: Email, Step 2: OTP & New Password
  const [email, setEmail] = useState('');
  const [otpCode, setOtpCode] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  // --- STEP 1: REQUEST OTP ---
  const handleRequestOTP = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await authAPI.requestPasswordReset(email);
      setSuccess('If the email exists, a reset code has been sent. Check your inbox.');
      setStep(2); // Move to OTP entry
    } catch (err) {
      setError('Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  // --- STEP 2: VIRTUAL KEYBOARD LOGIC ---
  const handleOTPKeyPress = (key) => {
    if (otpCode.length < 6) {
      setOtpCode(prev => prev + key);
    }
  };

  const handleOTPBackspace = () => {
    setOtpCode(prev => prev.slice(0, -1));
  };

  const handleOTPClear = () => {
    setOtpCode('');
  };

  // --- STEP 3: SUBMIT NEW PASSWORD ---
  const handleResetSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    if (otpCode.length !== 6) {
      setError('Please enter a 6-digit OTP using the virtual keyboard.');
      setLoading(false);
      return;
    }

    try {
      await authAPI.confirmPasswordReset({
        email: email,
        otp_code: otpCode,
        new_password: newPassword
      });
      setSuccess('Password successfully reset! Redirecting to login...');
      setTimeout(() => navigate('/login'), 3000);
    } catch (err) {
      let errorMsg = 'Failed to reset password';
      if (err.response?.data?.detail) {
          errorMsg = Array.isArray(err.response.data.detail) 
            ? err.response.data.detail[0].msg 
            : err.response.data.detail;
      }
      setError(errorMsg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <nav className="auth-navbar">
        <a href="/" className="auth-navbar-brand">FortKnox</a>
        <div className="auth-navbar-right">
          <a href="/login" className="btn-nav-login">Login</a>
        </div>
      </nav>

      <section className="auth-hero" style={{ minHeight: 'auto', padding: '40px' }}>
        <div className="auth-hero-text" style={{ textAlign: 'center', margin: '0 auto' }}>
          <h2>Reset Password</h2>
          <p>Secure account recovery via Email OTP and Virtual Keyboard.</p>
        </div>
      </section>

      <section className="auth-form-section">
        <div className="auth-card">
          
          {/* STEP 1: ENTER EMAIL */}
          {step === 1 && (
            <form onSubmit={handleRequestOTP}>
              <div className="form-group">
                <label>Registered Email</label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  placeholder="you@example.com"
                />
              </div>

              {error && <div className="error-message">{error}</div>}
              {success && <div className="success-message">{success}</div>}

              <button type="submit" disabled={loading}>
                {loading ? 'Requesting...' : 'Send Reset Code'}
              </button>
            </form>
          )}

          {/* STEP 2: ENTER OTP AND NEW PASSWORD */}
          {step === 2 && (
            <form onSubmit={handleResetSubmit}>
              <div className="success-message" style={{ marginBottom: '20px' }}>
                {success}
              </div>

              <div className="form-group" style={{ textAlign: 'center' }}>
                <label>Secure OTP Entry</label>
                <div style={{ 
                  fontSize: '24px', letterSpacing: '8px', fontWeight: 'bold', 
                  color: '#1a1a2e', background: '#f3f4f6', padding: '10px', 
                  borderRadius: '8px', border: '1px solid #d1d5db', 
                  margin: '10px auto', width: 'fit-content', minWidth: '150px'
                }}>
                  {otpCode.padEnd(6, '*')}
                </div>
                
                {/* VIRTUAL KEYBOARD */}
                <VirtualKeyboard 
                  onKeyPress={handleOTPKeyPress}
                  onBackspace={handleOTPBackspace}
                  onClear={handleOTPClear}
                  disabled={loading}
                />
              </div>

              <div className="form-group">
                <label>New Password</label>
                <input
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  required
                  placeholder="Minimum 12 characters"
                />
              </div>

              {error && <div className="error-message">{error}</div>}

              <button type="submit" disabled={loading || otpCode.length !== 6}>
                {loading ? 'Resetting...' : 'Confirm Password Reset'}
              </button>
            </form>
          )}

          <p className="auth-link">
            Remember your password? <a href="/login">Sign in</a>
          </p>
        </div>
      </section>
    </>
  );
}

export default ForgotPassword;
import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { authAPI } from '../services/api';
import './Auth.css';

function VerifyOTP() {
  const [email, setEmail] = useState('');
  const [otpCode, setOtpCode] = useState('');
  const [devOtp, setDevOtp] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  
  // NEW: Ref to track if OTP has already been triggered in this session
  const otpSentRef = useRef(false);

  useEffect(() => {
    const pendingEmail = localStorage.getItem('pending_email');
    if (pendingEmail) {
      setEmail(pendingEmail);
      
      // SAFETY CHECK: Only trigger the automatic OTP send once
      if (!otpSentRef.current) {
        otpSentRef.current = true; 
        sendOTP(pendingEmail);
      }
    } else {
      navigate('/register');
    }
  }, [navigate]);

  const sendOTP = async (emailAddress) => {
    try {
      const response = await authAPI.sendOTP(emailAddress);
      // dev_otp will be null now that we use real email, but we keep the state for safety
      setDevOtp(response.data.dev_otp);
      setSuccess('OTP sent! Please check your email inbox.');
      setError('');
    } catch (err) {
      let errorMsg = 'Failed to send OTP';
      if (err.response?.data?.detail) {
          errorMsg = Array.isArray(err.response.data.detail) 
            ? err.response.data.detail[0].msg 
            : err.response.data.detail;
      }
      setError(errorMsg);
      setSuccess('');
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await authAPI.verifyOTP({ email, otp_code: otpCode });
      setSuccess('Email verified! Redirecting to login...');
      localStorage.removeItem('pending_email');
      setTimeout(() => navigate('/login'), 2000);
    } catch (err) {
      let errorMsg = 'Invalid OTP';
      if (err.response?.data?.detail) {
          errorMsg = Array.isArray(err.response.data.detail) 
            ? err.response.data.detail[0].msg 
            : err.response.data.detail;
      }
      setError(errorMsg);
      setLoading(false);
    }
  };

  return (
    <>
      <nav className="auth-navbar">
        <a href="/" className="auth-navbar-brand">FortKnox</a>
        <div className="auth-navbar-center">
          <a href="/">Home</a>
          <a href="/login">Find Jobs</a>
          <a href="/login">About Us</a>
        </div>
        <div className="auth-navbar-right">
          <a href="/login" className="btn-nav-login">Login</a>
          <a href="/register" className="btn-nav-register">Register</a>
        </div>
      </nav>

      <section className="auth-hero">
        <div className="auth-hero-text">
          <h1>Almost there</h1>
          <p>We've sent a verification code to your email. This step confirms your identity and keeps your account secure.</p>
        </div>
        <div className="auth-hero-visual">
          <div className="hero-placeholder">✉️</div>
        </div>
      </section>

      <section className="auth-form-section">
        <div className="auth-card">
          <h2>Verify your email</h2>
          <p className="otp-info">
            Enter the 6-digit code sent to <span className="otp-email">{email}</span>
          </p>

          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label>Verification Code</label>
              <input
                type="text"
                value={otpCode}
                onChange={(e) => setOtpCode(e.target.value)}
                required
                placeholder="Enter 6-digit code"
                maxLength="6"
              />
            </div>

            {error && <div className="error-message">{error}</div>}
            {success && <div className="success-message">{success}</div>}

            <button type="submit" disabled={loading}>
              {loading ? 'Verifying...' : 'Verify Code'}
            </button>
          </form>

          <p className="auth-link">
            <a href="#!" onClick={(e) => {
              e.preventDefault();
              sendOTP(email);
            }}>Resend Code</a>
          </p>
        </div>
      </section>

      <section className="auth-features-bar">
        <div className="auth-feature-item"><span className="auth-feature-icon">⏱️</span> Code expires in 10 min</div>
        <div className="auth-feature-item"><span className="auth-feature-icon">🔒</span> 5 attempts max</div>
        <div className="auth-feature-item"><span className="auth-feature-icon">🛡️</span> Rate-limited</div>
        <div className="auth-feature-item"><span className="auth-feature-icon">✉️</span> Email verified</div>
      </section>
    </>
  );
}

export default VerifyOTP;
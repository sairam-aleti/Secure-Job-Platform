import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { authAPI } from '../services/api';
import { motion } from 'framer-motion';
import './Auth.css';

function VerifyOTP() {
  const [email, setEmail] = useState('');
  const [otpCode, setOtpCode] = useState('');
  const [devOtp, setDevOtp] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  
  const otpSentRef = useRef(false);

  const sendOTP = useCallback(async (emailAddress) => {
    try {
      const response = await authAPI.sendOTP(emailAddress);
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
  }, []);

  useEffect(() => {
    const pendingEmail = localStorage.getItem('pending_email');
    if (pendingEmail) {
      setEmail(pendingEmail);
      
      if (!otpSentRef.current) {
        otpSentRef.current = true; 
        sendOTP(pendingEmail);
      }
    } else {
      navigate('/register');
    }
  }, [navigate, sendOTP]);

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
      <div className="auth-grid-bg"></div>
      <div className="auth-wrapper">

        <nav className="auth-navbar">
          <a href="/" className="auth-navbar-brand">Fort<span>Knox</span></a>
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

        <motion.section className="auth-hero"
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
        >
          <div className="auth-hero-text">
            <div className="auth-tech-label" style={{ marginBottom: '16px' }}>OTP_VERIFICATION</div>
            <h1>Almost there</h1>
            <p>We've sent a verification code to your email. This step confirms your identity and keeps your account secure.</p>
          </div>
          <div className="auth-hero-visual">
            <div className="hero-placeholder"><svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="#0A66C2" strokeWidth="1.5"><rect x="2" y="4" width="20" height="16" rx="2"/><polyline points="22,7 12,13 2,7"/></svg></div>
          </div>
        </motion.section>

        <motion.section className="auth-form-section"
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.2 }}
        >
          <div className="auth-card">
            <h2>Verify your email</h2>
            <p className="otp-info">
              Enter the 6-digit code sent to <span className="otp-email">{email}</span>
            </p>

            {devOtp && (
              <div style={{ background: 'rgba(245,158,11,0.08)', border: '1px dashed rgba(245,158,11,0.3)', borderRadius: '8px', padding: '12px', marginBottom: '16px', fontSize: '12px', color: '#92400e', fontFamily: 'JetBrains Mono, monospace' }}>
                <strong>Dev Mode OTP:</strong> {devOtp}
              </div>
            )}

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
                  style={{ textAlign: 'center', letterSpacing: '8px', fontSize: '24px', fontFamily: 'Space Grotesk, sans-serif', fontWeight: '700' }}
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
        </motion.section>

        <section className="auth-features-bar">
          <div className="auth-feature-item"><span className="auth-feature-icon">I</span> Code expires in 10 min</div>
          <div className="auth-feature-item"><span className="auth-feature-icon">II</span> 5 attempts max</div>
          <div className="auth-feature-item"><span className="auth-feature-icon">III</span> Rate-limited</div>
          <div className="auth-feature-item"><span className="auth-feature-icon">IV</span> Email verified</div>
        </section>

      </div>
    </>
  );
}

export default VerifyOTP;
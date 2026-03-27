import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { authAPI } from '../services/api';
import forge from 'node-forge';
import './Auth.css';

function Login() {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
  });
  const [otpCode, setOtpCode] = useState('');
  const [otpPending, setOtpPending] = useState(false);
  const [devOtp, setDevOtp] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    });
  };

  // STEP 1: Submit credentials — backend sends OTP
  const handleCredentials = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setLoading(true);

    sessionStorage.clear();

    try {
      const response = await authAPI.login(formData);
      
      if (response.data.login_pending) {
        // Backend sent OTP, show OTP input
        setOtpPending(true);
        setSuccess('OTP sent to your email. Check your inbox.');
        if (response.data.dev_otp) {
          setDevOtp(response.data.dev_otp);
        }
      } else if (response.data.access_token) {
        // Fallback: direct token (shouldn't happen with new backend)
        completeLogin(response.data.access_token);
      }
    } catch (err) {
      let errorMsg = err.response?.data?.detail || 'Login failed';
      if (Array.isArray(errorMsg)) errorMsg = errorMsg[0].msg;
      setError(errorMsg);
    } finally {
      setLoading(false);
    }
  };

  // STEP 2: Verify OTP — backend issues JWT
  const handleOTPVerify = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await authAPI.loginVerifyOTP({
        email: formData.email,
        otp_code: otpCode
      });
      
      completeLogin(response.data.access_token);
    } catch (err) {
      let errorMsg = err.response?.data?.detail || 'OTP verification failed';
      if (Array.isArray(errorMsg)) errorMsg = errorMsg[0].msg;
      setError(errorMsg);
    } finally {
      setLoading(false);
    }
  };

  const completeLogin = (token) => {
    localStorage.setItem('access_token', token);
    localStorage.setItem('user_email', formData.email);
    
    // Derive key from password using PBKDF2 for E2EE messaging
    const salt = formData.email;
    const derivedKey = forge.pkcs5.pbkdf2(formData.password, salt, 10000, 32);
    sessionStorage.setItem('derived_key', forge.util.encode64(derivedKey));
    
    navigate('/dashboard');
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
          <h1>{otpPending ? 'Verify Your Identity' : 'Welcome back to FortKnox'}</h1>
          <p>{otpPending 
            ? 'We sent a verification code to your email. Enter it below to complete login.' 
            : 'Sign in to your account to access your encrypted dashboard, manage resumes, and control your privacy settings.'
          }</p>
        </div>
        <div className="auth-hero-visual">
          <div className="hero-placeholder">
            {otpPending 
              ? <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="#2563eb" strokeWidth="1.5"><rect x="2" y="4" width="20" height="16" rx="2"/><polyline points="22,7 12,13 2,7"/></svg>
              : <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="#2563eb" strokeWidth="1.5"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            }
          </div>
        </div>
      </section>

      <section className="auth-form-section">
        <div className="auth-card">
          {!otpPending ? (
            <>
              <h2>Sign In</h2>
              <p className="auth-subtitle">Enter your credentials to continue</p>
              <form onSubmit={handleCredentials}>
                <div className="form-group">
                  <label>Email</label>
                  <input
                    type="email"
                    name="email"
                    value={formData.email}
                    onChange={handleChange}
                    required
                    placeholder="you@example.com"
                  />
                </div>

                <div className="form-group" style={{ marginBottom: '5px' }}>
                  <label>Password</label>
                  <input
                    type="password"
                    name="password"
                    value={formData.password}
                    onChange={handleChange}
                    required
                    placeholder="Enter your password"
                  />
                </div>
                
                <div style={{ textAlign: 'right', marginBottom: '20px' }}>
                  <a href="/forgot-password" style={{ fontSize: '13px', color: '#3461c7', textDecoration: 'none', fontWeight: '500' }}>
                    Forgot Password?
                  </a>
                </div>

                {error && <div className="error-message">{error}</div>}

                <button type="submit" disabled={loading}>
                  {loading ? 'Verifying...' : 'Sign In'}
                </button>
              </form>

              <p className="auth-link">
                Don't have an account? <a href="/register">Create one</a>
              </p>
            </>
          ) : (
            <>
              <h2>Enter Verification Code</h2>
              <p className="auth-subtitle">
                A 6-digit code was sent to <strong>{formData.email}</strong>
              </p>
              
              {devOtp && (
                <div style={{ background: '#fef3c7', border: '1px solid #f59e0b', borderRadius: '8px', padding: '12px', marginBottom: '16px', fontSize: '13px', color: '#92400e' }}>
                  <strong>Dev Mode OTP:</strong> {devOtp}
                </div>
              )}
              
              <form onSubmit={handleOTPVerify}>
                <div className="form-group">
                  <label>Verification Code</label>
                  <input
                    type="text"
                    value={otpCode}
                    onChange={(e) => setOtpCode(e.target.value)}
                    required
                    placeholder="Enter 6-digit code"
                    maxLength="6"
                    style={{ textAlign: 'center', letterSpacing: '8px', fontSize: '24px' }}
                  />
                </div>

                {error && <div className="error-message">{error}</div>}
                {success && <div className="success-message">{success}</div>}

                <button type="submit" disabled={loading}>
                  {loading ? 'Verifying...' : 'Verify & Login'}
                </button>
              </form>

              <p className="auth-link">
                <a href="#!" onClick={(e) => { e.preventDefault(); setOtpPending(false); setError(''); setOtpCode(''); }}>
                  Back to login
                </a>
              </p>
            </>
          )}
        </div>
      </section>

      <section className="auth-features-bar">
        <div className="auth-feature-item"><span className="auth-feature-icon">I</span> AES-256 Encryption</div>
        <div className="auth-feature-item"><span className="auth-feature-icon">II</span> Argon2 Hashing</div>
        <div className="auth-feature-item"><span className="auth-feature-icon">III</span> OTP Verification</div>
        <div className="auth-feature-item"><span className="auth-feature-icon">IV</span> Privacy Controls</div>
      </section>
    </>
  );
}

export default Login;
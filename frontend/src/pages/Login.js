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
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    // SECURITY: Clear any old session data before starting a new one
    sessionStorage.clear();

    try {
      const response = await authAPI.login(formData);
      
      // Save Authentication details
      localStorage.setItem('access_token', response.data.access_token);
      localStorage.setItem('user_email', formData.email);
      
      // SECURITY FIX: Derive key from password using PBKDF2 immediately,
      // then store ONLY the derived key — never store the raw password.
      // This derived key is used to decrypt the private key for E2EE messaging.
      const salt = formData.email; // Use email as salt for deterministic derivation
      const derivedKey = forge.pkcs5.pbkdf2(formData.password, salt, 10000, 32);
      sessionStorage.setItem('derived_key', forge.util.encode64(derivedKey));
      
      navigate('/dashboard');
    } catch (err) {
      let errorMsg = err.response?.data?.detail || 'Login failed';
      if (Array.isArray(errorMsg)) errorMsg = errorMsg[0].msg;
      setError(errorMsg);
    } finally {
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
          <h1>Welcome back to FortKnox</h1>
          <p>Sign in to your account to access your encrypted dashboard, manage resumes, and control your privacy settings.</p>
        </div>
        <div className="auth-hero-visual">
          <div className="hero-placeholder">🔐</div>
        </div>
      </section>

      <section className="auth-form-section">
        <div className="auth-card">
          <h2>Sign In</h2>
          <p className="auth-subtitle">Enter your credentials to continue</p>
          <form onSubmit={handleSubmit}>
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
              {loading ? 'Signing in...' : 'Sign In'}
            </button>
          </form>

          <p className="auth-link">
            Don't have an account? <a href="/register">Create one</a>
          </p>
        </div>
      </section>

      <section className="auth-features-bar">
        <div className="auth-feature-item"><span className="auth-feature-icon">🔐</span> AES-256 Encryption</div>
        <div className="auth-feature-item"><span className="auth-feature-icon">🛡️</span> Argon2 Hashing</div>
        <div className="auth-feature-item"><span className="auth-feature-icon">✉️</span> OTP Verification</div>
        <div className="auth-feature-item"><span className="auth-feature-icon">👁️</span> Privacy Controls</div>
      </section>
    </>
  );
}

export default Login;
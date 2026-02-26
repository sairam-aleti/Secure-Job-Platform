import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { authAPI } from '../services/api';
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
      
      // SECURITY: Save password in SESSION storage (clears when tab closes)
      // This is needed to unlock the Private Key for E2EE messaging
      sessionStorage.setItem('user_pwd', formData.password);
      
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

            <div className="form-group">
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
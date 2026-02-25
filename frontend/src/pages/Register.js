import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { authAPI } from '../services/api';
import './Auth.css';

function Register() {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    full_name: '',
    role: 'job_seeker',
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

    try {
      await authAPI.register(formData);
      // After registration, redirect to OTP verification
      localStorage.setItem('pending_email', formData.email);
      navigate('/verify-otp');
    } catch (err) {
      setError(err.response?.data?.detail || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      {/* ---- Navbar ---- */}
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

      {/* ---- Hero ---- */}
      <section className="auth-hero">
        <div className="auth-hero-text">
          <h1>Start your secure career journey</h1>
          <p>Join FortKnox — a platform built with enterprise-grade encryption, identity verification, and privacy controls at its core.</p>
        </div>
        <div className="auth-hero-visual">
          <div className="hero-placeholder">🛡️</div>
        </div>
      </section>

      {/* ---- Form Section ---- */}
      <section className="auth-form-section">
        <div className="auth-card">
          <h2>Create your account</h2>
          <p className="auth-subtitle">Get started in under a minute</p>
          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label>Full Name</label>
              <input
                type="text"
                name="full_name"
                value={formData.full_name}
                onChange={handleChange}
                required
                placeholder="John Doe"
              />
            </div>

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
                placeholder="Minimum 12 characters"
              />
            </div>

            <div className="form-group">
              <label>I am a</label>
              <select name="role" value={formData.role} onChange={handleChange}>
                <option value="job_seeker">Job Seeker</option>
                <option value="recruiter">Recruiter</option>
              </select>
            </div>

            {error && <div className="error-message">{error}</div>}

            <button type="submit" disabled={loading}>
              {loading ? 'Creating Account...' : 'Create Account'}
            </button>
          </form>

          <p className="auth-link">
            Already have an account? <a href="/login">Sign in</a>
          </p>
        </div>
      </section>

      {/* ---- Security Features Bar ---- */}
      <section className="auth-features-bar">
        <div className="auth-feature-item"><span className="auth-feature-icon">🔐</span> AES-256 Encryption</div>
        <div className="auth-feature-item"><span className="auth-feature-icon">🛡️</span> Argon2 Hashing</div>
        <div className="auth-feature-item"><span className="auth-feature-icon">✉️</span> OTP Verification</div>
        <div className="auth-feature-item"><span className="auth-feature-icon">👁️</span> Privacy Controls</div>
      </section>
    </>
  );
}

export default Register;
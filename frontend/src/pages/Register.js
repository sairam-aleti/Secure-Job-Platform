import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { authAPI } from '../services/api';
import { motion } from 'framer-motion';
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
  const [showPassword, setShowPassword] = useState(false);
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
      localStorage.setItem('pending_email', formData.email);
      navigate('/verify-otp');
    } catch (err) {
      let errorMsg = 'Registration failed';
      
      if (err.response?.data?.detail) {
          if (Array.isArray(err.response.data.detail)) {
              errorMsg = err.response.data.detail[0].msg;
          } else {
              errorMsg = err.response.data.detail;
          }
      }
      
      setError(errorMsg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <>

      <div className="auth-wrapper">

        <nav className="auth-navbar">
          <a href="/" className="auth-navbar-brand">Fort<span>Knox</span></a>
          <div className="auth-navbar-center">
            <a href="/">HOME</a>
            <a href="/login">FIND JOBS</a>
            <a href="/about">ABOUT US</a>
          </div>
          <div className="auth-navbar-right">
            <a href="/login" className="btn-nav-login">LOGIN</a>
            <a href="/register" className="btn-nav-register">REGISTER</a>
          </div>
        </nav>

        <motion.section className="auth-hero"
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
        >
          <div className="auth-hero-text">
            <div className="auth-tech-label" style={{ marginBottom: '16px' }}>NETWORK_EXPANSION_INITIATED</div>
            <h1>Start your secure career journey</h1>
            <p>Identity verification and privacy-first engineering. Join the most secure job network in the digital frontier.</p>
          </div>
          <div className="auth-hero-visual">
            <div className="vault-standalone-scene">
              <div className="vault-body-3d">
                <div className="vault-interior-slot">
                  <motion.div 
                    className="badge-reveal-card"
                    animate={{ 
                      scale: [0.8, 1, 1, 0.8],
                      opacity: [0, 1, 1, 0],
                      z: [0, 50, 50, 0]
                    }}
                    transition={{ 
                      duration: 5, 
                      times: [0, 0.4, 0.6, 1],
                      repeat: Infinity,
                      repeatDelay: 2
                    }}
                  >
                    <div className="badge-reveal-header"></div>
                    <div className="badge-reveal-photo">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ width: '28px', height: '28px' }}>
                        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                        <circle cx="12" cy="7" r="4"></circle>
                      </svg>
                    </div>
                    <div className="badge-reveal-lines">
                      <div className="badge-reveal-line"></div>
                      <div className="badge-reveal-line" style={{ width: '70%' }}></div>
                      <div className="badge-reveal-line" style={{ width: '90%' }}></div>
                    </div>
                  </motion.div>
                </div>
                
                <motion.div 
                  className="vault-door-3d"
                  style={{ transformStyle: 'preserve-3d' }}
                  animate={{ 
                    rotateY: [0, -110, -110, 0] 
                  }}
                  transition={{ 
                    duration: 5, 
                    times: [0, 0.3, 0.7, 1],
                    repeat: Infinity,
                    repeatDelay: 2
                  }}
                >
                  <motion.div 
                    className="vault-wheel-handle"
                    animate={{ rotate: [0, 0, 0, 720] }}
                    transition={{ 
                      duration: 5, 
                      times: [0, 0.7, 0.8, 1],
                      repeat: Infinity,
                      repeatDelay: 2
                    }}
                  >
                    <div className="vault-spoke sp-1"></div>
                    <div className="vault-spoke sp-2"></div>
                    <div className="vault-spoke sp-3"></div>
                    <div className="vault-hub"></div>
                  </motion.div>
                </motion.div>
              </div>
            </div>
          </div>
        </motion.section>

        <motion.section className="auth-form-section"
          initial={{ opacity: 0, scale: 0.95, y: 40 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          transition={{ 
            type: "spring",
            stiffness: 100,
            damping: 15,
            delay: 0.2 
          }}
        >
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
                <div className="password-input-wrapper">
                  <input
                    type={showPassword ? "text" : "password"}
                    name="password"
                    value={formData.password}
                    onChange={handleChange}
                    required
                    placeholder="Minimum 12 characters"
                  />
                  <button 
                    type="button" 
                    className="eye-button" 
                    onClick={() => setShowPassword(!showPassword)}
                    title={showPassword ? "Hide Password" : "Show Password"}
                  >
                    {showPassword 
                      ? <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>
                      : <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                    }
                  </button>
                </div>
              </div>

              <div className="form-group">
                <label>I am a</label>
                <select name="role" value={formData.role} onChange={handleChange}>
                  <option value="job_seeker">Job Seeker</option>
                  <option value="recruiter">Recruiter</option>
                  <option value="admin">Admin</option>
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
        </motion.section>

        <section className="auth-features-bar">
          <div className="auth-feature-item"><span className="auth-feature-icon">I</span> AES-256 Encryption</div>
          <div className="auth-feature-item"><span className="auth-feature-icon">II</span> Argon2 Hashing</div>
          <div className="auth-feature-item"><span className="auth-feature-icon">III</span> OTP Verification</div>
          <div className="auth-feature-item"><span className="auth-feature-icon">IV</span> Privacy Controls</div>
        </section>

      </div>
    </>
  );
}

export default Register;
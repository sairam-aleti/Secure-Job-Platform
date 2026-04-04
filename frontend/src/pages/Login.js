import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { authAPI } from '../services/api';
import forge from 'node-forge';
import cryptoService from '../services/cryptoService';
import { motion, AnimatePresence } from 'framer-motion';
import { profileAPI } from '../services/api';
import './Auth.css';

function Login() {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
  });
  const [otpCode, setOtpCode] = useState('');
  const [otpPending, setOtpPending] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
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
      
      if (response.data.access_token) {
        // Superadmin: got direct token, go straight to dashboard
        completeLogin(response.data.access_token);
      } else if (response.data.login_pending) {
        // Normal user: OTP sent to email, show OTP input
        setOtpPending(true);
        setSuccess('OTP sent to your email. Check your inbox.');
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

  const completeLogin = async (token) => {
    localStorage.setItem('access_token', token);
    localStorage.setItem('user_email', formData.email);
    
    // Derive key from password using PBKDF2 for E2EE messaging
    const salt = formData.email;
    const derivedKey = forge.pkcs5.pbkdf2(formData.password, salt, 10000, 32);
    const derivedKeyB64 = forge.util.encode64(derivedKey);
    sessionStorage.setItem('derived_key', derivedKeyB64);
    
    // Generate and upload E2EE keys immediately so DMs work right away
    try {
      // Step 1: Check backend for existing keys instead of overriding automatically
      const profRes = await profileAPI.getProfile();
      
      const serverPrivKey = profRes.data.encrypted_private_key;
      const existingEncryptedKey = localStorage.getItem('encrypted_private_key');
      
      if (serverPrivKey) {
        // Backend has keys, pull to device and sync
        localStorage.setItem('encrypted_private_key', serverPrivKey);
        const privKey = cryptoService.decryptPrivateKey(serverPrivKey, derivedKeyB64);
        if (privKey && !profRes.data.public_key) {
           const pubKey = cryptoService.getPublicKeyFromPrivate(privKey);
           if (pubKey) await authAPI.updatePublicKey({ public_key: pubKey, encrypted_private_key: serverPrivKey });
        }
      } else if (existingEncryptedKey) {
        // Migration/edge case: keys exist logically, upload both to server
        const privKey = cryptoService.decryptPrivateKey(existingEncryptedKey, derivedKeyB64);
        if (privKey) {
          const pubKey = cryptoService.getPublicKeyFromPrivate(privKey);
          if (pubKey) await authAPI.updatePublicKey({ public_key: pubKey, encrypted_private_key: existingEncryptedKey });
        }
      } else {
        // No keys — generate fresh keypair and store on server
        const { publicKey, privateKey } = cryptoService.generateKeyPair();
        const encryptedPrivKey = cryptoService.encryptPrivateKey(privateKey, derivedKeyB64);
        localStorage.setItem('encrypted_private_key', encryptedPrivKey);
        await authAPI.updatePublicKey({ public_key: publicKey, encrypted_private_key: encryptedPrivKey });
      }
    } catch (err) {
      console.error('Key setup during login:', err);
      // Non-fatal — Dashboard will retry
    }
    
    navigate('/dashboard');
  };

  return (
    <>
      <nav className="auth-navbar">
        <a href="/" className="auth-navbar-brand">Fort<span>Knox</span></a>
        <div className="auth-navbar-center">
          <a href="/">HOME</a>
          <a href="/login">FIND JOBS</a>
          <a href="/login">ABOUT US</a>
        </div>
        <div className="auth-navbar-right">
          <a href="/login" className="btn-nav-login">LOGIN</a>
          <a href="/register" className="btn-nav-register">REGISTER</a>
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
          <AnimatePresence mode="wait">
            {otpPending ? (
              <motion.div 
                key="otp-visual"
                initial={{ opacity: 0, scale: 0.8 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 1.2 }}
                className="fingerprint-visual-wrapper"
              >
                {/* OTP Stage: Grey to Blue scanner (Static) with Person Icon */}
                <svg className="fingerprint-concentric-svg" viewBox="0 0 200 200">
                  <defs>
                    <linearGradient id="scanGradientOTP" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="var(--cy-brand)" />
                      <stop offset="100%" stopColor="#e0e0e0" />
                    </linearGradient>
                  </defs>
                  {[85, 72, 59, 46, 33].map((radius, i) => (
                    <motion.circle
                      key={radius}
                      cx="100"
                      cy="100"
                      r={radius}
                      fill="none"
                      stroke="#e0e0e0" // Initial grey
                      strokeWidth="3.5"
                      strokeLinecap="round"
                      strokeDasharray={`${radius * 0.4} ${radius * 0.3} ${radius * 0.8} ${radius * 0.5}`}
                      animate={{ 
                        stroke: ["#e0e0e0", "var(--cy-brand)", "#e0e0e0"],
                        strokeWidth: [3.5, 4.5, 3.5]
                      }}
                      transition={{ 
                        duration: 3, 
                        repeat: Infinity, 
                        delay: i * 0.4, 
                        ease: "easeInOut" 
                      }}
                    />
                  ))}
                  
                  {/* Scanner Vertical Beam effect */}
                  <motion.rect
                    width="180" height="2"
                    x="10" y="10"
                    fill="var(--cy-brand)"
                    style={{ opacity: 0.3, filter: 'blur(2px)' }}
                    animate={{ y: [20, 180, 20] }}
                    transition={{ duration: 4, repeat: Infinity, ease: "linear" }}
                  />
                </svg>
                
                {/* Center Badge with PERSON Icon */}
                <motion.div 
                  className="lock-center-badge"
                  animate={{ 
                    y: [0, -3, 0],
                    scale: [1, 1.05, 1]
                  }}
                  transition={{ duration: 4, repeat: Infinity, ease: "easeInOut" }}
                >
                  <svg viewBox="0 0 24 24" fill="none" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" style={{ width: '36px', height: '36px', color: '#b0bfc6' }}>
                    <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                    <circle cx="12" cy="7" r="4"></circle>
                  </svg>
                </motion.div>
              </motion.div>
            ) : (
              <motion.div 
                key="login-visual"
                initial={{ opacity: 0, scale: 0.8 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 1.2 }}
                className="fingerprint-visual-wrapper"
              >
                {/* Login Stage: Staggered Rotation (Phased) */}
                <svg className="fingerprint-concentric-svg" viewBox="0 0 200 200">
                  {[85, 72, 59, 46, 33].map((radius, i) => (
                    <motion.circle
                      key={radius}
                      cx="100"
                      cy="100"
                      r={radius}
                      fill="none"
                      stroke="var(--cy-brand)"
                      strokeWidth="2.5"
                      strokeLinecap="round"
                      strokeDasharray={`${radius * 0.4} ${radius * 0.3} ${radius * 0.8} ${radius * 0.5}`}
                      initial={{ rotate: i * 45, opacity: 0.1 }}
                      animate={{ 
                        rotate: 360,
                        opacity: [0.2, 0.5, 0.2],
                      }}
                      transition={{ 
                        rotate: { 
                          duration: 15 + i * 5, 
                          repeat: Infinity, 
                          ease: "linear",
                          delay: i * 1.5 // Staggered start: few, then few more, then full
                        },
                        opacity: { duration: 3, repeat: Infinity, ease: "easeInOut", delay: i * 0.2 }
                      }}
                    />
                  ))}
                  
                  {/* Background Aura */}
                  <motion.circle 
                    cx="100" cy="100" r="95" 
                    fill="none" stroke="var(--cy-brand)" strokeWidth="0.5" 
                    initial={{ opacity: 0 }}
                    animate={{ opacity: [0, 0.1, 0], scale: [0.95, 1, 0.95] }}
                    transition={{ duration: 4, repeat: Infinity }}
                  />
                </svg>
                {/* Center Badge with Floating Motion */}
                <motion.div 
                  className="lock-center-badge"
                  animate={{ 
                    y: [0, -3, 0],
                    scale: [1, 1.05, 1]
                  }}
                  transition={{ duration: 4, repeat: Infinity, ease: "easeInOut" }}
                >
                  <svg viewBox="0 0 24 24" fill="none" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" style={{ width: '32px', height: '32px', color: 'var(--cy-brand)' }}>
                    <path d="M7 11V7a5 5 0 0 1 9.9-1" />
                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                  </svg>
                </motion.div>
              </motion.div>
            )}
          </AnimatePresence>
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
                  <div className="password-input-wrapper">
                    <input
                      type={showPassword ? "text" : "password"}
                      name="password"
                      value={formData.password}
                      onChange={handleChange}
                      required
                      placeholder="Enter your password"
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
              
              <form onSubmit={handleOTPVerify}>
                <div className="form-group">
                  <label>Verification Code</label>
                  <input
                    type="text"
                    className="otp-input"
                    value={otpCode}
                    onChange={(e) => setOtpCode(e.target.value)}
                    required
                    placeholder="Enter Code"
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
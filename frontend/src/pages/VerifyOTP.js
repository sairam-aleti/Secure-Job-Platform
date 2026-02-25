import React, { useState, useEffect } from 'react';
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

  useEffect(() => {
    const pendingEmail = localStorage.getItem('pending_email');
    if (pendingEmail) {
      setEmail(pendingEmail);
      // Automatically send OTP
      sendOTP(pendingEmail);
    } else {
      navigate('/register');
    }
  }, [navigate]);

  const sendOTP = async (emailAddress) => {
    try {
      const response = await authAPI.sendOTP(emailAddress);
      setDevOtp(response.data.dev_otp);
      setSuccess('OTP sent! (Check dev_otp below for testing)');
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to send OTP');
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
      setError(err.response?.data?.detail || 'Invalid OTP');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <h2>Verify Your Email</h2>
        <p style={{ textAlign: 'center', color: '#666', marginBottom: '20px' }}>
          Enter the OTP sent to {email}
        </p>

        {devOtp && (
          <div className="success-message">
            <strong>Dev OTP:</strong> {devOtp}
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>OTP Code</label>
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
            {loading ? 'Verifying...' : 'Verify OTP'}
          </button>
        </form>

        <p className="auth-link">
          <a href="#" onClick={() => sendOTP(email)}>Resend OTP</a>
        </p>
      </div>
    </div>
  );
}

export default VerifyOTP;
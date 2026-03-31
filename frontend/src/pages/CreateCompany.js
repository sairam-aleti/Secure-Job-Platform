import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { companyAPI } from '../services/api';
import { motion } from 'framer-motion';
import './Dashboard.css';

function CreateCompany() {
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    location: '',
    website: '',
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const navigate = useNavigate();

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccessMessage('');

    try {
      await companyAPI.create(formData);
      setSuccessMessage('Company created successfully! Redirecting...');
      setTimeout(() => navigate('/dashboard'), 2000);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to create company');
      setLoading(false);
    }
  };

  return (
    <div className="app-layout">
      <div className="app-grid-bg"></div>

      <nav className="app-nav">
        <a href="/dashboard" className="nav-brand">Fort<span>Knox</span></a>
        <div className="nav-center">
          <a href="/dashboard">Dashboard</a>
        </div>
        <div className="nav-actions">
          <button className="btn-logout" onClick={() => navigate('/dashboard')}>Back</button>
        </div>
      </nav>

      <div className="page-hero">
        <div className="page-hero-inner">
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '10px', color: 'var(--cy-brand)', textTransform: 'uppercase', letterSpacing: '2px', marginBottom: '12px' }}>COMPANY_SETUP</div>
          <h2>Create Company Page</h2>
          <p>Establish your company presence on FortKnox</p>
        </div>
      </div>

      <main className="app-content">
        <motion.div className="card" initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}>
          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label>Company Name</label>
              <input type="text" name="name" value={formData.name} onChange={handleChange} required placeholder="e.g. SecureTech Inc." />
            </div>

            <div className="form-group">
              <label>Description</label>
              <textarea name="description" value={formData.description} onChange={handleChange} required placeholder="Tell us about your company..." rows="4" />
            </div>

            <div className="form-row">
              <div className="form-group">
                <label>Location</label>
                <input type="text" name="location" value={formData.location} onChange={handleChange} required placeholder="e.g. San Francisco, CA" />
              </div>
              <div className="form-group">
                <label>Website</label>
                <input type="url" name="website" value={formData.website} onChange={handleChange} placeholder="https://example.com" />
              </div>
            </div>

            {successMessage && <div className="success-message">{successMessage}</div>}
            {error && <div className="error-message">{error}</div>}

            <button type="submit" disabled={loading}>
              {loading ? 'Creating...' : 'Create Company Page'}
            </button>
          </form>
        </motion.div>
      </main>
    </div>
  );
}

export default CreateCompany;
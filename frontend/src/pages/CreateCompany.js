import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { companyAPI } from '../services/api';
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
  const [successMessage, setSuccessMessage] = useState(''); // NEW
  const navigate = useNavigate();

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccessMessage('');

    try {
      await companyAPI.create(formData);
      setSuccessMessage('Company created successfully! Redirecting...'); // NEW UI Message
      setTimeout(() => navigate('/dashboard'), 2000); // Redirect after 2s
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to create company');
      setLoading(false); // Only stop loading if error (success keeps loading until redirect)
    }
  };

  return (
    <div className="app-layout">
      <nav className="app-nav">
        <a href="/dashboard" className="nav-brand">FortKnox</a>
        <div className="nav-center">
          <a href="/dashboard">Dashboard</a>
        </div>
        <div className="nav-actions">
          <button className="btn-logout" onClick={() => navigate('/dashboard')}>Back</button>
        </div>
      </nav>

      <div className="page-hero">
        <div className="page-hero-inner">
          <h2>Create Company Page</h2>
          <p>Establish your company presence on FortKnox</p>
        </div>
      </div>

      <main className="app-content">
        <div className="card">
          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label>Company Name</label>
              <input
                type="text"
                name="name"
                value={formData.name}
                onChange={handleChange}
                required
                placeholder="e.g. SecureTech Inc."
              />
            </div>

            <div className="form-group">
              <label>Description</label>
              <textarea
                name="description"
                value={formData.description}
                onChange={handleChange}
                required
                placeholder="Tell us about your company..."
                rows="4"
              />
            </div>

            <div className="form-row">
              <div className="form-group">
                <label>Location</label>
                <input
                  type="text"
                  name="location"
                  value={formData.location}
                  onChange={handleChange}
                  required
                  placeholder="e.g. San Francisco, CA"
                />
              </div>
              <div className="form-group">
                <label>Website</label>
                <input
                  type="url"
                  name="website"
                  value={formData.website}
                  onChange={handleChange}
                  placeholder="https://example.com"
                />
              </div>
            </div>

            {successMessage && <div className="success-message">{successMessage}</div>} {/* NEW */}
            {error && <div className="error-message">{error}</div>}

            <button type="submit" disabled={loading}>
              {loading ? 'Creating...' : 'Create Company Page'}
            </button>
          </form>
        </div>
      </main>
    </div>
  );
}

export default CreateCompany;
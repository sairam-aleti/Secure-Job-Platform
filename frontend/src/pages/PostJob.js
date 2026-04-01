import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { jobAPI, companyAPI } from '../services/api';
import { motion } from 'framer-motion';
import './Dashboard.css';

function PostJob() {
  const [companies, setCompanies] = useState([]);
  const [formData, setFormData] = useState({
    company_id: '',
    title: '',
    description: '',
    location: '',
    employment_type: 'Full-time',
    skills_required: '',
    salary_amount: '',
    currency: 'USD',
    deadline: '',
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    fetchCompanies();
  }, []);

  const fetchCompanies = async () => {
    try {
      const response = await companyAPI.list();
      setCompanies(response.data);
      if (response.data.length > 0) {
        setFormData(prev => ({ ...prev, company_id: response.data[0].id }));
      }
    } catch (err) {
      console.error('Failed to load companies');
    }
  };

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccessMessage('');

    try {
      const skillsArray = formData.skills_required.split(',').map(s => s.trim());
      const payload = { 
        ...formData, 
        skills_required: JSON.stringify(skillsArray),
        salary_range: `${formData.currency} ${formData.salary_amount}`
      };
      // Remove temporary fields
      delete payload.salary_amount;
      delete payload.currency;
      
      // Send deadline as ISO string or null
      if (payload.deadline) {
        payload.deadline = new Date(payload.deadline).toISOString();
      } else {
        payload.deadline = null;
      }
      await jobAPI.create(payload);
      setSuccessMessage('Job posted successfully! Redirecting...');
      setTimeout(() => navigate('/dashboard'), 2000);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to post job');
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
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '10px', color: 'var(--cy-brand)', textTransform: 'uppercase', letterSpacing: '2px', marginBottom: '12px' }}>JOB_POSTING</div>
          <h2>Post a New Job</h2>
          <p>Find the best talent for your company</p>
        </div>
      </div>

      <main className="app-content">
        <motion.div className="card" initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}>
          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label>Company</label>
              <select name="company_id" value={formData.company_id} onChange={handleChange} required>
                {companies.map(c => (<option key={c.id} value={c.id}>{c.name}</option>))}
              </select>
            </div>

            <div className="form-group">
              <label>Job Title</label>
              <input type="text" name="title" value={formData.title} onChange={handleChange} required placeholder="e.g. Senior Security Analyst" />
            </div>

            <div className="form-row">
              <div className="form-group">
                <label>Employment Type</label>
                <select name="employment_type" value={formData.employment_type} onChange={handleChange}>
                  <option value="Full-time">Full-time</option>
                  <option value="Part-time">Part-time</option>
                  <option value="Contract">Contract</option>
                  <option value="Internship">Internship</option>
                </select>
              </div>
              <div className="form-group">
                <label>Location</label>
                <input type="text" name="location" value={formData.location} onChange={handleChange} required placeholder="e.g. Remote / New York" />
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label>Salary Range</label>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <select 
                    name="currency" 
                    value={formData.currency} 
                    onChange={handleChange}
                    style={{ flex: '0 0 80px' }}
                  >
                    <option value="USD">USD ($)</option>
                    <option value="EUR">EUR (€)</option>
                    <option value="INR">INR (₹)</option>
                  </select>
                  <input 
                    type="text" 
                    name="salary_amount" 
                    value={formData.salary_amount} 
                    onChange={handleChange} 
                    placeholder="e.g. 100k - 120k" 
                    style={{ flex: 1 }}
                  />
                </div>
              </div>
              <div className="form-group">
                <label>Application Deadline (Optional)</label>
                <input type="datetime-local" name="deadline" value={formData.deadline} onChange={handleChange} />
              </div>
            </div>

            <div className="form-group">
              <label>Required Skills (comma separated)</label>
              <input type="text" name="skills_required" value={formData.skills_required} onChange={handleChange} required placeholder="e.g. Python, Linux, Burp Suite" />
            </div>

            <div className="form-group">
              <label>Job Description</label>
              <textarea name="description" value={formData.description} onChange={handleChange} required placeholder="Describe the role responsibilities..." rows="6" />
            </div>

            {successMessage && <div className="success-message">{successMessage}</div>}
            {error && <div className="error-message">{error}</div>}

            <button type="submit" disabled={loading}>
              {loading ? 'Posting...' : 'Post Job'}
            </button>
          </form>
        </motion.div>
      </main>
    </div>
  );
}

export default PostJob;
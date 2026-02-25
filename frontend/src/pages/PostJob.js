import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { jobAPI, companyAPI } from '../services/api';
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
    salary_range: '',
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [successMessage, setSuccessMessage] = useState(''); // NEW
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
      // Format skills as JSON string array
      const skillsArray = formData.skills_required.split(',').map(s => s.trim());
      
      await jobAPI.create({
        ...formData,
        skills_required: JSON.stringify(skillsArray)
      });
      
      setSuccessMessage('Job posted successfully! Redirecting...'); // NEW UI Message
      setTimeout(() => navigate('/dashboard'), 2000); // Redirect after 2s
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to post job');
      setLoading(false); // Only stop loading on error
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
          <h2>Post a New Job</h2>
          <p>Find the best talent for your company</p>
        </div>
      </div>

      <main className="app-content">
        <div className="card">
          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label>Company</label>
              <select 
                name="company_id" 
                value={formData.company_id} 
                onChange={handleChange}
                required
              >
                {companies.map(c => (
                  <option key={c.id} value={c.id}>{c.name}</option>
                ))}
              </select>
            </div>

            <div className="form-group">
              <label>Job Title</label>
              <input
                type="text"
                name="title"
                value={formData.title}
                onChange={handleChange}
                required
                placeholder="e.g. Senior Security Analyst"
              />
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
                <input
                  type="text"
                  name="location"
                  value={formData.location}
                  onChange={handleChange}
                  required
                  placeholder="e.g. Remote / New York"
                />
              </div>
            </div>

            <div className="form-group">
              <label>Salary Range</label>
              <input
                type="text"
                name="salary_range"
                value={formData.salary_range}
                onChange={handleChange}
                placeholder="e.g. $100k - $120k"
              />
            </div>

            <div className="form-group">
              <label>Required Skills (comma separated)</label>
              <input
                type="text"
                name="skills_required"
                value={formData.skills_required}
                onChange={handleChange}
                required
                placeholder="e.g. Python, Linux, Burp Suite"
              />
            </div>

            <div className="form-group">
              <label>Job Description</label>
              <textarea
                name="description"
                value={formData.description}
                onChange={handleChange}
                required
                placeholder="Describe the role responsibilities..."
                rows="6"
              />
            </div>

            {successMessage && <div className="success-message">{successMessage}</div>} {/* NEW */}
            {error && <div className="error-message">{error}</div>}

            <button type="submit" disabled={loading}>
              {loading ? 'Posting...' : 'Post Job'}
            </button>
          </form>
        </div>
      </main>
    </div>
  );
}

export default PostJob;
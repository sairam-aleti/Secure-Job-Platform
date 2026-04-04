import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
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
  const [searchParams] = useSearchParams();
  const editJobId = searchParams.get('edit');
  const [isEditMode, setIsEditMode] = useState(false);

  useEffect(() => {
    fetchCompanies();
    if (editJobId) {
      loadJobForEdit(editJobId);
    }
  }, [editJobId]);

  const fetchCompanies = async () => {
    try {
      const response = await companyAPI.list();
      setCompanies(response.data);
      if (response.data.length > 0 && !editJobId) {
        setFormData(prev => ({ ...prev, company_id: response.data[0].id }));
      }
    } catch (err) {
      console.error('Failed to load companies');
    }
  };

  const loadJobForEdit = async (jobId) => {
    try {
      const jobsRes = await jobAPI.myJobs();
      const job = jobsRes.data.find(j => j.id === parseInt(jobId));
      if (job) {
        setIsEditMode(true);
        // Parse salary_range back to currency + amount
        let currency = 'USD';
        let amount = '';
        if (job.salary_range) {
          const parts = job.salary_range.split(' ');
          if (parts.length >= 2) {
            currency = parts[0];
            amount = parts.slice(1).join(' ');
          } else {
            amount = job.salary_range;
          }
        }
        // Parse skills_required (could be JSON array string)
        let skills = job.skills_required || '';
        try {
          const parsed = JSON.parse(skills);
          if (Array.isArray(parsed)) skills = parsed.join(', ');
        } catch { /* keep as-is */ }

        setFormData({
          company_id: job.company_id || '',
          title: job.title || '',
          description: job.description || '',
          location: job.location || '',
          employment_type: job.employment_type || 'Full-time',
          skills_required: skills,
          salary_amount: amount,
          currency: currency,
          deadline: job.deadline ? new Date(job.deadline).toISOString().split('T')[0] : '',
        });
      } else {
        setError('Job not found. You can only edit your own jobs.');
      }
    } catch (err) {
      setError('Failed to load job for editing.');
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

    // Validate deadline is not in the past
    if (formData.deadline) {
      const deadlineDate = new Date(formData.deadline);
      if (deadlineDate < new Date()) {
        setError('Deadline must be a future date.');
        setLoading(false);
        return;
      }
    }

    // Validate salary amount is not unrealistically high
    if (formData.salary_amount.trim()) {
      const salaryNumbers = formData.salary_amount.match(/\d+\.?\d*/g);
      if (salaryNumbers) {
        const maxVal = Math.max(...salaryNumbers.map(Number));
        if (maxVal > 10000000) {
          setError('Salary value is unrealistic. Please enter a valid range (max 10,000,000).');
          setLoading(false);
          return;
        }
      }
    }

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

      if (isEditMode && editJobId) {
        await jobAPI.update(parseInt(editJobId), payload);
        setSuccessMessage('Job updated successfully! Redirecting...');
      } else {
        await jobAPI.create(payload);
        setSuccessMessage('Job posted successfully! Redirecting...');
      }
      setTimeout(() => navigate('/dashboard'), 2000);
    } catch (err) {
      // Extract error message safely — handle both string and array/object detail
      let errorMsg = 'Failed to post job';
      const detail = err.response?.data?.detail;
      if (detail) {
        if (typeof detail === 'string') {
          errorMsg = detail;
        } else if (Array.isArray(detail)) {
          errorMsg = detail.map(d => typeof d === 'object' ? (d.msg || JSON.stringify(d)) : d).join(', ');
        } else if (typeof detail === 'object') {
          errorMsg = detail.msg || JSON.stringify(detail);
        }
      }
      setError(errorMsg);
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
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '10px', color: 'var(--cy-brand)', textTransform: 'uppercase', letterSpacing: '2px', marginBottom: '12px' }}>
            {isEditMode ? 'JOB_EDIT' : 'JOB_POSTING'}
          </div>
          <h2>{isEditMode ? 'Edit Job Posting' : 'Post a New Job'}</h2>
          <p>{isEditMode ? 'Update the details of your job listing' : 'Find the best talent for your company'}</p>
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
              <input type="text" name="title" value={formData.title} onChange={handleChange} required placeholder="e.g. Senior Security Analyst" maxLength={200} />
              <div style={{fontSize:'10px', color:'var(--cy-text-mute)', textAlign:'right', marginTop:'2px'}}>{(formData.title || '').length}/200</div>
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
                <input type="text" name="location" value={formData.location} onChange={handleChange} required placeholder="e.g. Remote / New York" maxLength={200} />
                <div style={{fontSize:'10px', color:'var(--cy-text-mute)', textAlign:'right', marginTop:'2px'}}>{(formData.location || '').length}/200</div>
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
                    maxLength={100}
                  />
                </div>
                <div style={{fontSize:'10px', color:'var(--cy-text-mute)', textAlign:'right', marginTop:'2px'}}>{(formData.salary_amount || '').length}/100</div>
              </div>
              <div className="form-group">
                <label>Application Deadline (Optional)</label>
                <input 
                  type={formData.deadline ? "date" : "text"}
                  onFocus={(e) => e.target.type = 'date'}
                  onBlur={(e) => { if (!e.target.value) e.target.type = 'text'; }}
                  placeholder="dd/mm/yyyy"
                  name="deadline" 
                  value={formData.deadline} 
                  onChange={handleChange}
                  min={new Date().toISOString().split('T')[0]} 
                  style={{ color: formData.deadline ? 'inherit' : 'var(--cy-text-mute)' }}
                />
              </div>
            </div>

            <div className="form-group">
              <label>Required Skills (comma separated)</label>
              <input type="text" name="skills_required" value={formData.skills_required} onChange={handleChange} required placeholder="e.g. Python, Linux, Burp Suite" maxLength={500} />
              <div style={{fontSize:'10px', color:'var(--cy-text-mute)', textAlign:'right', marginTop:'2px'}}>{(formData.skills_required || '').length}/500</div>
            </div>

            <div className="form-group">
              <label>Job Description</label>
              <textarea name="description" value={formData.description} onChange={handleChange} required placeholder="Describe the role responsibilities..." rows="6" maxLength={3000} />
              <div style={{fontSize:'10px', color:'var(--cy-text-mute)', textAlign:'right', marginTop:'2px'}}>{(formData.description || '').length}/3000</div>
            </div>

            {successMessage && <div className="success-message">{successMessage}</div>}
            {error && <div className="error-message">{error}</div>}

            <button type="submit" disabled={loading}>
              {loading ? (isEditMode ? 'Updating...' : 'Posting...') : (isEditMode ? 'Update Job' : 'Post Job')}
            </button>
          </form>
        </motion.div>
      </main>
    </div>
  );
}

export default PostJob;
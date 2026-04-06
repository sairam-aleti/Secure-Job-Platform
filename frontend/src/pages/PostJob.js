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
    currency: 'INR',
    deadline: '',
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const editJobId = searchParams.get('edit');
  const [isEditMode, setIsEditMode] = useState(false);
  const [tags, setTags] = useState([]);
  const [tagInput, setTagInput] = useState('');
  const [activeJobsCount, setActiveJobsCount] = useState(0);

  useEffect(() => {
    fetchCompanies();
    fetchActiveJobs();
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

  const fetchActiveJobs = async () => {
    if (editJobId) return; // Ignore on edit mode to save calls.
    try {
      const response = await jobAPI.myJobs();
      const active = response.data.filter(j => {
        if (!j.deadline) return true;
        return new Date(j.deadline) > new Date();
      });
      setActiveJobsCount(active.length);
    } catch {}
  };

  const loadJobForEdit = async (jobId) => {
    try {
      const jobsRes = await jobAPI.myJobs();
      const job = jobsRes.data.find(j => j.id === parseInt(jobId));
      if (job) {
        setIsEditMode(true);
        // Parse salary_range back to currency + amount
        let currency = 'INR';
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
          if (Array.isArray(parsed)) setTags(parsed);
        } catch { 
           if (skills) setTags(skills.split(',').map(s=>s.trim()).filter(s=>s));
        }

        setFormData({
          company_id: job.company_id || '',
          title: job.title || '',
          description: job.description || '',
          location: job.location || '',
          employment_type: job.employment_type || 'Full-time',
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
    if (e.target.name === 'salary_amount') {
      // Allowed characters: digits, spaces, commas, hyphens
      const cleanValue = e.target.value.replace(/[^0-9,\- ]/g, '');
      setFormData({ ...formData, salary_amount: cleanValue });
      return;
    }
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleTagKeyDown = (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      const val = tagInput.trim();
      if (!val) return;
      if (val.length > 20) {
        setError('Skill tag cannot exceed 20 characters.');
        return;
      }
      if (tags.length >= 15) {
        setError('You can only add up to 15 skills.');
        return;
      }
      if (!/[A-Za-z]/.test(val)) {
        setError('Tags must contain at least one alphabet character.');
        return;
      }
      if (!tags.includes(val)) {
        setTags([...tags, val]);
      }
      setTagInput('');
      setError('');
    }
  };

  const removeTag = (indexToRemove) => {
    setTags(tags.filter((_, index) => index !== indexToRemove));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccessMessage('');

    if (!formData.title.trim()) {
      setError('Job title is required.');
      setLoading(false);
      return;
    }
    
    if (tags.length < 3) {
      setError('Please enter at least 3 skills as tags.');
      setLoading(false);
      return;
    }

    if (!formData.location.trim() || !formData.description.trim()) {
      setError('Fundamental fields cannot be empty or just spaces.');
      setLoading(false);
      return;
    }

    if (!formData.salary_amount.trim()) {
      setError('Salary is required (e.g., 500000 or 500000-1000000).');
      setLoading(false);
      return;
    }

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
    if (formData.salary_amount) {
      const rawSalary = formData.salary_amount.replace(/[^0-9]/g, '');
      if (rawSalary) {
        if (parseInt(rawSalary, 10) > 500000000) {  // Realistic check for INR up to 50 Crores
          setError('Salary value is unrealistic. Please enter a valid reasonable range limit.');
          setLoading(false);
          return;
        }
      }
    }

    try {
      const payload = {
        ...formData,
        skills_required: JSON.stringify(tags),
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
          {(companies.length === 0 || (!isEditMode && activeJobsCount >= 5)) ? (
            <div style={{ background: 'rgba(220, 38, 38, 0.1)', border: '1px solid #dc2626', padding: '24px', borderRadius: '8px', color: '#dc2626', textAlign: 'center', marginBottom: '20px' }}>
              <h3 style={{ margin: 0, fontSize: '18px', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                Action Required
              </h3>
              {companies.length === 0 ? (
                <>
                  <p style={{ marginTop: '12px', fontSize: '15px' }}>You must create a Company Page before posting a job.</p>
                  <button 
                    onClick={() => navigate('/create-company')} 
                    style={{ marginTop: '16px', background: '#dc2626', color: '#fff', border: 'none', padding: '10px 20px', borderRadius: '4px', cursor: 'pointer', fontWeight: 'bold' }}
                  >
                    Create Company Page
                  </button>
                </>
              ) : (
                <p style={{ marginTop: '12px', fontSize: '15px' }}>You have reached the maximum limit of 5 active job postings.</p>
              )}
            </div>
          ) : null}

          <form onSubmit={handleSubmit} style={{ opacity: (companies.length === 0 || (!isEditMode && activeJobsCount >= 5)) ? 0.4 : 1, pointerEvents: (companies.length === 0 || (!isEditMode && activeJobsCount >= 5)) ? 'none' : 'auto' }}>
            <div className="form-group">
              <label>Company</label>
              <select name="company_id" value={formData.company_id} onChange={handleChange} required>
                {companies.map(c => (<option key={c.id} value={c.id}>{c.name}</option>))}
              </select>
            </div>

            <div className="form-group">
              <label>Job Title</label>
              <input type="text" name="title" value={formData.title} onChange={handleChange} required placeholder="e.g. Senior Security Analyst" maxLength={200} />
              <div style={{ fontSize: '10px', color: 'var(--cy-text-mute)', textAlign: 'right', marginTop: '2px' }}>{(formData.title || '').length}/200</div>
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
                <div style={{ fontSize: '10px', color: 'var(--cy-text-mute)', textAlign: 'right', marginTop: '2px' }}>{(formData.location || '').length}/200</div>
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label>Salary </label>
                <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                  <div style={{ flex: '0 0 auto', background: 'var(--cy-glass-bg)', border: '1px dashed var(--cy-border)', borderRadius: '8px', padding: '12px 16px', fontSize: '14px', fontWeight: 200, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    INR (₹)
                  </div>
                  <input
                    type="text"
                    name="salary_amount"
                    value={formData.salary_amount}
                    onChange={handleChange}
                    placeholder="e.g. 5,00,000  OR  5,00,000 - 10,00,000"
                    required
                    style={{ flex: 1 }}
                    maxLength={50}
                  />
                </div>
                <div style={{ fontSize: '10px', color: 'var(--cy-text-mute)', textAlign: 'right', marginTop: '2px' }}>{(formData.salary_amount || '').length}/50</div>
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
              <label>Required Skills (Press Enter to add tag)</label>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginBottom: '8px' }}>
                {tags.map((tag, index) => (
                  <div key={index} style={{ background: 'rgba(10,102,194,0.08)', color: 'var(--cy-brand)', border: '1px dashed rgba(10,102,194,0.25)', padding: '5px 12px', borderRadius: '16px', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '6px', fontWeight: '600', fontFamily: 'Space Grotesk, sans-serif' }}>
                    {tag}
                    <span onClick={() => removeTag(index)} style={{ cursor: 'pointer', fontWeight: 'bold', opacity: 0.7, lineHeight: 1 }}>✕</span>
                  </div>
                ))}
              </div>
              <input 
                type="text" 
                value={tagInput}
                onChange={(e) => setTagInput(e.target.value)}
                onKeyDown={handleTagKeyDown}
                placeholder="e.g. Python, Linux (At least 3 skills)" 
                maxLength={20} 
              />
            </div>

            <div className="form-group">
              <label>Job Description</label>
              <textarea name="description" value={formData.description} onChange={handleChange} required placeholder="Describe the role responsibilities..." rows="6" maxLength={3000} />
              <div style={{ fontSize: '10px', color: 'var(--cy-text-mute)', textAlign: 'right', marginTop: '2px' }}>{(formData.description || '').length}/3000</div>
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
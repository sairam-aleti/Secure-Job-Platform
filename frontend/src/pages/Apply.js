import React, { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { applicationAPI, resumeAPI } from '../services/api';
import './Dashboard.css';

function Apply() {
  const { jobId } = useParams();
  const [resumes, setResumes] = useState([]);
  const [formData, setFormData] = useState({
    job_id: jobId,
    resume_id: '',
    cover_letter: ''
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    fetchResumes();
  }, []);

  const fetchResumes = async () => {
    try {
      const response = await resumeAPI.list();
      setResumes(response.data);
      if (response.data.length > 0) {
        setFormData(prev => ({ ...prev, resume_id: response.data[0].id }));
      }
    } catch (err) {
      setError('Failed to load your resumes. Please upload one first.');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSaving(true);
    setError('');

    try {
      await applicationAPI.apply(formData);
      setSuccess('Application submitted successfully! Redirecting...');
      setTimeout(() => navigate('/dashboard'), 2000);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to submit application');
      setSaving(false);
    }
  };

  if (loading) return <div className="app-layout"><main className="app-content"><p>Loading...</p></main></div>;

  return (
    <div className="app-layout">
      <nav className="app-nav">
        <a href="/dashboard" className="nav-brand">FortKnox</a>
        <div className="nav-actions">
          <button className="btn-logout" onClick={() => navigate('/jobs')}>Back to Jobs</button>
        </div>
      </nav>

      <div className="page-hero">
        <div className="page-hero-inner">
          <h2>Submit Application</h2>
          <p>Complete your application for this position</p>
        </div>
      </div>

      <main className="app-content">
        <div className="card">
          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label>Select Resume</label>
              <select 
                name="resume_id" 
                value={formData.resume_id} 
                onChange={(e) => setFormData({...formData, resume_id: e.target.value})}
                required
              >
                {resumes.length === 0 ? (
                  <option disabled>No resumes found. Please upload one first.</option>
                ) : (
                  resumes.map(r => (
                    <option key={r.id} value={r.id}>{r.original_filename}</option>
                  ))
                )}
              </select>
            </div>

            <div className="form-group">
              <label>Cover Letter (Optional)</label>
              <textarea
                name="cover_letter"
                value={formData.cover_letter}
                onChange={(e) => setFormData({...formData, cover_letter: e.target.value})}
                placeholder="Why are you a good fit for this role?"
                rows="6"
              />
            </div>

            {error && <div className="error-message">{error}</div>}
            {success && <div className="success-message">{success}</div>}

            <button type="submit" disabled={saving || resumes.length === 0}>
              {saving ? 'Submitting...' : 'Submit Application'}
            </button>
          </form>
        </div>
      </main>
    </div>
  );
}

export default Apply;
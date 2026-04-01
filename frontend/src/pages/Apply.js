import React, { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { applicationAPI, resumeAPI, profileAPI } from '../services/api';
import { motion } from 'framer-motion';
import './Dashboard.css';

function Apply() {
  const { jobId } = useParams();
  const [resumes, setResumes] = useState([]);
  const [formData, setFormData] = useState({
    job_id: parseInt(jobId),
    resume_id: '',
    cover_letter: ''
  });
  const [profile, setProfile] = useState(null);
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
      try {
        const profRes = await profileAPI.getProfile();
        setProfile(profRes.data);
      } catch {}
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSaving(true);
    if (!formData.resume_id) {
      setError('Please select a resume to apply.');
      setSaving(false);
      return;
    }

    try {
      console.log("Submitting application:", formData);
      await applicationAPI.apply(formData);
      setSuccess('Application submitted successfully! Redirecting...');
      setTimeout(() => navigate('/dashboard'), 2000);
    } catch (err) {
      console.error("Full application error object:", err);
      setSaving(false);
      
      if (err.response) {
        // The server responded with a status code that falls out of the range of 2xx
        const msg = err.response.data?.detail;
        const errorString = typeof msg === 'object' ? JSON.stringify(msg) : (msg || `Server Error (${err.response.status})`);
        setError(`Application Failed: ${errorString}`);
      } else if (err.request) {
        // The request was made but no response was received
        setError('Network Error: The server did not respond. This could be due to a backend crash or a CORS/SSL block. Check the server logs.');
      } else {
        // Something happened in setting up the request that triggered an Error
        setError(`Request Error: ${err.message}`);
      }
    }
  };

  if (loading) return <div className="app-layout"><div className="app-grid-bg"></div><main className="app-content"><p style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '13px', color: 'var(--cy-text-mute)', textAlign: 'center', marginTop: '80px' }}>Loading...</p></main></div>;

  return (
    <div className="app-layout">
      <div className="app-grid-bg"></div>

      <nav className="app-nav">
        <a href="/dashboard" className="nav-brand">Fort<span>Knox</span></a>
        <div className="nav-actions">
          {profile && (
            <div style={{ display: 'flex', alignItems: 'center', marginRight: '16px' }}>
              <div 
                style={{ 
                  width: '32px', height: '32px', borderRadius: '50%', background: 'var(--cy-glass-bg)', 
                  border: '1px dashed var(--cy-border)', display: 'flex', alignItems: 'center', justifyContent: 'center',
                  overflow: 'hidden', position: 'relative'
                }}
              >
                {profile.profile_picture ? (
                  <img src={`https://127.0.0.1:8000/uploads/${profile.profile_picture}`} alt="Profile" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
                ) : (
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--cy-text-mute)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                )}
              </div>
            </div>
          )}
          <button className="btn-logout" onClick={() => navigate('/jobs')}>Back to Jobs</button>
        </div>
      </nav>

      <div className="page-hero">
        <div className="page-hero-inner">
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '10px', color: 'var(--cy-brand)', textTransform: 'uppercase', letterSpacing: '2px', marginBottom: '12px' }}>APPLICATION_SUBMIT</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
            <div 
              style={{ 
                width: '64px', height: '64px', borderRadius: '50%', background: 'var(--cy-glass-bg)', 
                border: '2px dashed var(--cy-border)', display: 'flex', alignItems: 'center', justifyContent: 'center',
                overflow: 'hidden', position: 'relative', flexShrink: 0
              }}
            >
              {profile?.profile_picture ? (
                <img src={`https://127.0.0.1:8000/uploads/${profile.profile_picture}`} alt="Profile" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
              ) : (
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--cy-text-mute)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
              )}
            </div>
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <h2 style={{ margin: 0 }}>Submit Application</h2>
              <p style={{ margin: 0, marginTop: '4px' }}>Complete your application for this position</p>
            </div>
          </div>
        </div>
      </div>

      <main className="app-content">
        <motion.div className="card" initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}>
          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label>Select Resume</label>
              <select name="resume_id" value={formData.resume_id} onChange={(e) => setFormData({...formData, resume_id: parseInt(e.target.value)})} required>
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
              <textarea name="cover_letter" value={formData.cover_letter}
                onChange={(e) => setFormData({...formData, cover_letter: e.target.value})}
                placeholder="Why are you a good fit for this role?" rows="6"
              />
            </div>

            {error && <div className="error-message">{error}</div>}
            {success && <div className="success-message">{success}</div>}

            <button type="submit" disabled={saving || resumes.length === 0}>
              {saving ? 'Submitting...' : 'Submit Application'}
            </button>
          </form>
        </motion.div>
      </main>
    </div>
  );
}

export default Apply;
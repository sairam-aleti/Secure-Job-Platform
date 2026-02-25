import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { jobAPI, profileAPI } from '../services/api';
import './Dashboard.css';

function JobBoard() {
  const [jobs, setJobs] = useState([]);
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      console.log("Fetching Job Board data...");
      const profileRes = await profileAPI.getProfile();
      setProfile(profileRes.data);

      const jobsRes = await jobAPI.list();
      console.log("Jobs received from backend:", jobsRes.data); // DEBUG LOG
      setJobs(jobsRes.data);
    } catch (err) {
      console.error('Job Board fetch error:', err);
      setError('Failed to load jobs. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('user_email');
    navigate('/login');
  };

  const filteredJobs = jobs.filter(job => 
    job.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
    job.description.toLowerCase().includes(searchTerm.toLowerCase())
  );

  if (loading) {
    return (
      <div className="app-layout">
        <nav className="app-nav">
          <a href="/dashboard" className="nav-brand">FortKnox</a>
        </nav>
        <main className="app-content">
          <p style={{ textAlign: 'center', color: '#6b7280', marginTop: '80px' }}>Loading job board...</p>
        </main>
      </div>
    );
  }

  return (
    <div className="app-layout">
      <nav className="app-nav">
        <a href="/dashboard" className="nav-brand">FortKnox</a>
        <div className="nav-center">
          <a href="/dashboard">Dashboard</a>
          <a href="/jobs">Job Board</a>
          {profile?.role !== 'recruiter' && <a href="/profile">Profile</a>}
          {profile?.role === 'admin' && <a href="/admin">Admin</a>}
        </div>
        <div className="nav-actions">
          <button className="btn-logout" onClick={handleLogout}>Sign Out</button>
        </div>
      </nav>

      <div className="page-hero">
        <div className="page-hero-inner">
          <h2>Job Board</h2>
          <p>Public listings for all open positions</p>
        </div>
      </div>

      <main className="app-content">
        {error && <div className="error-message">{error}</div>}

        <div className="card">
          <div className="form-group" style={{ marginBottom: 0 }}>
            <label>Search Opportunities</label>
            <input 
              type="text" 
              placeholder="Search by job title or keywords..." 
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
        </div>

        <div className="section-title" style={{ marginTop: '40px' }}>
          <h3>Open Positions ({filteredJobs.length})</h3>
        </div>

        {filteredJobs.length === 0 ? (
          <div className="card" style={{ textAlign: 'center', padding: '40px' }}>
            <p style={{ color: '#6b7280' }}>No public jobs found. If you just posted a job, try refreshing.</p>
          </div>
        ) : (
          <div className="job-grid" style={{ display: 'grid', gap: '20px' }}>
            {filteredJobs.map((job) => (
              <div key={job.id} className="card">
                <div className="card-header">
                  <h3 style={{ color: '#3461c7' }}>{job.title}</h3>
                  <span className="card-badge" style={{ background: '#ecfdf5', color: '#065f46' }}>
                    {job.employment_type}
                  </span>
                </div>
                <div className="profile-info" style={{ marginBottom: '20px' }}>
                   <div className="profile-field">
                      <span className="profile-field-label">Location</span>
                      <span className="profile-field-value">{job.location}</span>
                   </div>
                   <div className="profile-field">
                      <span className="profile-field-label">Salary</span>
                      <span className="profile-field-value">{job.salary_range || 'Not disclosed'}</span>
                   </div>
                </div>
                <p style={{ fontSize: '15px', color: '#4b5563', lineHeight: '1.6', marginBottom: '20px' }}>
                  {job.description}
                </p>
                <div style={{ borderTop: '1px solid #f3f4f6', paddingTop: '15px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '13px', color: '#9ca3af' }}>
                    Posted on: {new Date(job.posted_at).toLocaleDateString()}
                  </span>
                  {profile?.role === 'job_seeker' ? (
                    <button className="btn-upload" style={{ padding: '8px 24px' }} onClick={() => navigate(`/apply/${job.id}`)}>
                       Apply Now
                    </button>
                  ) : (
                    <span className="card-badge" style={{ background: '#f3f4f6', color: '#6b7280' }}>
                      Viewing as {profile?.role}
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </main>
    </div>
  );
}

export default JobBoard;
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { jobAPI, profileAPI, applicationAPI } from '../services/api';
import './Dashboard.css';

function JobBoard() {
  const [jobs, setJobs] = useState([]);
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState('All'); // NEW: Type Filter
  const [filterLocation, setFilterLocation] = useState('All'); // NEW: Location Filter
  const [error, setError] = useState('');
  const [appliedJobIds, setAppliedJobIds] = useState([]);
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
      setJobs(jobsRes.data);

      if (profileRes.data.role === 'job_seeker') {
         const appsRes = await applicationAPI.myApplications();
         const ids = appsRes.data.map(app => app.job_id);
         setAppliedJobIds(ids);
      }

    } catch (err) {
      console.error('Job Board fetch error:', err);
      setError('Failed to load jobs. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.clear();
    sessionStorage.clear();
    navigate('/login');
  };

  // --- NEW: ADVANCED FILTERING LOGIC ---
  const filteredJobs = jobs.filter(job => {
    // 1. Keyword Match
    const matchesSearch = job.title.toLowerCase().includes(searchTerm.toLowerCase()) || 
                          job.description.toLowerCase().includes(searchTerm.toLowerCase());
    
    // 2. Type Match (Full-time, Internship, etc.)
    const matchesType = filterType === 'All' || job.employment_type === filterType;
    
    // 3. Location Match (Remote vs On-Site)
    // Simple logic: if filter is "Remote", job location must contain "Remote"
    let matchesLocation = true;
    if (filterLocation === 'Remote') {
        matchesLocation = job.location.toLowerCase().includes('remote');
    } else if (filterLocation === 'On-site') {
        matchesLocation = !job.location.toLowerCase().includes('remote');
    }

    return matchesSearch && matchesType && matchesLocation;
  });

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
          {profile?.role === 'admin' && <a href="/admin">Admin Panel</a>}
        </div>
        <div className="nav-actions">
          <button className="btn-logout" onClick={handleLogout}>Sign Out</button>
        </div>
      </nav>

      <div className="page-hero">
        <div className="page-hero-inner">
          <h2>Job Board</h2>
          <p>Explore career opportunities in security and technology</p>
        </div>
      </div>

      <main className="app-content">
        {error && <div className="error-message">{error}</div>}

        {/* --- NEW: ADVANCED SEARCH & FILTER BAR --- */}
        <div className="card" style={{ display: 'flex', gap: '15px', flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div className="form-group" style={{ marginBottom: 0, flex: '2' }}>
            <label>Search Opportunities</label>
            <input 
              type="text" 
              placeholder="Keywords, skills, or titles..." 
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
          <div className="form-group" style={{ marginBottom: 0, flex: '1' }}>
            <label>Job Type</label>
            <select value={filterType} onChange={(e) => setFilterType(e.target.value)}>
              <option value="All">All Types</option>
              <option value="Full-time">Full-time</option>
              <option value="Part-time">Part-time</option>
              <option value="Internship">Internship</option>
              <option value="Contract">Contract</option>
            </select>
          </div>
          <div className="form-group" style={{ marginBottom: 0, flex: '1' }}>
            <label>Location</label>
            <select value={filterLocation} onChange={(e) => setFilterLocation(e.target.value)}>
              <option value="All">Anywhere</option>
              <option value="Remote">Remote Only</option>
              <option value="On-site">On-site Only</option>
            </select>
          </div>
        </div>

        <div className="section-title" style={{ marginTop: '40px' }}>
          <h3>Open Positions ({filteredJobs.length})</h3>
        </div>

        {filteredJobs.length === 0 ? (
          <div className="card" style={{ textAlign: 'center', padding: '40px' }}>
            <p style={{ color: '#6b7280' }}>No jobs found matching your filters.</p>
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
                    appliedJobIds.includes(job.id) ? (
                      <span className="card-badge" style={{ background: '#f3f4f6', color: '#6b7280' }}>
                        Already Applied
                      </span>
                    ) : (
                      <button className="btn-upload" style={{ padding: '8px 24px' }} onClick={() => navigate(`/apply/${job.id}`)}>
                        Apply Now
                      </button>
                    )
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
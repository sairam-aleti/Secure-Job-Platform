import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { jobAPI, profileAPI, applicationAPI } from '../services/api';
import { motion } from 'framer-motion';
import './Dashboard.css';

function JobBoard() {
  const [jobs, setJobs] = useState([]);
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState('All');
  const [filterLocation, setFilterLocation] = useState('All');
  const [sortBy, setSortBy] = useState('latest_jobs');
  const [error, setError] = useState('');
  const [appliedJobIds, setAppliedJobIds] = useState([]);
  const [currentPage, setCurrentPage] = useState(1);
  const jobsPerPage = 3;
  const navigate = useNavigate();

  useEffect(() => {
    setCurrentPage(1);
  }, [searchTerm, filterType, filterLocation]);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const profRes = await profileAPI.getProfile();
      setProfile(profRes.data);

      try {
        const jobsRes = await jobAPI.list();
        setJobs(jobsRes.data);
      } catch (e) {
        setError('Failed to load jobs. Please check your connection.');
      }

      if (profRes.data.role === 'job_seeker') {
        try {
          const appsRes = await applicationAPI.myApplications();
          setAppliedJobIds(appsRes.data.map(app => app.job_id));
        } catch (e) {
          console.error("Failed to load your applications:", e);
          // Don't set global error here so jobs still show up fine
        }
      }
    } catch (err) {
      setError('Initial load failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (dateString) => {
    if (!dateString) return '';
    const date = new Date(dateString);
    const day = String(date.getDate()).padStart(2, '0');
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const year = date.getFullYear();
    return `${day}/${month}/${year}`;
  };

  const handleLogout = () => {
    localStorage.clear();
    sessionStorage.clear();
    navigate('/login');
  };

  const filteredJobs = jobs.filter(job => {
    let parsedSkills = '';
    try {
      if (job.skills_required) parsedSkills = JSON.parse(job.skills_required).join(' ').toLowerCase();
    } catch (e) {
      parsedSkills = String(job.skills_required || '').toLowerCase();
    }

    const term = (searchTerm || '').toLowerCase();
    const matchesSearch =
      (job.title || '').toLowerCase().includes(term) ||
      (job.description || '').toLowerCase().includes(term) ||
      parsedSkills.includes(term);

    const matchesType = filterType === 'All' || job.employment_type === filterType;
    let matchesLocation = true;
    if (filterLocation === 'Remote') {
      matchesLocation = (job.location || '').toLowerCase().includes('remote');
    } else if (filterLocation === 'On-site') {
      matchesLocation = !(job.location || '').toLowerCase().includes('remote');
    }
    return matchesSearch && matchesType && matchesLocation;
  });

  filteredJobs.sort((a, b) => {
    if (sortBy === 'latest_jobs') {
      const dA = new Date(a.date_posted || 0);
      const dB = new Date(b.date_posted || 0);
      return dB - dA; // Latest first
    } else if (sortBy === 'deadline') {
      const dA = new Date(a.deadline || Number.MAX_SAFE_INTEGER);
      const dB = new Date(b.deadline || Number.MAX_SAFE_INTEGER);
      return dA - dB;
    } else if (sortBy === 'salary_high' || sortBy === 'salary_low') {
      const parseSal = (s) => parseInt((s || '0').split('-')[0].replace(/\D/g, ''), 10) || 0;
      const sA = parseSal(a.salary_range);
      const sB = parseSal(b.salary_range);
      return sortBy === 'salary_high' ? sB - sA : sA - sB;
    }
    return 0;
  });

  const totalPages = Math.ceil(filteredJobs.length / jobsPerPage);
  const currentJobs = filteredJobs.slice((currentPage - 1) * jobsPerPage, currentPage * jobsPerPage);

  if (loading) {
    return (
      <div className="app-layout">
        <div className="app-grid-bg"><div className="orb-1" /><div className="orb-2" /><div className="orb-3" /></div>
        <nav className="app-nav"><a href="/dashboard" className="nav-brand">Fort<span>Knox</span></a></nav>
        <main className="app-content">
          <p style={{ textAlign: 'center', color: 'var(--cy-text-mute)', marginTop: '80px', fontFamily: 'JetBrains Mono, monospace', fontSize: '13px' }}>Loading job board...</p>
        </main>
      </div>
    );
  }

  return (
    <div className="app-layout">


      <nav className="app-nav">
        <a href="/dashboard" className="nav-brand">Fort<span>Knox</span></a>
        <div className="nav-center">
          <a href="/dashboard">Dashboard</a>
          <a href="/jobs">Job Board</a>
          <a href="/profile">Profile</a>
          {profile?.role === 'admin' && <a href="/admin">Admin Panel</a>}
        </div>
        <div className="nav-actions">
          {profile && (
            <div style={{ display: 'flex', alignItems: 'center', marginRight: '16px' }}>
              <span style={{ color: 'var(--cy-text-mute)', fontSize: '10px', marginRight: '8px', fontFamily: 'JetBrains Mono, monospace', textTransform: 'uppercase', letterSpacing: '1px' }}>
                Welcome Back, {profile.full_name}
              </span>
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
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--cy-text-mute)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" /><circle cx="12" cy="7" r="4" /></svg>
                )}
              </div>
            </div>
          )}
          <button className="btn-logout" onClick={handleLogout}>Sign Out</button>
        </div>
      </nav>

      <div className="page-hero">
        <div className="page-hero-inner">
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '10px', color: 'var(--cy-brand)', textTransform: 'uppercase', letterSpacing: '2px', marginBottom: '12px' }}>JOB_LISTINGS</div>
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
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--cy-text-mute)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" /><circle cx="12" cy="7" r="4" /></svg>
              )}
            </div>
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <h2 style={{ margin: 0 }}>Job Board</h2>
              <p style={{ margin: 0, marginTop: '4px' }}>Explore career opportunities in security and technology</p>
            </div>
          </div>
        </div>
      </div>

      <main className="app-content">
        {error && <div className="error-message">{error}</div>}

        <motion.div className="card" style={{ display: 'flex', gap: '15px', flexWrap: 'wrap', alignItems: 'flex-end' }}
          initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }}
        >
          <div className="form-group" style={{ marginBottom: 0, flex: '2' }}>
            <label>Search Opportunities</label>
            <input type="text" placeholder="Keywords, skills, or titles..." value={searchTerm} onChange={(e) => setSearchTerm(e.target.value)} />
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
        </motion.div>

        <div className="section-title" style={{ marginTop: '40px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h3>Open Positions ({filteredJobs.length})</h3>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <select
              value={sortBy}
              onChange={(e) => { setSortBy(e.target.value); setCurrentPage(1); }}
              style={{
                background: 'rgba(10,102,194,0.08)', border: '1px dashed rgba(10,102,194,0.3)',
                color: 'var(--cy-brand)', padding: '6px 12px', fontSize: '11px', borderRadius: '4px',
                fontFamily: 'JetBrains Mono, monospace', outline: 'none', cursor: 'pointer',
                boxShadow: '0 0 8px rgba(10,102,194,0.15)'
              }}
            >
              <option value="latest_jobs">Latest Jobs</option>
              <option value="salary_high">Salary: High to Low</option>
              <option value="salary_low">Salary: Low to High</option>
              <option value="deadline">Application Deadline (Soonest)</option>
            </select>
          </div>
        </div>

        {filteredJobs.length === 0 ? (
          <div className="card" style={{ textAlign: 'center', padding: '40px' }}>
            <p style={{ color: 'var(--cy-text-mute)', fontFamily: 'JetBrains Mono, monospace', fontSize: '12px' }}>No jobs found matching your filters.</p>
          </div>
        ) : (
          <>
            <div style={{ display: 'grid', gap: '20px' }}>
              {currentJobs.map((job, i) => (
                <motion.div key={job.id} className="card"
                  initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}
                >
                  <div className="card-header">
                    <h3 style={{ color: 'var(--cy-brand)' }}>{job.title}</h3>
                    <span className="card-badge" style={{ background: 'rgba(5,150,105,0.08)', color: '#065f46', border: '1px dashed rgba(5,150,105,0.3)' }}>
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
                  <p style={{ fontSize: '14px', color: 'var(--cy-text-mute)', lineHeight: '1.7', marginBottom: '20px' }}>
                    {job.description}
                  </p>
                  <div style={{ borderTop: '1px dashed var(--cy-border)', paddingTop: '15px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <span style={{ fontSize: '11px', color: 'var(--cy-text-mute)', fontFamily: 'JetBrains Mono, monospace' }}>
                        Posted: {formatDate(job.posted_at)}
                      </span>
                      {job.deadline && (
                        <span style={{
                          fontSize: '11px', fontFamily: 'JetBrains Mono, monospace',
                          color: '#ffffff',
                          backgroundColor: '#dc2626',
                          padding: '4px 8px',
                          borderRadius: '4px',
                          boxShadow: '0 4px 6px rgba(220, 38, 38, 0.4)',
                          fontWeight: '600'
                        }}>
                          {new Date(job.deadline) < new Date()
                            ? `Deadline Passed: ${formatDate(job.deadline)}`
                            : `Deadline: ${formatDate(job.deadline)}`
                          }
                        </span>
                      )}
                    </div>

                    {profile?.role === 'job_seeker' ? (
                      appliedJobIds.includes(job.id) ? (
                        <span className="card-badge" style={{ background: 'var(--cy-bg-off)', color: 'var(--cy-text-mute)' }}>
                          Already Applied
                        </span>
                      ) : (job.deadline && new Date(job.deadline) < new Date()) ? (
                        <span className="card-badge" style={{ background: 'rgba(185,28,28,0.08)', color: '#991b1b', border: '1px dashed rgba(185,28,28,0.3)' }}>
                          Applications Closed
                        </span>
                      ) : (
                        <button className="btn-upload" style={{ padding: '8px 24px' }} onClick={() => navigate(`/apply/${job.id}`)}>
                          Apply Now
                        </button>
                      )
                    ) : (
                      <span className="card-badge" style={{ background: 'var(--cy-bg-off)', color: 'var(--cy-text-mute)' }}>
                        Viewing as {profile?.role}
                      </span>
                    )}
                  </div>
                </motion.div>
              ))}
            </div>

            {totalPages > 1 && (
              <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', marginTop: '32px', gap: '16px' }}>
                <button
                  className="btn-upload"
                  onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                  disabled={currentPage === 1}
                  style={{ opacity: currentPage === 1 ? 0.5 : 1, padding: '8px 16px', border: 'none', borderRadius: '4px' }}
                >
                  Previous
                </button>
                <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '13px', color: 'var(--cy-text-mute)' }}>
                  Page {currentPage} of {totalPages}
                </span>
                <button
                  className="btn-upload"
                  onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                  disabled={currentPage === totalPages}
                  style={{ opacity: currentPage === totalPages ? 0.5 : 1, padding: '8px 16px', border: 'none', borderRadius: '4px' }}
                >
                  Next
                </button>
              </div>
            )}
          </>
        )}
      </main>
    </div>
  );
}

export default JobBoard;
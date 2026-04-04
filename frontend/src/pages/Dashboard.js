import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { profileAPI, resumeAPI, jobAPI, applicationAPI, authAPI, connectionAPI, userAPI } from '../services/api'; 
import cryptoService from '../services/cryptoService'; 
import { motion } from 'framer-motion';
import './Dashboard.css';

const cardVariants = {
  hidden: { opacity: 0, y: 30 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.5 } }
};

function Dashboard() {
  const [profile, setProfile] = useState(null);
  const [resumes, setResumes] = useState([]);
  const [myJobs, setMyJobs] = useState([]);
  const [applications, setApplications] = useState([]); 
  const [pendingRequests, setPendingRequests] = useState([]); 
  const [connections, setConnections] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [file, setFile] = useState(null);
  const [uploadStatus, setUploadStatus] = useState('');
  const [recommendations, setRecommendations] = useState([]); 
  const [viewers, setViewers] = useState([]); 
  const [unreadCounts, setUnreadCounts] = useState({ dm: {}, groups: {}, total_dm: 0, total_groups: 0 });
  const navigate = useNavigate();
  const fileInputRef = useRef(null);

  const fetchResumes = useCallback(async () => {
    try {
      const response = await resumeAPI.list();
      setResumes(response.data);
    } catch (err) { console.error(err); }
  }, []);

  const fetchUserApplications = useCallback(async () => {
    try {
      const response = await applicationAPI.myApplications();
      setApplications(response.data);
    } catch (err) { console.error(err); }
  }, []);

  const fetchRecommendations = useCallback(async () => {
    try {
        const res = await jobAPI.getRecommendations();
        setRecommendations(res.data);
    } catch (err) { console.error(err); }
  }, []);

  const fetchMyJobs = useCallback(async () => {
    try {
      const response = await jobAPI.myJobs();
      setMyJobs(response.data);
    } catch (err) { console.error(err); }
  }, []);

  const fetchRecruiterApplications = useCallback(async () => {
    try {
      const response = await applicationAPI.recruiterApplications();
      setApplications(response.data);
    } catch (err) { console.error(err); }
  }, []);

  const fetchPendingRequests = useCallback(async () => {
    try {
      const response = await connectionAPI.getPending();
      setPendingRequests(response.data);
    } catch (err) { console.error(err); }
  }, []);

  const fetchMyConnections = useCallback(async () => {
    try {
      const res = await connectionAPI.getMyConnections();
      setConnections(res.data);
    } catch (err) { 
      console.error("Failed to fetch connections", err); 
    }
  }, []);
  
  const fetchProfileViewers = useCallback(async () => {
    try {
        const res = await userAPI.getViewers();
        setViewers(res.data);
    } catch (err) {
        console.error("Failed to fetch profile viewers", err);
    }
  }, []);

  const fetchUnreadCounts = useCallback(async () => {
    try {
      const { notificationAPI } = await import('../services/api');
      const res = await notificationAPI.getUnreadCounts();
      setUnreadCounts(res.data);
    } catch (err) { console.error("Failed to fetch notifications", err); }
  }, []);

  // ─────────────────────────────────────────────────────────────────────────────
  // setupEncryption — FALLBACK ONLY.
  //
  // The primary key setup now happens in Login.js → completeLogin(), where
  // derived_key is guaranteed to be available. This function only runs if:
  //   • The user somehow arrives at Dashboard without keys being set up
  //     (e.g. an old user account that predates the encryption feature, or
  //      a rare edge case where login key setup failed silently).
  //
  // It does NOT regenerate keys if they already exist in localStorage,
  // preventing unnecessary key churn on every Dashboard load.
  // ─────────────────────────────────────────────────────────────────────────────
  const setupEncryption = useCallback(async () => {
    const derivedKeyB64 = sessionStorage.getItem('derived_key');
    if (!derivedKeyB64) return; // derived_key gone (tab closed) — can't do anything here

    try {
      const existingEncryptedKey = localStorage.getItem('encrypted_private_key');

      if (existingEncryptedKey) {
        // Keys exist locally — make sure public key AND encrypted private key are in the backend.
        const privKey = cryptoService.decryptPrivateKey(existingEncryptedKey, derivedKeyB64);
        if (privKey) {
          const pubKey = cryptoService.getPublicKeyFromPrivate(privKey);
          await authAPI.updatePublicKey({ public_key: pubKey, encrypted_private_key: existingEncryptedKey });
        }
      } else {
        // Check if backend already has keys (e.g. logged in from another device)
        try {
          const profRes = await profileAPI.getProfile();
          if (profRes.data.encrypted_private_key) {
            localStorage.setItem('encrypted_private_key', profRes.data.encrypted_private_key);
            return; // Keys restored from server
          }
        } catch (e) { /* ignore */ }
        // Truly no keys anywhere — generate fresh
        const { publicKey, privateKey } = cryptoService.generateKeyPair();
        const encryptedPrivKey = cryptoService.encryptPrivateKey(privateKey, derivedKeyB64);
        localStorage.setItem('encrypted_private_key', encryptedPrivKey);
        await authAPI.updatePublicKey({ public_key: publicKey, encrypted_private_key: encryptedPrivKey });
      }
    } catch (err) {
      console.error('Dashboard fallback key setup failed:', err);
    }
  }, []);

  const fetchProfile = useCallback(async () => {
    try {
      // Step 1: Get critical profile data first
      const response = await profileAPI.getProfile();
      const userData = response.data;
      setProfile(userData);

      // Step 2: Prepare a list of all secondary data fetches
      const promises = [];

      // ── KEY SYNC ──────────────────────────────────────────────────────────
      // ALWAYS sync encryption keys on dashboard load so the public key is
      // always available in the backend for other users to encrypt DMs.
      const derivedKeyB64 = sessionStorage.getItem('derived_key');
      if (derivedKeyB64) {
        promises.push(setupEncryption());
      }
      // ─────────────────────────────────────────────────────────────────────
      
      if (userData.role === 'job_seeker') {
        promises.push(fetchResumes());
        promises.push(fetchUserApplications()); 
        promises.push(fetchRecommendations());
      } else if (userData.role === 'recruiter') {
        promises.push(fetchMyJobs());
        promises.push(fetchRecruiterApplications()); 
        promises.push(fetchPendingRequests()); 
      }

      if (userData.role !== 'admin' && userData.role !== 'superadmin') {
        promises.push(fetchMyConnections());
        promises.push(fetchProfileViewers()); 
      }

      // Step 3: Run all fetches in parallel
      // We use a small timeout to ensure the overlay stays at least 800ms for "polish" 
      // but no more than 1.5s total if data is fast.
      promises.push(fetchUnreadCounts());
      
      const minDisplayTime = new Promise(resolve => setTimeout(resolve, 1000));
      await Promise.all([...promises, minDisplayTime]);

    } catch (err) {
      if (err.response?.status === 403 && err.response?.data?.detail === 'Account suspended') {
        setError('Your account has been suspended by an administrator. Please contact support.');
      } else if (err.response?.status === 401) {
        localStorage.clear();
        navigate('/login');
      } else {
        setError('Failed to load profile');
      }
    } finally {
      setLoading(false);
    }
  }, [navigate, fetchResumes, fetchUserApplications, fetchRecommendations, fetchMyJobs, fetchRecruiterApplications, fetchPendingRequests, fetchMyConnections, fetchProfileViewers, setupEncryption, fetchUnreadCounts]);

  useEffect(() => {
    const token = localStorage.getItem('access_token');
    if (!token) {
      navigate('/login');
      return;
    }
    fetchProfile();

    const interval = setInterval(fetchUnreadCounts, 10000);
    return () => clearInterval(interval);
  }, [navigate, fetchProfile, fetchUnreadCounts]);

  const handleLogout = () => {
    localStorage.clear();
    sessionStorage.clear();
    navigate('/login');
  };

  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
  };

  const handleUpload = async () => {
    if (resumes.length > 0) {
      setUploadStatus('Please remove your current resume before uploading a new one.');
      return;
    }
    if (!file) {
      setUploadStatus('Please select a file');
      return;
    }
    const formData = new FormData();
    formData.append('file', file);
    try {
      setUploadStatus('Uploading and parsing...');
      await resumeAPI.upload(formData);
      setUploadStatus('Resume uploaded successfully!');
      setFile(null);
      if (fileInputRef.current) fileInputRef.current.value = '';
      fetchResumes();
      fetchRecommendations();
    } catch (err) {
      let errorMsg = 'Upload failed';
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
      setUploadStatus(errorMsg);
    }
  };

  const handleDeleteResume = async (resumeId) => {
    if (!window.confirm('Are you sure you want to PERMANENTLY delete this resume?')) return;
    try {
      await resumeAPI.delete(resumeId);
      setUploadStatus('Resume deleted.');
      setFile(null);
      if (fileInputRef.current) fileInputRef.current.value = '';
      fetchResumes();
    } catch (err) {
      alert('Failed to delete resume.');
    }
  };

  const handleDownload = async (resumeId, filename) => {
    try {
      const response = await resumeAPI.download(resumeId);
      const blob = new Blob([response.data]);
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      alert('Download failed: Not authorized or file error.');
    }
  };


  return (
    <div className="app-layout">
      {loading && (
        <motion.div 
          className="system-initializing-overlay"
          initial={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.8 }}
        >
          <div className="init-scanner"></div>
          <div className="init-text">Verifying Secure Session</div>
          <div className="init-status">Auditing data integrity & encryption keys...</div>
          <div className="init-progress-bar">
            <div className="init-progress-fill"></div>
          </div>
        </motion.div>
      )}

      <div className="app-grid-bg"></div>

      <nav className="app-nav">
        <a href="/dashboard" className="nav-brand">Fort<span>Knox</span></a>
        <div className="nav-center">
          <a href="/dashboard">Dashboard</a>
          {profile?.role !== 'admin' && profile?.role !== 'superadmin' && <a href="/network">Network</a>}
          {profile?.role !== 'admin' && profile?.role !== 'superadmin' && <a href="/jobs">Job Board</a>}
          {(profile?.role === 'job_seeker' || profile?.role === 'recruiter') && <a href="/profile">Profile</a>}
          {(profile?.role === 'admin' || profile?.role === 'superadmin') && <a href="/admin">Admin Panel</a>}
        </div>
        <div className="nav-actions">
          <button className="btn-logout" onClick={handleLogout}>Sign Out</button>
        </div>
      </nav>

      <div className="page-hero">
        <div className="page-hero-inner">
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '10px', color: 'var(--cy-brand)', textTransform: 'uppercase', letterSpacing: '2px', marginBottom: '12px' }}>DASHBOARD_PANEL</div>
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
              <h2 style={{ margin: 0 }}>Welcome back, {profile?.full_name}</h2>
              <p style={{ margin: 0, marginTop: '4px' }}>
                {profile?.role === 'recruiter' 
                  ? 'Manage your company and job postings' 
                  : (profile?.role === 'admin' || profile?.role === 'superadmin')
                    ? 'Platform Administration & Auditing' 
                    : 'Track your applications and resume'}
              </p>
            </div>
          </div>
        </div>
      </div>

      <main className="app-content">
        <motion.div className="stats-row" initial="hidden" animate="visible" variants={{ visible: { transition: { staggerChildren: 0.1 } } }}>
          <motion.div className="stat-item" variants={cardVariants}>
            <div className="stat-label">Email</div>
            <div className="stat-value" style={{ fontSize: '14px', wordBreak: 'break-all' }}>
              {profile?.email}
            </div>
          </motion.div>
          <motion.div className="stat-item" variants={cardVariants}>
            <div className="stat-label">Role</div>
            <div className="stat-value" style={{ textTransform: 'capitalize' }}>
              {profile?.role?.replace('_', ' ')}
            </div>
          </motion.div>
          <motion.div className="stat-item" variants={cardVariants}>
            <div className="stat-label">Status</div>
            <div className="stat-value" style={{ fontSize: '15px', color: profile?.is_verified ? '#059669' : '#d97706' }}>
              {profile?.is_verified ? '✓ Verified' : '○ Pending'}
            </div>
          </motion.div>
        </motion.div>

        {/* --- RECRUITER VIEW --- */}
        {profile?.role === 'recruiter' && (
          <>
            {pendingRequests.length > 0 && (
              <motion.div className="card" style={{ borderLeft: '3px solid #f59e0b' }} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}>
                <div className="card-header">
                  <h3>Connection Requests</h3>
                  <span className="card-badge" style={{ background: 'rgba(245,158,11,0.1)', color: '#92400e', border: '1px dashed rgba(245,158,11,0.3)' }}>New Requests</span>
                </div>
                <ul className="resume-list">
                  {pendingRequests.map((req) => (
                    <li key={req.request_id} className="resume-item">
                      <div className="resume-info">
                        <div className="resume-details">
                          <span className="resume-name">{req.name}</span>
                          <span className="resume-meta">{req.email}</span>
                        </div>
                      </div>
                      <div style={{ display: 'flex', gap: '10px' }}>
                        <button className="btn-activate" onClick={async () => {
                          await connectionAPI.updateRequest(req.request_id, 'accepted');
                          fetchPendingRequests();
                          fetchMyConnections();
                        }}>Accept</button>
                        <button className="btn-delete" onClick={async () => {
                          await connectionAPI.updateRequest(req.request_id, 'rejected');
                          fetchPendingRequests();
                        }}>Decline</button>
                      </div>
                    </li>
                  ))}
                </ul>
              </motion.div>
            )}

            <motion.div className="card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }}>
              <div className="card-header">
                <h3>Quick Actions</h3>
              </div>
              <div style={{ display: 'flex', gap: '16px', padding: '10px 0' }}>
                <button className="btn-upload" onClick={() => navigate('/create-company')}>Create Company Page</button>
                <button className="btn-upload" onClick={() => navigate('/post-job')}>Post a Job</button>
              </div>
            </motion.div>

            <motion.div className="card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.5 }}>
              <div className="card-header">
                <h3>Your Active Job Postings</h3>
                <span className="card-badge" style={{ background: 'rgba(10,102,194,0.08)', color: 'var(--cy-brand)' }}>{myJobs.length} Active</span>
              </div>
              {myJobs.length === 0 ? (
                <p style={{ color: 'var(--cy-text-mute)', textAlign: 'center', padding: '24px 0', fontFamily: 'JetBrains Mono, monospace', fontSize: '12px' }}>No jobs posted yet.</p>
              ) : (
                <ul className="resume-list">
                  {myJobs.map((job) => (
                    <li key={job.id} className="resume-item">
                      <div className="resume-info">
                        <div className="resume-details">
                          <span className="resume-name">{job.title}</span>
                          <span className="resume-meta">{job.employment_type} • {job.location}</span>
                        </div>
                      </div>
                      <div style={{ display: 'flex', gap: '8px' }}>
                        <button 
                          className="download-btn"
                          style={{ padding: '4px 12px', fontSize: '11px' }}
                          onClick={() => navigate(`/post-job?edit=${job.id}`)}
                        >
                          Edit
                        </button>
                        <button 
                          className="btn-logout"
                          style={{ padding: '4px 12px', fontSize: '11px', background: '#dc2626', color: 'white', border: 'none' }}
                          onClick={async () => {
                            if (window.confirm(`Delete "${job.title}"? This cannot be undone.`)) {
                              try {
                                await jobAPI.delete(job.id);
                                setMyJobs(prev => prev.filter(j => j.id !== job.id));
                              } catch (err) {
                                alert(err.response?.data?.detail || 'Failed to delete job');
                              }
                            }
                          }}
                        >
                          Delete
                        </button>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </motion.div>

            {applications.length > 0 && (
              <motion.div className="card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.6 }}>
                <div className="card-header">
                  <h3>Received Applications</h3>
                  <span className="card-badge" style={{ background: 'rgba(10,102,194,0.08)', color: 'var(--cy-brand)' }}>
                    {applications.length} Total
                  </span>
                </div>
                <ul className="resume-list">
                  {applications.map((app) => (
                    <li key={app.id} className="resume-item" style={{ flexDirection: 'column', alignItems: 'flex-start' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', width: '100%', marginBottom: '15px' }}>
                        <div className="resume-info">
                          <div className="resume-details">
                            <span className="resume-name">
                                {app.applicant_name}
                                <span className="card-badge" style={{ marginLeft: '10px', background: app.match_score > 70 ? 'rgba(5,150,105,0.1)' : 'rgba(245,158,11,0.1)', color: app.match_score > 70 ? '#065f46' : '#9a3412' }}>
                                    {app.match_score !== undefined ? app.match_score : 0}% Match
                                </span>
                            </span>
                            <div className="resume-meta">
                              <span>Position: {app.job_title}</span>
                              <span>Applied: {new Date(app.applied_at).toLocaleDateString('en-GB')}</span>
                            </div>
                          </div>
                        </div>
                        
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                          <span style={{ fontSize: '10px', color: 'var(--cy-text-mute)', fontWeight: '700', fontFamily: 'JetBrains Mono, monospace', textTransform: 'uppercase', letterSpacing: '1px' }}>Status:</span>
                          <select 
                            className="status-badge"
                            style={{ padding: '6px 12px', borderRadius: '4px', border: '1px dashed var(--cy-border)', background: 'rgba(255,255,255,0.4)', fontSize: '12px', cursor: 'pointer', fontFamily: 'Space Grotesk, sans-serif', fontWeight: '600' }}
                            value={app.status} 
                            onChange={async (e) => {
                              try {
                                await applicationAPI.updateStatus(app.id, e.target.value);
                                fetchRecruiterApplications();
                              } catch (err) { alert("Failed to update status."); }
                            }}
                          >
                            <option value="Applied">Applied</option>
                            <option value="Reviewed">Reviewed</option>
                            <option value="Interview">Interview</option>
                            <option value="Offer">Offer</option>
                            <option value="Rejected">Rejected</option>
                          </select>
                        </div>
                      </div>

                      {/* Recruiter Notes */}
                      <div style={{ width: '100%', marginBottom: '10px' }}>
                        <label style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '9px', color: 'var(--cy-text-mute)', textTransform: 'uppercase', letterSpacing: '1px', display: 'block', marginBottom: '4px' }}>Recruiter Notes</label>
                        <input 
                          type="text" 
                          placeholder="Add private notes about this candidate..."
                          defaultValue={app.recruiter_notes || ''}
                          onBlur={async (e) => {
                            const newNotes = e.target.value;
                            if (newNotes !== (app.recruiter_notes || '')) {
                              try {
                                await applicationAPI.updateNotes(app.id, newNotes);
                              } catch (err) { console.error('Notes save failed'); }
                            }
                          }}
                          style={{ 
                            width: '100%', padding: '8px 12px', borderRadius: '6px',
                            border: '1px dashed var(--cy-border)', background: 'rgba(255,255,255,0.3)',
                            fontSize: '12px', fontFamily: 'Inter, sans-serif', color: 'var(--cy-text-main)',
                            outline: 'none', boxSizing: 'border-box'
                          }}
                        />
                      </div>

                      <div style={{ display: 'flex', gap: '10px', width: '100%' }}>
                        <button className="download-btn" onClick={() => handleDownload(app.resume_id, `Resume_${app.applicant_name}.pdf`)}>View Resume</button>
                        <button className="download-btn" onClick={() => navigate(`/chat/${app.applicant_id}`)}>Chat</button>
                      </div>
                    </li>
                  ))}
                </ul>
              </motion.div>
            )}
          </>
        )}

        {/* --- JOB SEEKER VIEW --- */}
        {profile?.role === 'job_seeker' && (
          <>
            {recommendations.length > 0 && (
              <motion.div className="card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}>
                <div className="card-header">
                  <h3>Recommended for You</h3>
                  <span className="card-badge" style={{ background: 'rgba(10,102,194,0.08)', color: 'var(--cy-brand)' }}>Intelligent Matching</span>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '20px', marginTop: '10px' }}>
                  {recommendations.map((job) => (
                    <motion.div key={job.job_id} className="stat-item" style={{ cursor: 'pointer' }} onClick={() => navigate(`/apply/${job.job_id}`)} whileHover={{ scale: 1.02, boxShadow: '0 16px 48px rgba(10,102,194,0.15)' }}>
                      <div className="stat-label" style={{ color: '#059669' }}>{job.match_score}% Match</div>
                      <div className="stat-value" style={{ fontSize: '16px', marginBottom: '5px' }}>{job.title}</div>
                      <div style={{ fontSize: '12px', color: 'var(--cy-text-mute)', fontFamily: 'JetBrains Mono, monospace' }}>{job.company} • {job.location}</div>
                    </motion.div>
                  ))}
                </div>
              </motion.div>
            )}

            <motion.div className="card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }}>
              <div className="card-header"><h3>Profile Summary</h3></div>
              <div className="profile-info">
                <div className="profile-field">
                  <span className="profile-field-label">Headline</span>
                  <span className={`profile-field-value ${!profile?.headline ? 'empty' : ''}`}>{profile?.headline || 'Not set'}</span>
                </div>
                <div className="profile-field">
                  <span className="profile-field-label">Skills</span>
                  <span className={`profile-field-value ${!profile?.skills ? 'empty' : ''}`}>{profile?.skills || 'Not set'}</span>
                </div>
              </div>
            </motion.div>

            <motion.div className="card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.5 }}>
              <div className="card-header"><h3>Upload Resume</h3></div>
              <div className="upload-area">
                <p>{resumes.length > 0 ? "You already have a resume uploaded. Remove it to upload a new one." : "Select your resume to upload securely"}</p>
                <input 
                  type="file" 
                  accept=".pdf,.docx" 
                  onChange={handleFileChange} 
                  disabled={resumes.length > 0} 
                  ref={fileInputRef}
                />
              </div>
              <button 
                className="btn-upload" 
                onClick={handleUpload} 
                disabled={resumes.length > 0}
                style={{ opacity: resumes.length > 0 ? 0.5 : 1, cursor: resumes.length > 0 ? 'not-allowed' : 'pointer' }}
              >
                {resumes.length > 0 ? 'Resume Already Exists' : 'Upload & Encrypt'}
              </button>
              {uploadStatus && <p className="upload-status" style={{ color: uploadStatus.includes('successfully') || uploadStatus.includes('deleted') ? '#059669' : '#dc2626' }}>{uploadStatus}</p>}
            </motion.div>

            <motion.div className="card" style={{ marginTop: '20px' }} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.6 }}>
              <div className="card-header">
                <h3>Your Resumes</h3>
                <span className="card-badge" style={{ background: 'rgba(5,150,105,0.08)', color: '#065f46' }}>{resumes.length} file{resumes.length !== 1 ? 's' : ''}</span>
              </div>
              {resumes.length === 0 ? (
                <p style={{ color: 'var(--cy-text-mute)', textAlign: 'center', padding: '24px 0', fontFamily: 'JetBrains Mono, monospace', fontSize: '12px' }}>No resumes uploaded yet.</p>
              ) : (
                <ul className="resume-list">
                  {resumes.map((resume) => (
                    <li key={resume.id} className="resume-item">
                      <div className="resume-info">
                        <div className="resume-icon">📄</div>
                        <div className="resume-details">
                          <span className="resume-name">{resume.original_filename}</span>
                          <div className="resume-meta">
                            <span className="resume-size">{(resume.file_size / 1024).toFixed(1)} KB</span>
                            <span className="resume-date">{new Date(resume.uploaded_at).toLocaleDateString('en-GB')}</span>
                          </div>
                        </div>
                      </div>
                      <div style={{ display: 'flex', gap: '8px' }}>
                        <button className="download-btn" onClick={() => handleDownload(resume.id, resume.original_filename)}>
                          Download
                        </button>
                        <button className="btn-delete" onClick={() => handleDeleteResume(resume.id)} style={{ padding: '6px 12px', fontSize: '11px' }}>
                          Remove
                        </button>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </motion.div>

            {applications.length > 0 && (
              <motion.div className="card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.7 }}>
                <div className="card-header"><h3>Your Applications</h3></div>
                <ul className="resume-list">
                  {applications.map((app) => (
                    <li key={app.id} className="resume-item">
                      <div className="resume-details">
                        <span className="resume-name">{app.job_title}</span>
                        <span className="resume-meta">Status: <span className={`status-badge ${app.status.toLowerCase()}`} style={{ marginLeft: '4px' }}>{app.status}</span></span>
                      </div>
                      <div style={{ display: 'flex', gap: '8px' }}>
                        <button 
                          className="download-btn" 
                          style={{ position: 'relative' }}
                          onClick={() => app.recruiter_id && navigate(`/chat/${app.recruiter_id}`)}
                          disabled={!app.recruiter_id}
                        >
                          Chat with Recruiter
                          {app.recruiter_id && unreadCounts.dm[app.recruiter_id] > 0 && (
                            <span className="badge-count">{unreadCounts.dm[app.recruiter_id]}</span>
                          )}
                        </button>
                        
                        <button 
                          className="btn-upload" 
                          style={{ position: 'relative', padding: '6px 16px', fontSize: '11px', width: 'auto' }}
                          onClick={() => navigate(`/chat/groups`)}
                        >
                          Group Channels
                          {unreadCounts.total_groups > 0 && (
                            <span className="badge-count">{unreadCounts.total_groups}</span>
                          )}
                        </button>
                      </div>
                    </li>
                  ))}
                </ul>
              </motion.div>
            )}
          </>
        )}

        {/* --- RECENT VIEWERS SECTION --- */}
        {profile?.role !== 'admin' && profile?.role !== 'superadmin' && (
          <motion.div className="card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.8 }}>
            <div className="card-header">
              <h3>Recent Profile Viewers</h3>
              <span className="card-badge" style={{ background: 'var(--cy-bg-off)', color: 'var(--cy-text-mute)' }}>Last 5 visits</span>
            </div>
            {viewers.length === 0 ? (
              <p style={{ color: 'var(--cy-text-mute)', textAlign: 'center', padding: '24px 0', fontFamily: 'JetBrains Mono, monospace', fontSize: '12px' }}>No recent views recorded.</p>
            ) : (
              <ul className="resume-list">
                {viewers.map((viewer, index) => (
                  <li key={index} className="resume-item">
                    <div className="resume-info">
                      <span className="resume-name">{viewer.viewer_name}</span>
                      <span className="resume-meta">Viewed on: {new Date(viewer.timestamp).toLocaleString('en-GB')}</span>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </motion.div>
        )}

        {/* --- YOUR NETWORK SECTION WITH REMOVE BUTTON --- */}
        {profile?.role !== 'admin' && profile?.role !== 'superadmin' && (
          <motion.div className="card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.9 }}>
            <div className="card-header">
              <h3>Your Network</h3>
              <span className="card-badge" style={{ background: 'rgba(10,102,194,0.08)', color: 'var(--cy-brand)' }}>
                {connections.length} Professional{connections.length !== 1 ? 's' : ''}
              </span>
            </div>
            {connections.length === 0 ? (
              <p style={{ color: 'var(--cy-text-mute)', textAlign: 'center', padding: '24px 0', fontFamily: 'JetBrains Mono, monospace', fontSize: '12px' }}>
                No active connections. Visit the Network tab to find professionals.
              </p>
            ) : (
              <ul className="resume-list">
                {connections.map((conn) => (
                  <li key={conn.id} className="resume-item">
                    <div className="resume-info">
                      <div className="resume-details">
                        <span className="resume-name">{conn.full_name}</span>
                        <span className="resume-meta" style={{ textTransform: 'capitalize' }}>
                          {conn.role.replace('_', ' ')} • {conn.headline || 'Professional Member'}
                        </span>
                      </div>
                    </div>
                    <div style={{ display: 'flex', gap: '10px' }}>
                      <button 
                        className="download-btn" 
                        onClick={() => navigate(`/chat/${conn.id}`)}
                      >
                        Message
                      </button>
                      
                      <button 
                        className="btn-delete" 
                        onClick={async () => {
                          if(window.confirm(`Are you sure you want to remove ${conn.full_name} from your network?`)) {
                             try {
                               await connectionAPI.updateRequest(conn.request_id, 'rejected');
                               fetchMyConnections();
                             } catch (err) {
                               alert('Failed to remove connection.');
                             }
                          }
                        }}
                      >
                        Remove
                      </button>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </motion.div>
        )}

        {error && <div className="error-message">{error}</div>}
      </main>
    </div>
  );
}

export default Dashboard;


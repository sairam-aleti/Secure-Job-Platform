import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { profileAPI, resumeAPI, jobAPI, applicationAPI, authAPI, connectionAPI, userAPI, companyAPI, adminAPI } from '../services/api';
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
  const [companies, setCompanies] = useState([]);
  const [filterCompanyId, setFilterCompanyId] = useState('all');
  const [unreadCounts, setUnreadCounts] = useState({ dm: {}, groups: {}, total_dm: 0, total_groups: 0 });
  const [platformStats, setPlatformStats] = useState(null);
  const [recentActivity, setRecentActivity] = useState([]);
  const [lastLogin, setLastLogin] = useState(null);
  const [sessionWarning, setSessionWarning] = useState(false);

  const [sessionExtended, setSessionExtended] = useState(false);
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

  const fetchPlatformStats = useCallback(async () => {
    try {
      const res = await adminAPI.getStats();
      setPlatformStats(res.data);
    } catch (err) { console.error("Failed to fetch platform stats", err); }
  }, []);


  const formatAction = (action) => {
    const map = {
      'LOGIN_SUCCESS': 'Signed in successfully',
      'SESSION_REPLACED': 'Session replaced',
      'ADMIN_APPROVED': 'Admin was approved',
      'USER_SUSPENDED': 'User suspended',
      'ADMIN_STATS_CHECK': 'System statistics checked',
      'LOGIN_FAILURE': 'Login attempt failed',
      'MEMBER_ADDED': 'Member added to group',
      'JOB_POSTED': 'New job posted'
    };
    if (map[action]) return map[action];
    return action.split('_').map((w, i) => i === 0 ? w.charAt(0).toUpperCase() + w.slice(1).toLowerCase() : w.toLowerCase()).join(' ');
  };

  const fetchRecentActivity = useCallback(async () => {

    try {
      const res = await profileAPI.getRecentActivity();
      setRecentActivity(res.data);
    } catch (err) { console.error("Failed to fetch recent activity", err); }
  }, []);

  const fetchLastLogin = useCallback(async () => {
    try {
      const res = await profileAPI.getLastLogin();
      setLastLogin(res.data.last_login);
    } catch (err) { console.error("Failed to fetch last login", err); }
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
        promises.push(companyAPI.list().then(res => setCompanies(res.data.filter(c => c.recruiter_id === userData.id))).catch(console.error));
      }

      if (userData.role !== 'admin' && userData.role !== 'superadmin') {
        promises.push(fetchMyConnections());
        promises.push(fetchProfileViewers());
      } else {
        // Admin/Superadmin exclusive dashboard data
        promises.push(fetchPlatformStats());
        promises.push(fetchRecentActivity());
        promises.push(fetchLastLogin());
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

    // Session Watchdog
    const checkSession = () => {
      const tk = localStorage.getItem('access_token');
      if (!tk) return;
      try {
        const payload = JSON.parse(atob(tk.split('.')[1]));
        const timeLeftMs = (payload.exp * 1000) - Date.now();
        if (timeLeftMs > 0 && timeLeftMs <= 5 * 60 * 1000) {
          if (!sessionExtended) setSessionWarning(true);
        } else if (timeLeftMs <= 0) {
          if (!sessionExtended) {
            localStorage.clear(); sessionStorage.clear(); navigate('/login');
          }
        }
      } catch (e) { }
    };
    const sessionInterval = setInterval(checkSession, 15000);

    return () => { clearInterval(interval); clearInterval(sessionInterval); };
  }, [navigate, fetchProfile, fetchUnreadCounts, sessionExtended]);

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


  const activeSearchFilterJobs = myJobs || [];
  const filteredActiveJobs = activeSearchFilterJobs.filter(job => filterCompanyId === 'all' || job.company_id === parseInt(filterCompanyId));
  const groupedJobs = {};
  filteredActiveJobs.forEach(job => {
    const comp = companies.find(c => c.id === job.company_id);
    const compName = comp ? comp.name : `Company #${job.company_id}`;
    if (!groupedJobs[compName]) groupedJobs[compName] = [];
    groupedJobs[compName].push(job);
  });

  return (
    <div className="app-layout">
      {sessionWarning && (
        <div style={{ position: 'fixed', top: '20px', left: '50%', transform: 'translateX(-50%)', zIndex: 9999, background: '#dc2626', color: 'white', padding: '16px 24px', borderRadius: '8px', boxShadow: '0 8px 32px rgba(220, 38, 38, 0.4)', display: 'flex', alignItems: 'center', gap: '16px', fontFamily: 'Inter, sans-serif' }}>
          <span style={{ fontWeight: 500 }}>Your session will expire in 5 minutes. Stay logged in?</span>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button onClick={async () => {
              try {
                const res = await authAPI.refresh();
                localStorage.setItem('access_token', res.data.access_token);
                setSessionWarning(false);
                setSessionExtended(true);
                fetchProfile();
              } catch (err) {
                alert("Session refresh failed. Please log in again.");
                handleLogout();
              }
            }} style={{ background: 'white', color: '#dc2626', border: 'none', padding: '6px 16px', borderRadius: '4px', cursor: 'pointer', fontWeight: 'bold' }}>Yes</button>
            <button onClick={handleLogout} style={{ background: 'transparent', color: 'white', border: '1px solid white', padding: '6px 16px', borderRadius: '4px', cursor: 'pointer' }}>No</button>
          </div>
        </div>
      )}

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
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--cy-text-mute)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" /><circle cx="12" cy="7" r="4" /></svg>
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
        {(profile?.role === 'admin' || profile?.role === 'superadmin') ? (
          /* --- ADMIN/SUPERADMIN REDESIGNED CARDS --- */
          <motion.div initial="hidden" animate="visible" variants={{ visible: { transition: { staggerChildren: 0.1 } } }}>
            {/* PLATFORM USERS & PLATFORM ACTIVITY - NOW VERTICAL STACK */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', marginBottom: '20px' }}>
              <motion.div className="metric-card" variants={cardVariants} style={{ marginBottom: 0 }}>

                <h4>Platform Users</h4>
                <div className="metric-grid metric-grid-4">
                  <div className="metric-tile">
                    <span className="metric-tile-label">Total Users</span>
                    <span className="metric-tile-value">{platformStats?.total_users || 0}</span>
                  </div>
                  <div className="metric-tile">
                    <span className="metric-tile-label">Job Seekers</span>
                    <span className="metric-tile-value accent-blue">{platformStats?.job_seekers || 0}</span>
                  </div>
                  <div className="metric-tile">
                    <span className="metric-tile-label">Recruiters</span>
                    <span className="metric-tile-value accent-amber">{platformStats?.recruiters || 0}</span>
                  </div>
                  <div className="metric-tile">
                    <span className="metric-tile-label">Admins</span>
                    <span className="metric-tile-value accent-red">{platformStats?.admins || 0}</span>
                  </div>
                </div>
              </motion.div>

              <motion.div className="metric-card" variants={cardVariants} style={{ marginBottom: 0 }}>
                <h4>Platform Activity</h4>

                <div className="metric-grid metric-grid-3">
                  <div className="metric-tile">
                    <span className="metric-tile-label">Jobs Posted</span>
                    <span className="metric-tile-value accent-blue">{platformStats?.jobs_posted || 0}</span>
                  </div>
                  <div className="metric-tile">
                    <span className="metric-tile-label">Applications</span>
                    <span className="metric-tile-value accent-amber">{platformStats?.applications || 0}</span>
                  </div>
                  <div className="metric-tile">
                    <span className="metric-tile-label">Pending Requests</span>
                    <span className="metric-tile-value" style={{ color: (platformStats?.pending_requests > 0) ? '#dc2626' : '#059669' }}>
                      {platformStats?.pending_requests || 0}
                    </span>
                  </div>
                </div>
              </motion.div>
            </div>

            {/* ACCOUNT INFO & RECENT ACTIVITY ROW - ALIGN TOP/BOTTOM */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', alignItems: 'stretch' }}>
              <motion.div className="metric-card" variants={cardVariants} style={{ marginBottom: 0, height: '100%' }}>

                <h4>Account Info</h4>
                <div className="account-info-list" style={{ marginTop: '12px' }}>
                  <div className="account-info-row">
                    <span className="info-label">Email</span>
                    <span className="info-value">{profile?.email}</span>
                  </div>
                  <div className="account-info-row">
                    <span className="info-label">Role</span>
                    <span className={`role-badge role-${profile?.role}`} style={{ fontSize: '11px' }}>{profile?.role}</span>
                  </div>
                  <div className="account-info-row">
                    <span className="info-label">Status</span>
                    <span className="status-badge verified" style={{ background: 'rgba(5,150,105,0.08)', color: '#059669', border: '1px dashed rgba(5,150,105,0.3)', padding: '4px 10px' }}>Verified</span>
                  </div>
                  <div className="account-info-row">
                    <span className="info-label">Last Login</span>
                    <span className="info-value" style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '12px' }}>
                      {lastLogin ? new Date(lastLogin).toLocaleString('en-GB', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'First Session'}
                    </span>
                  </div>
                </div>
              </motion.div>

              <motion.div className="metric-card" variants={cardVariants} style={{ marginBottom: 0, height: '100%' }}>
                <h4>Recent Activity</h4>

                <div className="activity-list">
                  {recentActivity.length === 0 ? (
                    <p style={{ color: 'var(--cy-text-mute)', fontSize: '12px', fontFamily: 'Inter, sans-serif' }}>No recent activity found.</p>
                  ) : (
                    recentActivity.map((log, idx) => (
                      <div key={log.id} className="activity-item">
                        <div className="activity-dot" style={{ background: idx === 0 ? '#059669' : idx === 1 ? '#0a66c2' : '#d97706' }}></div>
                        <div className="activity-info">
                          <span style={{ fontWeight: 500, fontSize: '13px' }}>{formatAction(log.action)}</span>
                          <span className="activity-time">
                            {new Date(log.timestamp).toLocaleDateString() === new Date().toLocaleDateString() ? 'Today' : new Date(log.timestamp).toLocaleDateString('en-GB', { day: '2-digit', month: 'short' })}, {new Date(log.timestamp).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })}
                          </span>
                        </div>
                      </div>
                    ))
                  )}
                </div>

              </motion.div>
            </div>
          </motion.div>
        ) : (
          /* --- ORIGINAL STATS ROW (Job Seekers & Recruiters) --- */
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
        )}


        {/* --- RECRUITER VIEW --- */}
        {profile?.role === 'recruiter' && (
          <>
            <motion.div className="card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }}>
              <div className="card-header">
                <h3>Quick Actions</h3>
              </div>
              <div style={{ display: 'flex', gap: '16px', padding: '10px 0' }}>
                <button className="btn-upload" onClick={() => navigate('/create-company')}>Create Company Page</button>
                <button className="btn-upload" onClick={() => navigate('/post-job')}>Post a Job</button>
              </div>
            </motion.div>

            {companies.length > 0 && (
              <motion.div className="card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.45 }}>
                <div className="card-header">
                  <h3>Your Company Pages</h3>
                  <span className="card-badge" style={{ background: 'rgba(5,150,105,0.1)', color: '#065f46', border: '1px dashed rgba(5,150,105,0.3)' }}>{companies.length}/3 Pages</span>
                </div>
                <ul className="resume-list" style={{ maxHeight: '420px', overflowY: 'auto', paddingRight: '8px' }}>
                  {companies.map(comp => (
                    <li key={comp.id} className="resume-item" style={{ padding: '16px 24px' }}>
                      <div className="resume-info">
                        <div className="resume-details">
                          <span className="resume-name">{comp.name}</span>
                          <span className="resume-meta">{comp.location}</span>
                        </div>
                      </div>
                      <div style={{ display: 'flex', gap: '8px' }}>
                        <button
                          style={{ padding: '4px 12px', fontSize: '11px', borderRadius: '4px', border: '1.5px solid #059669', background: 'transparent', color: '#059669', cursor: 'pointer', fontWeight: '700', fontFamily: 'Space Grotesk, sans-serif', letterSpacing: '0.5px', textTransform: 'uppercase' }}
                          onClick={() => navigate(`/create-company?edit=${comp.id}`)}
                        >Edit</button>
                        <button
                          style={{ padding: '4px 12px', fontSize: '11px', borderRadius: '4px', background: '#dc2626', color: 'white', border: 'none', cursor: 'pointer', fontWeight: '700', fontFamily: 'Space Grotesk, sans-serif', textTransform: 'uppercase' }}
                          onClick={async () => {
                            if (window.confirm(`Delete company profile "${comp.name}"?\n\nNote: Remove all active jobs for this company first.`)) {
                              try {
                                await companyAPI.delete(comp.id);
                                setCompanies(prev => prev.filter(c => c.id !== comp.id));
                              } catch (err) {
                                alert(err.response?.data?.detail || 'Failed to delete company');
                              }
                            }
                          }}
                        >Delete</button>
                      </div>
                    </li>
                  ))}
                </ul>
              </motion.div>
            )}

            <motion.div className="card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.5 }}>
              <div className="card-header">
                <h3>Your Active Job Postings</h3>
                <span className="card-badge" style={{ background: 'rgba(10,102,194,0.08)', color: 'var(--cy-brand)' }}>
                  {filteredActiveJobs.length} Active Jobs ({filterCompanyId === 'all' ? 'All Companies' : companies.find(c => c.id === parseInt(filterCompanyId))?.name || 'Company'})
                </span>
              </div>

              {companies.length > 0 && (
                <div style={{ padding: '0 24px 16px' }}>
                  <select
                    value={filterCompanyId}
                    onChange={(e) => setFilterCompanyId(e.target.value)}
                    style={{
                      width: '100%', padding: '12px 16px', borderRadius: '8px',
                      border: '1px solid rgba(10,102,194,0.2)', background: 'rgba(10,102,194,0.04)',
                      color: 'var(--cy-brand)', fontSize: '14px', fontFamily: 'Space Grotesk, sans-serif',
                      fontWeight: '600', boxShadow: '0 4px 12px rgba(10,102,194,0.05)', cursor: 'pointer',
                      outline: 'none'
                    }}
                  >
                    <option value="all" style={{ background: 'white', color: 'black' }}>All Companies</option>
                    {companies.map(c => <option key={c.id} value={c.id} style={{ background: 'white', color: 'black' }}>{c.name}</option>)}
                  </select>
                </div>
              )}

              {filteredActiveJobs.length === 0 ? (
                <p style={{ color: 'var(--cy-text-mute)', textAlign: 'center', padding: '24px 0', fontFamily: 'JetBrains Mono, monospace', fontSize: '12px' }}>No jobs found.</p>
              ) : (
                <ul className="resume-list" style={{ maxHeight: '420px', overflowY: 'auto', paddingRight: '8px' }}>
                  {filteredActiveJobs.map((job) => (
                    <li key={job.id} className="resume-item" style={{ padding: '16px 24px' }}>
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
                      <div style={{ fontSize: '12px', color: 'var(--cy-text-mute)', fontFamily: 'JetBrains Mono, monospace' }}>{job.company} •{job.location}</div>
                    </motion.div>
                  ))}
                </div>
              </motion.div>
            )}

            <motion.div className="card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }}>
              <div className="card-header"><h3>Profile Summary</h3></div>
              {(!profile?.headline && !profile?.skills) ? (
                <div style={{ textAlign: 'center', padding: '30px 10px' }}>
                  <p style={{ color: 'var(--cy-text-mute)', fontSize: '13px', marginBottom: '16px' }}>Complete your profile to get better job recommendations</p>
                  <button onClick={() => navigate('/profile')} className="btn-upload" style={{ padding: '8px 24px', fontSize: '12px', width: 'auto' }}>Complete Profile</button>
                </div>
              ) : (
                <div className="profile-info" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                  <div className="profile-field">
                    <span className="profile-field-label" style={{ fontWeight: 'bold' }}>Headline</span>
                    <span className="profile-field-value" style={{ marginTop: '4px', display: 'block' }}>{profile?.headline ? (profile.headline.length > 15 ? profile.headline.substring(0, 15) + '...' : profile.headline) : 'Not set'}</span>
                  </div>
                  <div className="profile-field">
                    <span className="profile-field-label" style={{ fontWeight: 'bold' }}>Skills</span>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '4px' }}>
                      {profile?.skills ? profile.skills.split(',').slice(0, 5).map(s => <span key={s} className="skill-tag" style={{ background: 'rgba(10,102,194,0.08)', color: 'var(--cy-brand)', border: '1px dashed rgba(10,102,194,0.3)', padding: '4px 8px', borderRadius: '4px', fontSize: '11px' }}>{s.trim()}</span>) : <span className="empty">Not set</span>}
                    </div>
                  </div>
                </div>
              )}
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
                <div style={{ textAlign: 'center', padding: '30px 0' }}>
                  <p style={{ color: 'var(--cy-text-mute)', fontFamily: 'JetBrains Mono, monospace', fontSize: '14px', marginBottom: '8px' }}>No resumes uploaded yet</p>
                  <p style={{ color: 'var(--cy-text-main)', fontSize: '12px', opacity: 0.8 }}>Upload your resume to apply for jobs faster</p>
                </div>
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
                      <div className="resume-details" style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                        <span className="resume-name" style={{ fontSize: '14px', color: '#065f46' }}>{app.job_title}</span>
                        <span style={{ fontSize: '12px', fontFamily: 'JetBrains Mono, monospace', color: '#111', fontWeight: 'bold' }}>{app.company_name || 'Unknown Company'} &nbsp;&bull;&nbsp;{app.location || 'Remote'}</span>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '11px', fontFamily: 'JetBrains Mono, monospace' }}>
                          <span style={{ color: 'var(--cy-text-mute)' }}>Status: <span className={`status-badge ${app.status.toLowerCase()}`} style={{ marginLeft: '4px' }}>{app.status}</span></span>
                          <span style={{ color: 'var(--cy-text-mute)' }}>Applied on:{new Date(app.applied_at).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })}</span>
                        </div>
                      </div>
                      <div style={{ display: 'flex', gap: '8px' }}>
                        <button
                          className="download-btn"
                          style={{ position: 'relative', background: 'rgba(5,150,105,0.08)', color: '#065f46', border: '1px dashed rgba(5,150,105,0.3)', boxShadow: '0 0 6px rgba(5,150,105,0.12)' }}
                          onClick={() => {
                            if (!app.recruiter_id) return;
                            const isConnected = connections.some(c => String(c.id) === String(app.recruiter_id) || String(c.user_id) === String(app.recruiter_id));
                            const hasMessage = unreadCounts.dm && unreadCounts.dm[app.recruiter_id] > 0;

                            if (isConnected || hasMessage) {
                              navigate(`/chat/${app.recruiter_id}`);
                            } else {
                              alert("First send a connection request to the recruiter.");
                            }
                          }}
                          disabled={!app.recruiter_id}
                        >
                          Chat with Recruiter
                          {app.recruiter_id && unreadCounts.dm && unreadCounts.dm[app.recruiter_id] > 0 && (
                            <span className="badge-count">{unreadCounts.dm[app.recruiter_id]}</span>
                          )}
                        </button>

                        <button
                          className="download-btn"
                          style={{ position: 'relative', padding: '6px 16px', fontSize: '11px', background: 'rgba(10,102,194,0.08)', color: 'var(--cy-brand)', border: '1px dashed rgba(10,102,194,0.3)', boxShadow: '0 0 6px rgba(10,102,194,0.12)' }}
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
              <span className="card-badge" style={{ background: 'rgba(5,150,105,0.08)', color: '#065f46', border: '1px dashed rgba(5,150,105,0.3)', boxShadow: '0 0 6px rgba(5,150,105,0.12)' }}>{viewers.length} Profile Viewers</span>
            </div>
            {viewers.length === 0 ? (
              <p style={{ color: 'var(--cy-text-mute)', textAlign: 'center', padding: '24px 0', fontFamily: 'JetBrains Mono, monospace', fontSize: '12px' }}>No recent views recorded.</p>
            ) : (
              <ul className="resume-list" style={{ maxHeight: '260px', overflowY: 'auto', paddingRight: '8px' }}>
                {viewers.map((viewer, index) => (
                  <li key={index} className="resume-item" style={{ padding: '10px 16px', borderBottom: '1px solid var(--cy-border)' }}>
                    <div className="resume-info" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span className="resume-name" style={{ fontSize: '14px', color: '#065f46' }}>{viewer.viewer_name}</span>
                      <span style={{ color: 'var(--cy-text-mute)', fontSize: '11px', fontFamily: 'JetBrains Mono, monospace' }}>
                        {new Date(viewer.timestamp).toLocaleDateString('en-GB', { day: '2-digit', month: 'short' })} • {new Date(viewer.timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: true })}
                      </span>
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


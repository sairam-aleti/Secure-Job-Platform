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

const Dashboard = () => {
  const getStatusClass = (status) => {
    switch (status) {
      case 'Offer': return 'offered-card-highlight';
      case 'Offer Accepted': return 'accepted-card-highlight';
      case 'Offer Declined': return 'declined-card-highlight';
      case 'Rejected': return 'rejected-card-highlight';
      case 'Reviewed': return 'reviewed-card-highlight';
      case 'Interviewed': return 'interviewed-card-highlight';
      default: return 'applied-card-highlight';
    }
  };

  const getInitials = (name) => {
    if (!name) return '??';
    const parts = name.split(' ');
    if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
    return name.substring(0, 2).toUpperCase();
  };

  const [profile, setProfile] = useState(null);
  const [resumes, setResumes] = useState([]);
  const [myJobs, setMyJobs] = useState([]);
  const [applications, setApplications] = useState([]);
  const [seekerAppPage, setSeekerAppPage] = useState(1);
  const [recruiterAppPage, setRecruiterAppPage] = useState(1);
  const appsPerPage = 3;
  const [appError, setAppError] = useState(null);
  const [visibleRecruiterApps, setVisibleRecruiterApps] = useState(3);
  const [appCompanyFilter, setAppCompanyFilter] = useState('all');
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
      setAppError(null);
      const response = await applicationAPI.recruiterApplications();
      setApplications(response.data);
    } catch (err) { 
      console.error(err); 
      setAppError("Failed to load applications. Please refresh or contact support.");
    }
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

  const setupEncryption = useCallback(async () => {
    const derivedKeyB64 = sessionStorage.getItem('derived_key');
    if (!derivedKeyB64) return; 

    try {
      const existingEncryptedKey = localStorage.getItem('encrypted_private_key');

      if (existingEncryptedKey) {
        const privKey = cryptoService.decryptPrivateKey(existingEncryptedKey, derivedKeyB64);
        if (privKey) {
          const pubKey = cryptoService.getPublicKeyFromPrivate(privKey);
          await authAPI.updatePublicKey({ public_key: pubKey, encrypted_private_key: existingEncryptedKey });
        }
      } else {
        try {
          const profRes = await profileAPI.getProfile();
          if (profRes.data.encrypted_private_key) {
            localStorage.setItem('encrypted_private_key', profRes.data.encrypted_private_key);
            return; 
          }
        } catch (e) { }
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
      const response = await profileAPI.getProfile();
      const userData = response.data;
      setProfile(userData);

      const promises = [];

      const derivedKeyB64 = sessionStorage.getItem('derived_key');
      if (derivedKeyB64) {
        promises.push(setupEncryption());
      }

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
        promises.push(fetchPlatformStats());
        promises.push(fetchRecentActivity());
        promises.push(fetchLastLogin());
      }

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
    if (!resumeId) {
      alert("No resume available for this application.");
      return;
    }
    try {
      const response = await resumeAPI.download(resumeId);
      const blob = new Blob([response.data], { type: response.headers['content-type'] });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename || 'resume.pdf';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Download error:", err);
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
          <motion.div initial="hidden" animate="visible" variants={{ visible: { transition: { staggerChildren: 0.1 } } }}>
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

            <motion.div className="card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.6 }}>
              <div className="card-header" style={{ position: 'relative' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
                  <h3>Received Applications</h3>
                  <span className="card-badge" style={{ background: 'rgba(10,102,194,0.08)', color: 'var(--cy-brand)' }}>
                    {applications.length} Total
                  </span>
                </div>
                <div className="filter-wrapper">
                  <select 
                    className="filter-select"
                    value={appCompanyFilter}
                    onChange={(e) => {
                      setAppCompanyFilter(e.target.value);
                      setRecruiterAppPage(1);
                    }}
                  >
                    <option value="all">All Companies</option>
                    {[...new Set(applications.map(app => app.company_name))].map(company => (
                      <option key={company} value={company}>{company}</option>
                    ))}
                  </select>
                  <svg className="filter-triangle" width="10" height="10" viewBox="0 0 24 24" fill="currentColor"><path d="M7 10l5 5 5-5z"/></svg>
                </div>
              </div>
              {appError ? (
                <div className="error-message" style={{ margin: '20px' }}>
                  {appError}
                </div>
              ) : applications.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '40px 20px', color: 'var(--cy-text-mute)' }}>
                  <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1" strokeLinecap="round" strokeLinejoin="round" style={{ marginBottom: '16px', opacity: 0.3 }}><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /><line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" /><polyline points="10 9 9 9 8 9" /></svg>
                  <p style={{ fontFamily: 'Space Grotesk, sans-serif', fontWeight: '500' }}>No applications received yet.</p>
                  <p style={{ fontSize: '12px', marginTop: '4px' }}>Once job seekers apply for your roles, they will appear here.</p>
                </div>
              ) : (
                <>
                  <ul className="resume-list">
                    {[...applications]
                      .filter(app => appCompanyFilter === 'all' || app.company_name === appCompanyFilter)
                      .sort((a,b) => new Date(b.applied_at) - new Date(a.applied_at))
                      .slice((recruiterAppPage - 1) * appsPerPage, recruiterAppPage * appsPerPage)
                      .map((app) => (
                        <li key={app.id} className={`resume-item ${getStatusClass(app.status)}`} style={{ 
                          flexDirection: 'column', 
                          alignItems: 'flex-start', 
                          position: 'relative',
                          padding: '20px'
                        }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', width: '100%', marginBottom: '15px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                              <div className="candidate-avatar">{getInitials(app.applicant_name)}</div>
                              <div className="resume-info">
                                <div className="resume-details">
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                    <span className="resume-name" style={{ color: '#111', fontSize: '15px', fontWeight: '500' }}>
                                      {app.applicant_name}
                                    </span>
                                    <button
                                      onClick={async () => {
                                        try {
                                          await applicationAPI.toggleShortlist(app.id);
                                          fetchRecruiterApplications();
                                        } catch (err) { console.error("Shortlist toggle failed"); }
                                      }}
                                      style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, color: app.is_shortlisted ? '#f59e0b' : '#d1d5db' }}
                                      title={app.is_shortlisted ? "Remove from shortlist" : "Add to shortlist"}
                                    >
                                      <svg width="14" height="14" viewBox="0 0 24 24" fill={app.is_shortlisted ? "currentColor" : "none"} stroke="currentColor" strokeWidth="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" /></svg>
                                    </button>
                                  </div>
                                  <div style={{ fontSize: '13px', color: 'var(--cy-text-mute)', marginTop: '2px' }}>
                                    {app.company_name || 'FCS Corp'} • {app.job_title}
                                  </div>
                                </div>
                              </div>
                            </div>

                            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '4px' }}>
                              <select
                                disabled={app.status === 'Offer Accepted' || app.status === 'Offer Declined'}
                                className={`status-dropdown-semantic status-${app.status.toLowerCase().replace(/\s+/g, '-')}`}
                                value={app.status}
                                onChange={async (e) => {
                                  try {
                                    await applicationAPI.updateStatus(app.id, e.target.value);
                                    fetchRecruiterApplications();
                                  } catch (err) { alert("Failed to update status."); }
                                }}
                              >
                                <option value="Applied" disabled={['Reviewed', 'Interviewed', 'Offer', 'Rejected'].includes(app.status)}>Applied</option>
                                <option value="Reviewed" disabled={['Interviewed', 'Offer', 'Rejected'].includes(app.status)}>Reviewed</option>
                                <option value="Interviewed" disabled={['Offer', 'Rejected'].includes(app.status)}>Interviewed</option>
                                <option value="Offer" disabled={app.status === 'Rejected'}>Offer</option>
                                <option value="Offer Accepted" disabled>Offer Accepted</option>
                                <option value="Offer Declined" disabled>Offer Declined</option>
                                <option value="Rejected" disabled={app.status === 'Offer Accepted' || app.status === 'Offer Declined'}>Rejected</option>
                              </select>
                              {app.status === 'Offer Declined' && (
                                <span style={{ color: '#ef4444', fontSize: '11px', fontWeight: '800', textTransform: 'uppercase', marginTop: '4px' }}>Offer Declined</span>
                              )}
                              {app.status === 'Offer Accepted' && (
                                <span style={{ color: '#15803d', fontSize: '11px', fontWeight: '800', textTransform: 'uppercase', marginTop: '4px' }}>Offer Accepted</span>
                              )}
                              <span style={{ fontSize: '11px', color: 'var(--cy-text-mute)' }}>
                                {app.match_score !== undefined ? app.match_score : 0}% Match
                              </span>
                            </div>
                          </div>

                          <div style={{ width: '100%', marginBottom: '15px', position: 'relative' }}>
                            <textarea
                              className="notes-textarea"
                              placeholder="Add private recruiter notes..."
                              rows="2"
                              maxLength={100}
                              defaultValue={app.recruiter_notes || ''}
                              onBlur={async (e) => {
                                const newNotes = e.target.value;
                                if (newNotes !== (app.recruiter_notes || '')) {
                                  try { await applicationAPI.updateNotes(app.id, newNotes); } catch (err) { console.error('Notes save failed'); }
                                }
                              }}
                            />
                            <div style={{ position: 'absolute', bottom: '6px', right: '10px', fontSize: '9px', color: '#9ca3af', pointerEvents: 'none' }}>
                              100
                            </div>
                          </div>

                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%' }}>
                            <div style={{ display: 'flex', gap: '10px' }}>
                              <button className="btn-filled-primary" onClick={() => handleDownload(app.resume_id, `Resume_${app.applicant_name}.pdf`)}>View Resume</button>
                              <button className="btn-ghost-secondary" onClick={() => navigate(`/chat/${app.applicant_id}`)}>Chat with Applicant</button>
                            </div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                              <span style={{ fontSize: '11px', color: 'var(--cy-text-mute)', fontStyle: 'italic' }}>
                                Applied : {new Date(app.applied_at).toLocaleDateString('en-GB')}
                              </span>
                                <span title={app.status !== 'Rejected' && app.status !== 'Offer Declined' ? "Applications can only be deleted if they are Rejected or after the Offer is Declined." : "Delete Application"}>
                                  <button
                                    className={`icon-btn-tint-red ${app.status !== 'Rejected' && app.status !== 'Offer Declined' ? 'disabled' : ''}`}
                                    disabled={app.status !== 'Rejected' && app.status !== 'Offer Declined'}
                                    onClick={async () => {
                                      if (window.confirm("Are you sure? This action is permanent.")) {
                                        try { await applicationAPI.delete(app.id); fetchRecruiterApplications(); } catch (err) { alert("Failed to delete."); }
                                      }
                                    }}
                                  >
                                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 6h18M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2M10 11v6M14 11v6"/></svg>
                                  </button>
                                </span>
                            </div>
                          </div>
                        </li>
                      ))}
                  </ul>
                  {/* Recruiter Applications Pagination */}
                  {(() => {
                    const filtered = applications.filter(app => appCompanyFilter === 'all' || app.company_name === appCompanyFilter);
                    const totalPages = Math.ceil(filtered.length / appsPerPage);
                    if (totalPages <= 1) return null;
                    return (
                      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '15px', padding: '20px 0', borderTop: '1px solid var(--cy-border)' }}>
                        <button 
                          className="btn-nav-outline" 
                          disabled={recruiterAppPage === 1}
                          onClick={() => setRecruiterAppPage(p => p - 1)}
                          style={{ padding: '6px 12px', fontSize: '11px' }}
                        >Prev</button>
                        <span style={{ fontSize: '12px', fontWeight: '600', color: 'var(--cy-text-mute)' }}>Page {recruiterAppPage} of {totalPages}</span>
                        <button 
                          className="btn-nav-outline" 
                          disabled={recruiterAppPage === totalPages}
                          onClick={() => setRecruiterAppPage(p => p + 1)}
                          style={{ padding: '6px 12px', fontSize: '11px' }}
                        >Next</button>
                      </div>
                    );
                  })()}
                </>
              )}
            </motion.div>
          </>
        )}

        {/* --- JOB SEEKER VIEW --- */}
        {profile?.role === 'job_seeker' && (
          <>
            {recommendations.length > 0 && (
              <div className="recommended-container">
                <div className="card-header" style={{ border: 'none', marginBottom: '0' }}>
                  <h3>Recommended for You</h3>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span className="card-badge" style={{ background: '#fff', color: '#1a6ef5', border: '1px solid #d1dbed' }}>Intelligent Matching</span>
                  </div>
                </div>
                <div className="jobs-grid" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px' }}>
                  {recommendations.slice(0, 3).map((job) => {
                    const score = job.match_score || 0;
                    const pillClass = score >= 80 ? 'match-high' : score >= 40 ? 'match-mid' : 'match-low';
                    const userSkills = (profile?.skills || '').split(',').map(s => s.trim().toLowerCase()).filter(s => s !== '');
                    const requiredSkills = (job.skills_required || '')
                      .replace(/[\[\]"']/g, '')
                      .split(',')
                      .map(s => s.trim())
                      .filter(s => s !== '');
                    
                    return (
                      <motion.div key={job.job_id} className="job-card" whileHover={{ y: -2 }} onClick={() => navigate(`/apply/${job.job_id}`)}>
                        <div className="card-top-row">
                          <span className={`match-pill ${pillClass}`}>{score}% Match</span>
                          <button className="bookmark-btn" onClick={(e) => e.stopPropagation()}>
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z"/></svg>
                          </button>
                        </div>
                        
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                          <span style={{ fontSize: '15px', fontWeight: '500', color: '#1a1a1a' }}>{job.title}</span>
                          <span style={{ fontSize: '12px', color: '#7a8899' }}>{job.company} &bull; {job.location}</span>
                        </div>

                        <div style={{ borderTop: '1px solid #edf1f5', paddingTop: '10px', marginTop: '8px' }}>
                          <div style={{ fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.06em', color: '#a0adb8', marginBottom: '6px' }}>Skills required</div>
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '5px' }}>
                            {requiredSkills.slice(0, 5).map(skill => (
                              <span key={skill} style={{ 
                                background: '#e8f0fd', 
                                color: '#1a5cd4', 
                                border: '1px solid #b5d0f7', 
                                fontSize: '11px', 
                                padding: '3px 9px', 
                                borderRadius: '6px', 
                                fontWeight: '400' 
                              }}>
                                {skill}
                              </span>
                            ))}
                            {requiredSkills.length === 0 && <span style={{ fontSize: '11px', color: '#a0adb8', fontStyle: 'italic' }}>No specific skills listed</span>}
                          </div>
                        </div>

                        <div className="hairline-divider" />

                        <div className="meta-row">
                          <div style={{ display: 'flex', gap: '12px' }}>
                            <div className="meta-item">
                              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>
                              {job.type || 'Full-time'}
                            </div>
                            <div className="meta-item">
                              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                              Posted {job.posted_at ? `${Math.floor(Math.abs(new Date() - new Date(job.posted_at)) / (86400000))}d ago` : 'Recently'}
                            </div>
                          </div>
                          <button 
                            className="btn-apply-small" 
                            style={{ background: 'var(--cy-brand)' }}
                            onClick={(e) => { e.stopPropagation(); navigate(`/apply/${job.job_id}`); }}
                          >
                            Apply now
                          </button>
                        </div>
                      </motion.div>
                    );
                  })}
                  
                  {recommendations.length === 1 && (
                    <motion.div 
                      className="job-card" 
                      style={{ 
                        display: 'flex', 
                        flexDirection: 'column', 
                        justifyContent: 'center', 
                        alignItems: 'center', 
                        textAlign: 'center', 
                        padding: '24px',
                        background: '#fcfdfe',
                        border: '1px dashed #cbd5e1',
                        cursor: 'pointer'
                      }}
                      whileHover={{ y: -2, borderColor: 'var(--cy-brand)' }}
                      onClick={() => navigate('/profile')}
                    >
                      <div style={{ background: 'rgba(26,110,245,0.06)', borderRadius: '50%', width: '40px', height: '40px', display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '12px' }}>
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--cy-brand)" strokeWidth="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>
                      </div>
                      <span style={{ fontSize: '14px', fontWeight: '600', color: '#1a1a1a', marginBottom: '4px' }}>Want more matches?</span>
                      <span style={{ fontSize: '12px', color: '#7a8899', lineHeight: '1.5' }}>
                        Improve your CV and add more skills to increase your match percentage and discover more jobs.
                      </span>
                    </motion.div>
                  )}
                </div>
              </div>
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
                    <span className="profile-field-value" style={{ marginTop: '4px', display: 'block' }}>{profile?.headline ? (profile.headline.length > 25 ? profile.headline.substring(0, 25) + '...' : profile.headline) : 'Not set'}</span>
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

            <motion.div className="card" style={{ marginTop: '20px' }} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.7 }}>
              <div className="card-header">
                <h3>Your Applications</h3>
                <span className="card-badge" style={{ background: 'rgba(5,150,105,0.08)', color: '#065f46', border: '1px dashed rgba(5,150,105,0.3)' }}>{applications.length} Total</span>
              </div>
              {applications.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '30px 0' }}>
                   <p style={{ color: 'var(--cy-text-mute)', fontFamily: 'JetBrains Mono, monospace', fontSize: '14px' }}>No applications yet</p>
                </div>
              ) : (
                <>
                  <ul className="resume-list">
                    {(() => {
                      const hasAcceptedOffer = applications.some(a => a.status === 'Offer Accepted');
                      return [...applications]
                        .sort((a,b) => new Date(b.applied_at) - new Date(a.applied_at))
                        .slice((seekerAppPage - 1) * appsPerPage, seekerAppPage * appsPerPage)
                        .map((app) => {
                          const isRejected = app.status === 'Rejected' || app.status === 'Offer Declined';
                          const appliedDate = new Date(app.applied_at);
                          const sevenWeeksInMs = 7 * 7 * 24 * 60 * 60 * 1000;
                          const canDelete = isRejected || (new Date() - appliedDate > sevenWeeksInMs);

                          const statusSteps = ['Applied', 'Reviewed', 'Interviewed', 'Offer'];
                          let currentIdx = statusSteps.indexOf(app.status);
                          if (app.status === 'Offer Accepted') currentIdx = 3;
                          if (app.status === 'Offer Declined') currentIdx = 3;
                          
                          const activeStep = (isRejected || app.status === 'Offer Declined') ? 3 : (currentIdx !== -1 ? currentIdx : 0);

                          return (
                            <li key={app.id} className={`resume-item ${getStatusClass(app.status)}`} style={{ 
                              position: 'relative', 
                              marginBottom: '15px', 
                              flexDirection: 'column', 
                              alignItems: 'flex-start',
                              padding: '20px'
                            }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', width: '100%', alignItems: 'flex-start' }}>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                                  <span style={{ fontSize: '15px', color: '#111', fontWeight: '500' }}>{app.job_title}</span>
                                  <span style={{ fontSize: '12px', color: 'var(--cy-text-mute)', fontFamily: 'JetBrains Mono, monospace' }}>
                                    {app.company_name} • {app.location}
                                  </span>
                                </div>
                                <span className={`status-badge ${app.status.toLowerCase().replace(/\s+/g, '-')}`} style={{ fontSize: '10px' }}>{app.status}</span>
                              </div>

                              <div style={{ width: '100%', marginTop: '10px' }}>
                                <div className="progress-stepper">
                                  {[0, 1, 2, 3].map((step) => {
                                    let stepClass = 'step-upcoming';
                                    if (isRejected && step === activeStep) stepClass = 'step-rejected';
                                    else if (step < activeStep) stepClass = 'step-done';
                                    else if (step === activeStep) stepClass = 'step-current';
                                    return <div key={step} className={`step-bar ${stepClass}`} />;
                                  })}
                                </div>
                                <div className="stepper-label-row">
                                  {statusSteps.map((label, idx) => (
                                    <span key={label} className={`step-label ${idx <= activeStep ? 'active' : ''}`}>
                                      {label === 'Offer' && isRejected ? 'Rejected' : label}
                                    </span>
                                  ))}
                                </div>
                              </div>

                              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%', marginTop: '20px' }}>
                                <div style={{ display: 'flex', gap: '8px' }}>
                                  {app.status === 'Offer' && (
                                    <>
                                      <button 
                                        className={`btn-filled-success ${hasAcceptedOffer ? 'disabled' : ''}`} 
                                        disabled={hasAcceptedOffer}
                                        title={hasAcceptedOffer ? "You've already accepted an offer. You cannot accept multiple offers." : ""}
                                        onClick={async () => {
                                          if (window.confirm("Accept this offer?")) {
                                            try { await applicationAPI.seekerResponse(app.id, 'Offer Accepted'); fetchUserApplications(); } 
                                            catch (err) { alert("Failed to accept."); }
                                          }
                                        }}>Accept Offer</button>
                                    <button className="btn-filled-danger" onClick={async () => {
                                      if (window.confirm("Decline this offer?")) {
                                        try { await applicationAPI.seekerResponse(app.id, 'Offer Declined'); fetchUserApplications(); } 
                                        catch (err) { alert("Failed to decline."); }
                                      }
                                    }}>Decline</button>
                                  </>
                                )}
                                <button className="btn-filled-primary" onClick={() => { if (app.recruiter_id) navigate(`/chat/${app.recruiter_id}`); }}>Chat with Recruiter</button>
                                <button className="btn-ghost-secondary" onClick={() => navigate('/chat/groups')}>Group Channels</button>
                              </div>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                <span style={{ fontSize: '11px', color: 'var(--cy-text-mute)', fontStyle: 'italic' }}>
                                  Applied : {new Date(app.applied_at).toLocaleDateString('en-GB')}
                                </span>
                                <span title={!canDelete ? "Initial applications have a 7-week safety period. Deletion is only allowed for Rejected/Declined offers or after this period." : "Delete Application"}>
                                  <button className={`icon-btn-tint-red ${!canDelete ? 'disabled' : ''}`} disabled={!canDelete} onClick={async (e) => {
                                    e.stopPropagation();
                                    if (window.confirm("Are you sure? This cannot be undone.")) {
                                      try { 
                                        await applicationAPI.delete(app.id); 
                                        fetchUserApplications(); 
                                      } catch (err) { alert("Failed to delete application."); }
                                    }
                                  }}>
                                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 6h18M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2M10 11v6M14 11v6"/></svg>
                                  </button>
                                </span>
                              </div>
                            </div>
                          </li>
                          );
                        })
                      })()
                    }
                  </ul>
                  {Math.ceil(applications.length / appsPerPage) > 1 && (
                    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '15px', padding: '20px 0', borderTop: '1px solid var(--cy-border)' }}>
                      <button className="btn-nav-outline" disabled={seekerAppPage === 1} onClick={() => setSeekerAppPage(p => p - 1)} style={{ padding: '6px 12px', fontSize: '11px' }}>Prev</button>
                      <span style={{ fontSize: '12px', fontWeight: '600', color: 'var(--cy-text-mute)' }}>Page {seekerAppPage} of {Math.ceil(applications.length / appsPerPage)}</span>
                      <button className="btn-nav-outline" disabled={seekerAppPage === Math.ceil(applications.length / appsPerPage)} onClick={() => setSeekerAppPage(p => p + 1)} style={{ padding: '6px 12px', fontSize: '11px' }}>Next</button>
                    </div>
                  )}
                </>
              )}
            </motion.div>
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
                        {new Date(viewer.timestamp).toLocaleDateString('en-GB')}
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


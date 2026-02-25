import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { profileAPI, resumeAPI, jobAPI, applicationAPI, authAPI } from '../services/api'; 
import cryptoService from '../services/cryptoService'; 
import './Dashboard.css';

function Dashboard() {
  const [profile, setProfile] = useState(null);
  const [resumes, setResumes] = useState([]);
  const [myJobs, setMyJobs] = useState([]);
  const [applications, setApplications] = useState([]); 
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [file, setFile] = useState(null);
  const [uploadStatus, setUploadStatus] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    const token = localStorage.getItem('access_token');
    if (!token) {
      navigate('/login');
      return;
    }
    fetchProfile();
  }, [navigate]);

  const fetchProfile = async () => {
    try {
      const response = await profileAPI.getProfile();
      setProfile(response.data);

      // Initialize E2EE Keys if missing
      if (!response.data.public_key) {
        await setupEncryption();
      }
      
      // Fetch specific data based on role
      if (response.data.role === 'job_seeker') {
        fetchResumes();
        fetchUserApplications(); 
      } else if (response.data.role === 'recruiter') {
        fetchMyJobs();
        fetchRecruiterApplications(); 
      }
    } catch (err) {
      setError('Failed to load profile');
      if (err.response?.status === 401) {
        localStorage.removeItem('access_token');
        navigate('/login');
      }
    } finally {
      setLoading(false);
    }
  };

  const setupEncryption = async () => {
    const password = sessionStorage.getItem('user_pwd');
    if (!password) return;
    
    console.log("Generating Secure Messaging Keys...");
    try {
      const { publicKey, privateKey } = cryptoService.generateKeyPair();
      const encryptedPrivKey = cryptoService.encryptPrivateKey(privateKey, password);
      localStorage.setItem('encrypted_private_key', encryptedPrivKey);
      await authAPI.updatePublicKey({ public_key: publicKey });
      console.log("Identity established successfully.");
    } catch (err) {
      console.error("Encryption setup failed:", err);
    }
  };

  const fetchResumes = async () => {
    try {
      const response = await resumeAPI.list();
      setResumes(response.data);
    } catch (err) { console.error(err); }
  };

  const fetchMyJobs = async () => {
    try {
      const response = await jobAPI.myJobs();
      setMyJobs(response.data);
    } catch (err) { console.error(err); }
  };

  const fetchUserApplications = async () => {
    try {
      const response = await applicationAPI.myApplications();
      setApplications(response.data);
    } catch (err) { console.error(err); }
  };

  const fetchRecruiterApplications = async () => {
    try {
      const response = await applicationAPI.recruiterApplications();
      setApplications(response.data);
    } catch (err) { console.error(err); }
  };

  const handleLogout = () => {
    localStorage.clear();
    sessionStorage.clear();
    navigate('/login');
  };

  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
  };

  const handleUpload = async () => {
    if (!file) {
      setUploadStatus('Please select a file');
      return;
    }
    const formData = new FormData();
    formData.append('file', file);
    try {
      setUploadStatus('Uploading...');
      await resumeAPI.upload(formData);
      setUploadStatus('Resume uploaded successfully!');
      setFile(null);
      fetchResumes();
    } catch (err) {
      setUploadStatus(err.response?.data?.detail || 'Upload failed');
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
    } catch (err) {
      alert('Download failed: Not authorized or file error.');
    }
  };

  if (loading) {
    return (
      <div className="app-layout">
        <main className="app-content">
          <p style={{ textAlign: 'center', marginTop: '80px' }}>Loading your dashboard...</p>
        </main>
      </div>
    );
  }

  return (
    <div className="app-layout">
      {/* --- REFINED NAVBAR --- */}
      <nav className="app-nav">
        <a href="/dashboard" className="nav-brand">FortKnox</a>
        <div className="nav-center">
          <a href="/dashboard">Dashboard</a>
          {/* Admin doesn't need Job Board or Profile */}
          {profile?.role !== 'admin' && <a href="/jobs">Job Board</a>}
          {profile?.role === 'job_seeker' && <a href="/profile">Profile</a>}
          {profile?.role === 'admin' && <a href="/admin">Admin Panel</a>}
        </div>
        <div className="nav-actions">
          <button className="btn-logout" onClick={handleLogout}>Sign Out</button>
        </div>
      </nav>

      <div className="page-hero">
        <div className="page-hero-inner">
          <h2>Welcome back, {profile?.full_name}</h2>
          <p>
            {profile?.role === 'recruiter' 
              ? 'Manage your company and job postings' 
              : profile?.role === 'admin' 
                ? 'Platform Administration & Auditing' 
                : 'Track your applications and resume'}
          </p>
        </div>
      </div>

      <main className="app-content">
        {/* --- COMMON STATS --- */}
        <div className="stats-row">
          <div className="stat-item">
            <div className="stat-label">Email</div>
            <div className="stat-value" style={{ fontSize: '15px' }}>{profile?.email}</div>
          </div>
          <div className="stat-item">
            <div className="stat-label">Role</div>
            <div className="stat-value" style={{ textTransform: 'capitalize' }}>{profile?.role?.replace('_', ' ')}</div>
          </div>
          <div className="stat-item">
            <div className="stat-label">Status</div>
            <div className="stat-value" style={{ fontSize: '15px', color: profile?.is_verified ? '#059669' : '#d97706' }}>
              {profile?.is_verified ? 'Verified' : 'Pending'}
            </div>
          </div>
        </div>

        {/* --- RECRUITER VIEW --- */}
        {profile?.role === 'recruiter' && (
          <>
            <div className="card">
              <div className="card-header">
                <h3>Quick Actions</h3>
              </div>
              <div style={{ display: 'flex', gap: '16px', padding: '10px 0' }}>
                <button className="btn-upload" onClick={() => navigate('/create-company')}>Create Company Page</button>
                <button className="btn-upload" onClick={() => navigate('/post-job')}>Post a Job</button>
              </div>
            </div>

            <div className="card">
              <div className="card-header">
                <h3>Your Active Job Postings</h3>
                <span className="card-badge" style={{ background: '#eef2ff', color: '#3461c7' }}>{myJobs.length} Active</span>
              </div>
              {myJobs.length === 0 ? (
                <p style={{ color: '#9ca3af', textAlign: 'center', padding: '24px 0' }}>No jobs posted yet.</p>
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
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {applications.length > 0 && (
              <div className="card">
                <div className="card-header">
                  <h3>Received Applications</h3>
                </div>
                <ul className="resume-list">
                  {applications.map((app) => (
                    <li key={app.id} className="resume-item">
                      <div className="resume-info">
                        <div className="resume-details">
                          <span className="resume-name">{app.applicant_name}</span>
                          <span className="resume-meta">Position: {app.job_title}</span>
                        </div>
                      </div>
                      <div style={{ display: 'flex', gap: '10px' }}>
                        <button className="download-btn" onClick={() => handleDownload(app.resume_id, `Resume_${app.applicant_name}.pdf`)}>View Resume</button>
                        <button className="download-btn" style={{ borderColor: '#667eea', color: '#667eea' }} onClick={() => navigate(`/chat/${app.applicant_id}`)}>Chat</button>
                      </div>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </>
        )}

        {/* --- JOB SEEKER VIEW --- */}
        {profile?.role === 'job_seeker' && (
          <>
            <div className="card">
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
            </div>

            <div className="card">
              <div className="card-header"><h3>Upload Resume</h3></div>
              <div className="upload-area">
                <p>Select your resume to upload securely</p>
                <input type="file" accept=".pdf,.docx" onChange={handleFileChange} />
              </div>
              <button className="btn-upload" onClick={handleUpload}>Upload & Encrypt</button>
              {uploadStatus && <p className="upload-status">{uploadStatus}</p>}
            </div>

            {applications.length > 0 && (
              <div className="card">
                <div className="card-header"><h3>Your Applications</h3></div>
                <ul className="resume-list">
                  {applications.map((app) => (
                    <li key={app.id} className="resume-item">
                      <div className="resume-details">
                        <span className="resume-name">{app.job_title}</span>
                        <span className="resume-meta">Status: <strong>{app.status}</strong></span>
                      </div>
                      <button className="download-btn" style={{ borderColor: '#667eea', color: '#667eea' }} onClick={() => navigate(`/chat/${app.recruiter_id}`)}>Chat with Recruiter</button>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </>
        )}

        {error && <div className="error-message">{error}</div>}
      </main>
    </div>
  );
}

export default Dashboard;
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { profileAPI, resumeAPI } from '../services/api';
import './Dashboard.css';

function Dashboard() {
  const [profile, setProfile] = useState(null);
  const [resumes, setResumes] = useState([]);
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
    fetchResumes();
  }, [navigate]);

  const fetchProfile = async () => {
    try {
      const response = await profileAPI.getProfile();
      setProfile(response.data);
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

  const fetchResumes = async () => {
    try {
      const response = await resumeAPI.list();
      setResumes(response.data);
    } catch (err) {
      console.log('No resumes found or error fetching:', err);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('user_email');
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
      setUploadStatus('Uploading and encrypting...');
      await resumeAPI.upload(formData);
      setUploadStatus('Resume uploaded and encrypted successfully!');
      setFile(null);
      fetchResumes(); // Refresh the resume list
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
      window.URL.revokeObjectURL(url);
    } catch (err) {
      alert(err.response?.data?.detail || 'Download failed');
    }
  };

  if (loading) {
    return (
      <div className="app-layout">
        <nav className="app-nav">
          <a href="/dashboard" className="nav-brand">FortKnox</a>
          <div className="nav-center">
            <a href="/dashboard">Dashboard</a>
            <a href="/profile">Profile</a>
          </div>
          <div className="nav-actions">
            <button className="btn-logout" onClick={handleLogout}>Sign Out</button>
          </div>
        </nav>
        <main className="app-content">
          <p style={{ textAlign: 'center', color: '#6b7280', marginTop: '80px', fontSize: '15px' }}>Loading your dashboard...</p>
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
          <a href="/profile">Profile</a>
          {profile?.role === 'admin' && <a href="/admin">Admin</a>}
        </div>
        <div className="nav-actions">
          <button className="btn-logout" onClick={handleLogout}>Sign Out</button>
        </div>
      </nav>

      <div className="page-hero">
        <div className="page-hero-inner">
          <h2>Welcome back, {profile?.full_name}</h2>
          <p>Here's your dashboard overview</p>
        </div>
      </div>

      <main className="app-content">
        <div className="stats-row">
          <div className="stat-item">
            <div className="stat-label">Email</div>
            <div className="stat-value" style={{ fontSize: '15px', wordBreak: 'break-all' }}>{profile?.email}</div>
          </div>
          <div className="stat-item">
            <div className="stat-label">Role</div>
            <div className="stat-value" style={{ fontSize: '15px', textTransform: 'capitalize' }}>{profile?.role?.replace('_', ' ')}</div>
          </div>
          <div className="stat-item">
            <div className="stat-label">Status</div>
            <div className="stat-value" style={{ fontSize: '15px', color: profile?.is_verified ? '#059669' : '#d97706' }}>
              {profile?.is_verified ? '✓ Verified' : '⏳ Pending'}
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <h3>Profile Summary</h3>
          </div>
          <div className="profile-info">
            <div className="profile-field">
              <span className="profile-field-label">Headline</span>
              <span className={`profile-field-value ${!profile?.headline ? 'empty' : ''}`}>
                {profile?.headline || 'Not set'}
              </span>
            </div>
            <div className="profile-field">
              <span className="profile-field-label">Location</span>
              <span className={`profile-field-value ${!profile?.location ? 'empty' : ''}`}>
                {profile?.location || 'Not set'}
              </span>
            </div>
            <div className="profile-field">
              <span className="profile-field-label">Bio</span>
              <span className={`profile-field-value ${!profile?.bio ? 'empty' : ''}`}>
                {profile?.bio || 'Not set'}
              </span>
            </div>
            <div className="profile-field">
              <span className="profile-field-label">Skills</span>
              <span className={`profile-field-value ${!profile?.skills ? 'empty' : ''}`}>
                {profile?.skills || 'Not set'}
              </span>
            </div>
          </div>
        </div>

        {profile?.role !== 'admin' && (
          <>
            <div className="card">
              <div className="card-header">
                <h3>Upload Resume</h3>
                <span className="card-badge" style={{ background: '#eef2ff', color: '#3461c7' }}>AES-256-GCM Encrypted</span>
              </div>
              <div className="upload-area">
                <p>Select your resume to upload securely</p>
                <p className="upload-hint">Accepted formats: PDF, DOCX — Max 10MB</p>
                <input
                  type="file"
                  accept=".pdf,.docx"
                  onChange={handleFileChange}
                />
              </div>
              <button className="btn-upload" onClick={handleUpload}>Upload & Encrypt</button>
              {uploadStatus && <p className="upload-status">{uploadStatus}</p>}
            </div>

            <div className="card">
              <div className="card-header">
                <h3>Your Resumes</h3>
                <span className="card-badge" style={{ background: '#ecfdf5', color: '#065f46' }}>{resumes.length} file{resumes.length !== 1 ? 's' : ''}</span>
              </div>
              {resumes.length === 0 ? (
                <p style={{ color: '#9ca3af', textAlign: 'center', padding: '24px 0' }}>No resumes uploaded yet.</p>
              ) : (
                <ul className="resume-list">
                  {resumes.map((resume) => (
                    <li key={resume.id} className="resume-item">
                      <div className="resume-info">
                        <div className="resume-icon">📄</div>
                        <div className="resume-details">
                          <span className="resume-name">{resume.original_filename}</span>
                          <div className="resume-meta">
                            <span className="resume-size">
                              {(resume.file_size / 1024).toFixed(1)} KB
                            </span>
                            <span className="resume-date">
                              {new Date(resume.uploaded_at).toLocaleDateString()}
                            </span>
                          </div>
                        </div>
                      </div>
                      <button 
                        className="download-btn"
                        onClick={() => handleDownload(resume.id, resume.original_filename)}
                      >
                        Download
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </>
        )}

        {error && <div className="error-message">{error}</div>}
      </main>
    </div>
  );
}

export default Dashboard;
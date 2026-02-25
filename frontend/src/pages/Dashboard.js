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
      <div className="dashboard-container">
        <p>Loading...</p>
      </div>
    );
  }

  return (
    <div className="dashboard-container">
      <nav className="dashboard-nav">
        <h1>Secure Job Platform</h1>
        <div className="nav-links">
          <a href="/profile">Edit Profile</a>
          {profile?.role === 'admin' && <a href="/admin">Admin Panel</a>}
          <button onClick={handleLogout}>Logout</button>
        </div>
      </nav>

      <main className="dashboard-main">
        <div className="welcome-card">
          <h2>Welcome, {profile?.full_name}!</h2>
          <p>Email: {profile?.email}</p>
          <p>Role: {profile?.role}</p>
          <p>Verified: {profile?.is_verified ? 'Yes' : 'No'}</p>
        </div>

        <div className="profile-card">
          <h3>Your Profile</h3>
          <p><strong>Headline:</strong> {profile?.headline || 'Not set'}</p>
          <p><strong>Location:</strong> {profile?.location || 'Not set'}</p>
          <p><strong>Bio:</strong> {profile?.bio || 'Not set'}</p>
          <p><strong>Skills:</strong> {profile?.skills || 'Not set'}</p>
        </div>

        {profile?.role !== 'admin' && (
  <>
    <div className="upload-card">
      <h3>Upload Resume (Encrypted)</h3>
      <p>Your resume will be encrypted using AES-256-GCM</p>
      <input
        type="file"
        accept=".pdf,.docx"
        onChange={handleFileChange}
      />
      <button onClick={handleUpload}>Upload Resume</button>
      {uploadStatus && <p className="upload-status">{uploadStatus}</p>}
    </div>

    <div className="resume-card">
      <h3>Your Resumes</h3>
      {resumes.length === 0 ? (
        <p>No resumes uploaded yet.</p>
      ) : (
        <ul className="resume-list">
          {resumes.map((resume) => (
            <li key={resume.id} className="resume-item">
              <div className="resume-info">
                <span className="resume-name">{resume.original_filename}</span>
                <span className="resume-size">
                  {(resume.file_size / 1024).toFixed(1)} KB
                </span>
                <span className="resume-date">
                  {new Date(resume.uploaded_at).toLocaleDateString()}
                </span>
              </div>
              <button 
                className="download-btn"
                onClick={() => handleDownload(resume.id, resume.original_filename)}
              >
                Download (Decrypt)
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
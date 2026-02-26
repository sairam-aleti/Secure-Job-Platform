import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { profileAPI, resumeAPI, jobAPI, applicationAPI, authAPI, connectionAPI, userAPI } from '../services/api'; 
import cryptoService from '../services/cryptoService'; 
import './Dashboard.css';

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
  const [viewers, setViewers] = useState([]); // State for profile viewers
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
      
      // Role-based data fetching
      if (response.data.role === 'job_seeker') {
        fetchResumes();
        fetchUserApplications(); 
        fetchRecommendations();
      } else if (response.data.role === 'recruiter') {
        fetchMyJobs();
        fetchRecruiterApplications(); 
        fetchPendingRequests(); 
      }

      // FETCH SYSTEM DATA (For everyone except admin)
      if (response.data.role !== 'admin') {
        fetchMyConnections();
        fetchProfileViewers(); // NOW ACTIVATED: Fetch who looked at your profile
      }

    } catch (err) {
      setError('Failed to load profile');
      if (err.response?.status === 401) {
        localStorage.clear();
        navigate('/login');
      }
    } finally {
      setLoading(false);
    }
  };

  const setupEncryption = async () => {
    const password = sessionStorage.getItem('user_pwd');
    if (!password) return;
    try {
      const { publicKey, privateKey } = cryptoService.generateKeyPair();
      const encryptedPrivKey = cryptoService.encryptPrivateKey(privateKey, password);
      localStorage.setItem('encrypted_private_key', encryptedPrivKey);
      await authAPI.updatePublicKey({ public_key: publicKey });
    } catch (err) { console.error(err); }
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

  const fetchPendingRequests = async () => {
    try {
      const response = await connectionAPI.getPending();
      setPendingRequests(response.data);
    } catch (err) { console.error(err); }
  };

  const fetchRecommendations = async () => {
    try {
        const res = await jobAPI.getRecommendations();
        setRecommendations(res.data);
    } catch (err) { console.error(err); }
  };

  const fetchMyConnections = async () => {
    try {
      const res = await userAPI.getDirectory();
      const linked = res.data.filter(u => u.connection_status === 'accepted');
      setConnections(linked);
    } catch (err) { console.error(err); }
  };
  
  const fetchProfileViewers = async () => {
    try {
        const res = await userAPI.getViewers();
        setViewers(res.data);
    } catch (err) {
        console.error("Failed to fetch profile viewers", err);
    }
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
      setUploadStatus('Uploading and parsing...');
      await resumeAPI.upload(formData);
      setUploadStatus('Resume uploaded successfully!');
      setFile(null);
      fetchResumes();
      fetchRecommendations();
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
      <nav className="app-nav">
        <a href="/dashboard" className="nav-brand">FortKnox</a>
        <div className="nav-center">
          <a href="/dashboard">Dashboard</a>
          {profile?.role !== 'admin' && <a href="/network">Network</a>}
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
            {pendingRequests.length > 0 && (
              <div className="card" style={{ borderLeft: '4px solid #f59e0b' }}>
                <div className="card-header">
                  <h3>Connection Requests</h3>
                  <span className="card-badge" style={{ background: '#fef3c7', color: '#92400e' }}>New Requests</span>
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
              </div>
            )}

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
                    <li key={app.id} className="resume-item" style={{ flexDirection: 'column', alignItems: 'flex-start' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', width: '100%', marginBottom: '15px' }}>
                        <div className="resume-info">
                          <div className="resume-details">
                            <span className="resume-name">
                                {app.applicant_name}
                                <span className="card-badge" style={{ marginLeft: '10px', background: app.match_score > 70 ? '#ecfdf5' : '#fff7ed', color: app.match_score > 70 ? '#065f46' : '#9a3412' }}>
                                    {app.match_score}% Match
                                </span>
                            </span>
                            <div className="resume-meta">
                              <span>Position: {app.job_title}</span>
                              <span>Applied: {new Date(app.applied_at).toLocaleDateString()}</span>
                            </div>
                          </div>
                        </div>
                        
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                          <span style={{ fontSize: '13px', color: '#6b7280', fontWeight: '600' }}>Status:</span>
                          <select 
                            className="status-badge"
                            style={{ padding: '5px 10px', borderRadius: '6px', border: '1px solid #d1d5db', background: '#ffffff', fontSize: '13px', cursor: 'pointer'}}
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

                      <div style={{ display: 'flex', gap: '10px', width: '100%' }}>
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
            {recommendations.length > 0 && (
              <div className="card">
                <div className="card-header">
                  <h3>Recommended for You</h3>
                  <span className="card-badge" style={{ background: '#eef2ff', color: '#3461c7' }}>Intelligent Matching</span>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '20px', marginTop: '10px' }}>
                  {recommendations.map((job) => (
                    <div key={job.job_id} className="stat-item" style={{ border: '1px solid #e5e7eb', cursor: 'pointer' }} onClick={() => navigate(`/apply/${job.job_id}`)}>
                      <div className="stat-label" style={{ color: '#059669', fontWeight: '700' }}>{job.match_score}% Match</div>
                      <div className="stat-value" style={{ fontSize: '16px', marginBottom: '5px' }}>{job.title}</div>
                      <div style={{ fontSize: '13px', color: '#6b7280' }}>{job.company} • {job.location}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

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

        {/* --- RECENT VIEWERS SECTION (Requirement 2A) --- */}
        {profile?.role !== 'admin' && (
          <div className="card">
            <div className="card-header">
              <h3>Recent Profile Viewers</h3>
              <span className="card-badge" style={{ background: '#f3f4f6', color: '#4b5563' }}>Last 5 visits</span>
            </div>
            {viewers.length === 0 ? (
              <p style={{ color: '#9ca3af', textAlign: 'center', padding: '24px 0' }}>No recent views recorded.</p>
            ) : (
              <ul className="resume-list">
                {viewers.map((viewer, index) => (
                  <li key={index} className="resume-item">
                    <div className="resume-info">
                      <span className="resume-name">{viewer.viewer_name}</span>
                      <span className="resume-meta">Viewed on: {new Date(viewer.timestamp).toLocaleString()}</span>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}

        {/* --- YOUR NETWORK SECTION --- */}
        {profile?.role !== 'admin' && (
          <div className="card">
            <div className="card-header">
              <h3>Your Network</h3>
              <span className="card-badge" style={{ background: '#eef2ff', color: '#3461c7' }}>
                {connections.length} Professional{connections.length !== 1 ? 's' : ''}
              </span>
            </div>
            {connections.length === 0 ? (
              <p style={{ color: '#9ca3af', textAlign: 'center', padding: '24px 0' }}>
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
                    <button 
                      className="download-btn" 
                      style={{ borderColor: '#667eea', color: '#667eea' }}
                      onClick={() => navigate(`/chat/${conn.id}`)}
                    >
                      Message
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}

        {error && <div className="error-message">{error}</div>}
      </main>
    </div>
  );
}

export default Dashboard;
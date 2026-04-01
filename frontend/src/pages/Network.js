import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { userAPI, connectionAPI, profileAPI } from '../services/api';
import { motion } from 'framer-motion';
import './Dashboard.css';

function Network() {
  const [users, setUsers] = useState([]);
  const [profile, setProfile] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [statusMessage, setStatusMessage] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    fetchData();
  }, [searchTerm, page]);

  const fetchData = async () => {
    try {
      setLoading(true);
      if (!profile) {
        const profRes = await profileAPI.getProfile();
        setProfile(profRes.data);
      }
      const dirRes = await userAPI.getDirectory(searchTerm, page);
      setUsers(dirRes.data);
    } catch (err) {
      console.error('Failed to load directory');
    } finally {
      setLoading(false);
    }
  };

  const handleConnect = async (userId) => {
    try {
      await connectionAPI.sendRequest(userId);
      setStatusMessage("Connection request sent.");
      fetchData(); 
      setTimeout(() => setStatusMessage(''), 3000);
    } catch (err) {
      alert(err.response?.data?.detail || "Request failed.");
    }
  };

  const handleAcceptDecline = async (requestId, status) => {
    try {
      await connectionAPI.updateRequest(requestId, status);
      setStatusMessage(status === 'accepted' ? "Connection accepted." : "Request declined.");
      fetchData();
      setTimeout(() => setStatusMessage(''), 3000);
    } catch (err) {
      alert("Action failed.");
    }
  };

  const handleLogout = () => {
    localStorage.clear();
    sessionStorage.clear();
    navigate('/login');
  };

  return (
    <div className="app-layout">
      <div className="app-grid-bg"></div>

      <nav className="app-nav">
        <a href="/dashboard" className="nav-brand">Fort<span>Knox</span></a>
        <div className="nav-center">
          <a href="/dashboard">Dashboard</a>
          <a href="/network">Network</a>
          <a href="/jobs">Job Board</a>
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
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--cy-text-mute)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                )}
              </div>
            </div>
          )}
          <button className="btn-logout" onClick={handleLogout}>Sign Out</button>
        </div>
      </nav>

      <div className="page-hero">
        <div className="page-hero-inner">
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '10px', color: 'var(--cy-brand)', textTransform: 'uppercase', letterSpacing: '2px', marginBottom: '12px' }}>NETWORK_DIRECTORY</div>
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
              <h2 style={{ margin: 0 }}>Professional Directory</h2>
              <p style={{ margin: 0, marginTop: '4px' }}>Connect with other professionals on the platform</p>
            </div>
          </div>
        </div>
      </div>

      <main className="app-content">
        <motion.div className="card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
          <div className="form-group" style={{ marginBottom: 0 }}>
            <label>Search Members</label>
            <input type="text" placeholder="Search by name..." value={searchTerm}
              onChange={(e) => { setSearchTerm(e.target.value); setPage(1); }}
            />
          </div>
        </motion.div>

        {statusMessage && <div className="success-message">{statusMessage}</div>}

        <motion.div className="card" style={{ marginTop: '20px' }} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
          <div className="admin-table-wrapper">
            <table className="admin-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Headline</th>
                  <th>Role</th>
                  <th style={{ textAlign: 'right' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr><td colSpan="4" style={{ textAlign: 'center', padding: '20px', fontFamily: 'JetBrains Mono, monospace', fontSize: '12px', color: 'var(--cy-text-mute)' }}>Loading...</td></tr>
                ) : users.length === 0 ? (
                  <tr><td colSpan="4" style={{ textAlign: 'center', padding: '20px', fontFamily: 'JetBrains Mono, monospace', fontSize: '12px', color: 'var(--cy-text-mute)' }}>No members found.</td></tr>
                ) : (
                  users.map((u) => (
                    <tr key={u.id}>
                      <td 
                        onClick={() => navigate(`/user-profile/${u.id}`)} 
                        style={{ cursor: 'pointer', color: 'var(--cy-brand)', fontWeight: '600', fontFamily: 'Space Grotesk, sans-serif' }}
                      >
                        {u.full_name}
                      </td>
                      <td style={{ fontSize: '13px', color: 'var(--cy-text-mute)' }}>{u.headline}</td>
                      <td style={{ textTransform: 'capitalize' }}>{u.role.replace('_', ' ')}</td>
                      <td style={{ textAlign: 'right' }}>
                        {u.connection_status === 'none' && (
                          <button className="download-btn" onClick={() => handleConnect(u.id)}>Connect</button>
                        )}
                        {u.connection_status === 'request_sent' && (
                          <span className="status-badge suspended">Pending</span>
                        )}
                        {u.connection_status === 'request_received' && (
                          <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
                            <button className="btn-activate" style={{ padding: '4px 12px' }} onClick={() => handleAcceptDecline(u.request_id, 'accepted')}>Accept</button>
                            <button className="btn-delete" style={{ padding: '4px 12px' }} onClick={() => handleAcceptDecline(u.request_id, 'rejected')}>Decline</button>
                          </div>
                        )}
                        {u.connection_status === 'accepted' && (
                          <span className="status-badge active">Connected</span>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </motion.div>
      </main>
    </div>
  );
}

export default Network;
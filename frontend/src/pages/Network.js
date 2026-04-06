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
  const [activeView, setActiveView] = useState('network');
  const [connections, setConnections] = useState([]);
  const [pendingRequests, setPendingRequests] = useState([]);
  const [networkPage, setNetworkPage] = useState(1);
  const NETWORK_PAGE_SIZE = 7;
  const navigate = useNavigate();

  useEffect(() => {
    fetchData();
    fetchMyConnections();
    fetchPendingRequests();
  }, [searchTerm, page]);

  const fetchMyConnections = async () => {
    try {
      const response = await connectionAPI.getMyConnections();
      setConnections(response.data);
    } catch (err) { }
  };

  const fetchPendingRequests = async () => {
    try {
      const response = await connectionAPI.getPending();
      setPendingRequests(response.data);
    } catch (err) { }
  };

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
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--cy-text-mute)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" /><circle cx="12" cy="7" r="4" /></svg>
                )}
              </div>
            </div>
          )}
          <button className="download-btn" onClick={() => navigate('/dashboard')} style={{ marginRight: '8px', fontSize: '12px', padding: '7px 14px' }}>← Dashboard</button>
          <button className="btn-logout" onClick={handleLogout}>Sign Out</button>
        </div>
      </nav>

      <div className="page-hero">
        <div className="page-hero-inner">
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '10px', color: 'var(--cy-brand)', textTransform: 'uppercase', letterSpacing: '2px', marginBottom: '12px' }}>PROFESSIONAL_NETWORK</div>
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
              <h2 style={{ margin: 0 }}>Your Network</h2>
              <p style={{ margin: 0, marginTop: '4px' }}>View your connections, manage requests, and search for new professionals</p>
            </div>
          </div>
        </div>
      </div>

      <main className="app-content">
        <div style={{ display: 'flex', gap: '16px', marginBottom: '24px' }}>
          <button className={activeView === 'network' ? "btn-upload" : "download-btn"} onClick={() => setActiveView('network')}>My Network</button>
          <button className={activeView === 'directory' ? "btn-upload" : "download-btn"} onClick={() => setActiveView('directory')}>Search Members</button>
        </div>

        {statusMessage && <div className="success-message">{statusMessage}</div>}

        {activeView === 'network' ? (
          <>
            {pendingRequests.length > 0 && (
              <motion.div className="card" style={{ borderLeft: '3px solid #f59e0b', marginBottom: '20px' }} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
                <div className="card-header">
                  <h3>Connection Requests</h3>
                  <span className="card-badge" style={{ background: 'rgba(245,158,11,0.1)', color: '#92400e', border: '1px dashed rgba(245,158,11,0.3)' }}>New Requests</span>
                </div>
                <ul className="resume-list" style={{ maxHeight: '420px', overflowY: 'auto', paddingRight: '8px' }}>
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

            <motion.div className="card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
              <div className="card-header">
                <h3>Your Network</h3>
                <span className="card-badge" style={{ background: 'rgba(10,102,194,0.08)', color: 'var(--cy-brand)' }}>
                  {connections.length} Professional{connections.length !== 1 ? 's' : ''}
                </span>
              </div>
              {connections.length === 0 ? (
                <p style={{ color: 'var(--cy-text-mute)', textAlign: 'center', padding: '24px 0', fontFamily: 'JetBrains Mono, monospace', fontSize: '12px' }}>
                  No active connections. Click 'Search Members' to build your network.
                </p>
              ) : (
                <>
                  <ul className="resume-list" style={{ maxHeight: '420px', overflowY: 'auto', paddingRight: '8px' }}>
                    {connections.slice((networkPage - 1) * NETWORK_PAGE_SIZE, networkPage * NETWORK_PAGE_SIZE).map((conn) => (
                      <li key={conn.id} className="resume-item">
                        <div className="resume-info">
                          <div className="resume-details">
                            <span className="resume-name" style={{ margin: 0, color: 'var(--cy-brand)', fontSize: '15px' }}>{conn.full_name}</span>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', marginTop: '4px' }}>
                              <span style={{ textTransform: 'capitalize', fontSize: '11px', color: 'var(--cy-text-main)', fontWeight: 'bold', fontFamily: 'JetBrains Mono, monospace' }}>
                                {conn.role.replace('_', ' ')}
                              </span>
                              <span style={{ fontSize: '11px', color: 'var(--cy-text-mute)', fontFamily: 'JetBrains Mono, monospace' }}>
                                Connected since: {conn.created_at ? new Date(conn.created_at).toLocaleDateString('en-US', { month: 'short', year: 'numeric' }) : 'Unknown'}
                              </span>
                            </div>
                          </div>
                        </div>
                        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                          <button
                            className="download-btn"
                            onClick={() => navigate(`/chat/${conn.id}`)}
                            style={{ padding: '6px 14px', fontSize: '11px', background: 'rgba(10,102,194,0.1)', color: 'var(--cy-brand)', border: '1px dashed rgba(10,102,194,0.3)', boxShadow: '0 2px 4px rgba(0,0,0,0.1)' }}
                          >
                            Message
                          </button>
                          
                          <button
                            className="download-btn"
                            onClick={() => navigate(`/user-profile/${conn.id}`)}
                            style={{ padding: '6px 14px', fontSize: '11px', background: 'transparent', color: 'var(--cy-text-main)', border: '1px solid var(--cy-border)' }}
                          >
                            View Profile
                          </button>

                          <button
                            className="btn-delete"
                            onClick={async () => {
                              if (window.confirm(`Remove ${conn.full_name}?`)) {
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
                  {connections.length > NETWORK_PAGE_SIZE && (
                    <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', padding: '12px 24px 0', borderTop: '1px solid var(--cy-border)', marginTop: '8px' }}>
                      <button disabled={networkPage === 1} onClick={() => setNetworkPage(p => p - 1)} style={{ padding: '4px 12px', fontSize: '11px', borderRadius: '4px', border: '1px solid var(--cy-border)', background: 'var(--cy-glass-bg)', cursor: networkPage === 1 ? 'not-allowed' : 'pointer', color: 'var(--cy-text-main)', opacity: networkPage === 1 ? 0.4 : 1 }}>← Prev</button>
                      <span style={{ fontSize: '11px', color: 'var(--cy-text-mute)', alignSelf: 'center', fontFamily: 'JetBrains Mono, monospace' }}>{networkPage} / {Math.ceil(connections.length / NETWORK_PAGE_SIZE)}</span>
                      <button disabled={networkPage * NETWORK_PAGE_SIZE >= connections.length} onClick={() => setNetworkPage(p => p + 1)} style={{ padding: '4px 12px', fontSize: '11px', borderRadius: '4px', border: '1px solid var(--cy-border)', background: 'var(--cy-glass-bg)', cursor: networkPage * NETWORK_PAGE_SIZE >= connections.length ? 'not-allowed' : 'pointer', color: 'var(--cy-text-main)', opacity: networkPage * NETWORK_PAGE_SIZE >= connections.length ? 0.4 : 1 }}>Next →</button>
                    </div>
                  )}
                </>
              )}
            </motion.div>
          </>
        ) : (
          <>
            <motion.div className="card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
              <div className="form-group" style={{ marginBottom: 0 }}>
                <label>Search Directory</label>
                <input type="text" placeholder="Search by name..." value={searchTerm}
                  onChange={(e) => { setSearchTerm(e.target.value); setPage(1); }}
                />
              </div>
            </motion.div>

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
                          <td style={{ fontWeight: '600', fontFamily: 'Space Grotesk, sans-serif', color: 'var(--cy-text-main)' }}>
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
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', padding: '12px 16px', borderTop: '1px solid var(--cy-border)' }}>
                <button disabled={page === 1} onClick={() => setPage(p => p - 1)} style={{ padding: '4px 10px', fontSize: '11px', borderRadius: '4px', border: '1px solid var(--cy-border)', background: 'var(--cy-glass-bg)', cursor: page === 1 ? 'not-allowed' : 'pointer', opacity: page === 1 ? 0.4 : 1, color: 'var(--cy-text-main)' }}>← Prev</button>
                <span style={{ fontSize: '11px', color: 'var(--cy-text-mute)', alignSelf: 'center', fontFamily: 'JetBrains Mono, monospace' }}>Page {page}</span>
                <button disabled={users.length < 20} onClick={() => setPage(p => p + 1)} style={{ padding: '4px 10px', fontSize: '11px', borderRadius: '4px', border: '1px solid rgba(10,102,194,0.3)', background: 'rgba(10,102,194,0.06)', cursor: users.length < 20 ? 'not-allowed' : 'pointer', opacity: users.length < 20 ? 0.4 : 1, color: 'var(--cy-brand)', fontWeight: '600' }}>Next →</button>
              </div>
            </motion.div>
          </>
        )}
      </main>
    </div>
  );
}

export default Network;
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { userAPI, connectionAPI, profileAPI } from '../services/api';
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
      <nav className="app-nav">
        <a href="/dashboard" className="nav-brand">FortKnox</a>
        <div className="nav-center">
          <a href="/dashboard">Dashboard</a>
          <a href="/network">Network</a>
          <a href="/jobs">Job Board</a>
        </div>
        <div className="nav-actions">
          <button className="btn-logout" onClick={handleLogout}>Sign Out</button>
        </div>
      </nav>

      <div className="page-hero">
        <div className="page-hero-inner">
          <h2>Professional Directory</h2>
          <p>Connect with other professionals on the platform</p>
        </div>
      </div>

      <main className="app-content">
        <div className="card">
          <div className="form-group" style={{ marginBottom: 0 }}>
            <label>Search Members</label>
            <input 
              type="text" 
              placeholder="Search by name..." 
              value={searchTerm}
              onChange={(e) => { setSearchTerm(e.target.value); setPage(1); }}
            />
          </div>
        </div>

        {statusMessage && <div className="success-message">{statusMessage}</div>}

        <div className="card" style={{ marginTop: '20px' }}>
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
                  <tr><td colSpan="4" style={{ textAlign: 'center', padding: '20px' }}>Loading...</td></tr>
                ) : users.length === 0 ? (
                  <tr><td colSpan="4" style={{ textAlign: 'center', padding: '20px' }}>No members found.</td></tr>
                ) : (
                  users.map((u) => (
                    <tr key={u.id}>
                      <td 
                        onClick={() => navigate(`/user-profile/${u.id}`)} 
                        style={{ cursor: 'pointer', color: '#3461c7', textDecoration: 'underline' }}
                      >
                        <strong>{u.full_name}</strong>
                      </td>
                      <td style={{ fontSize: '13px', color: '#6b7280' }}>{u.headline}</td>
                      <td style={{ textTransform: 'capitalize' }}>{u.role.replace('_', ' ')}</td>
                      <td style={{ textAlign: 'right' }}>
                        {/* CASE 1: STRANGER */}
                        {u.connection_status === 'none' && (
                          <button className="download-btn" onClick={() => handleConnect(u.id)}>Connect</button>
                        )}

                        {/* CASE 2: REQUEST SENT BY ME */}
                        {u.connection_status === 'request_sent' && (
                          <span className="status-badge suspended">Pending</span>
                        )}

                        {/* CASE 3: REQUEST RECEIVED BY ME */}
                        {u.connection_status === 'request_received' && (
                          <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
                            <button className="btn-activate" style={{ padding: '4px 12px' }} onClick={() => handleAcceptDecline(u.request_id, 'accepted')}>Accept</button>
                            <button className="btn-delete" style={{ padding: '4px 12px' }} onClick={() => handleAcceptDecline(u.request_id, 'rejected')}>Decline</button>
                          </div>
                        )}

                        {/* CASE 4: ALREADY CONNECTED */}
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
        </div>
      </main>
    </div>
  );
}

export default Network;
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { adminAPI, profileAPI, authAPI } from '../services/api'; 
import api from '../services/api'; // Direct api access for logs
import './Dashboard.css';

function Admin() {
  const [users, setUsers] = useState([]);
  const [logs, setLogs] = useState([]); // NEW: Store Audit Logs
  const [currentUser, setCurrentUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [actionMessage, setActionMessage] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    const token = localStorage.getItem('access_token');
    if (!token) {
      navigate('/login');
      return;
    }
    checkAdminAccess();
  }, [navigate]);

  const checkAdminAccess = async () => {
    try {
      const profileResponse = await profileAPI.getProfile();
      setCurrentUser(profileResponse.data);
      
      if (profileResponse.data.role !== 'admin') {
        setError('Access Denied: Admin privileges required');
        setLoading(false);
        return;
      }
      
      await fetchData();
    } catch (err) {
      setError('Failed to verify admin access');
      if (err.response?.status === 401) {
        localStorage.removeItem('access_token');
        navigate('/login');
      }
      setLoading(false);
    }
  };

  const fetchData = async () => {
    try {
      // Fetch both Users and Audit Logs in parallel
      const [userRes, logRes] = await Promise.all([
        adminAPI.listUsers(),
        api.get('/admin/audit-logs')
      ]);
      setUsers(userRes.data);
      setLogs(logRes.data);
    } catch (err) {
      setError('Failed to load system data');
    } finally {
      setLoading(false);
    }
  };

  const handleSuspend = async (userId, userEmail) => {
    if (!window.confirm(`Are you sure you want to suspend ${userEmail}?`)) return;
    try {
      await adminAPI.suspendUser(userId);
      setActionMessage(`User ${userEmail} suspended.`);
      await fetchData(); // Refresh users and logs
    } catch (err) { setError('Action failed'); }
  };

  const handleActivate = async (userId, userEmail) => {
    try {
      await adminAPI.activateUser(userId);
      setActionMessage(`User ${userEmail} activated.`);
      await fetchData();
    } catch (err) { setError('Action failed'); }
  };

  const handleDelete = async (userId, userEmail) => {
    if (!window.confirm(`Permanently delete ${userEmail}?`)) return;
    try {
      await adminAPI.deleteUser(userId);
      setActionMessage(`User ${userEmail} deleted.`);
      await fetchData();
    } catch (err) { setError('Action failed'); }
  };

  const handleLogout = () => {
    localStorage.clear();
    sessionStorage.clear();
    navigate('/login');
  };

  if (loading) {
    return (
      <div className="app-layout">
        <nav className="app-nav">
          <a href="/dashboard" className="nav-brand">FortKnox</a>
        </nav>
        <main className="app-content">
          <p style={{ textAlign: 'center', marginTop: '80px' }}>Loading Admin Panel...</p>
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
          <a href="/admin">Admin Panel</a>
        </div>
        <div className="nav-actions">
          <button className="btn-logout" onClick={handleLogout}>Sign Out</button>
        </div>
      </nav>

      <div className="page-hero">
        <div className="page-hero-inner">
          <h2>Admin Control Center</h2>
          <p>Platform monitoring and tamper-evident auditing</p>
        </div>
      </div>

      <main className="app-content">
        {/* STATS */}
        <div className="stats-row">
          <div className="stat-item">
            <div className="stat-label">Total Users</div>
            <div className="stat-value">{users.length}</div>
          </div>
          <div className="stat-item">
            <div className="stat-label">System Logs</div>
            <div className="stat-value">{logs.length}</div>
          </div>
          <div className="stat-item">
            <div className="stat-label">Admin Status</div>
            <div className="stat-value" style={{ color: '#059669' }}>Active</div>
          </div>
        </div>

        {actionMessage && <div className="success-message">{actionMessage}</div>}
        {error && <div className="error-message">{error}</div>}

        {/* USER MANAGEMENT CARD */}
        <div className="card">
          <div className="card-header">
            <h3>User Management</h3>
          </div>
          <div className="admin-table-wrapper">
            <table className="admin-table">
              <thead>
                <tr>
                  <th>Email</th>
                  <th>Role</th>
                  <th>Verified</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((user) => (
                  <tr key={user.id}>
                    <td>{user.email}</td>
                    <td><span className={`role-badge role-${user.role}`}>{user.role}</span></td>
                    <td>{user.is_verified ? '✓ Yes' : 'No'}</td>
                    <td>
                      <span className={`status-badge ${user.is_active ? 'active' : 'suspended'}`}>
                        {user.is_active ? 'Active' : 'Suspended'}
                      </span>
                    </td>
                    <td className="action-buttons">
                      {user.role !== 'admin' && (
                        <>
                          {user.is_active ? (
                            <button className="btn-suspend" onClick={() => handleSuspend(user.id, user.email)}>Suspend</button>
                          ) : (
                            <button className="btn-activate" onClick={() => handleActivate(user.id, user.email)}>Activate</button>
                          )}
                          <button className="btn-delete" onClick={() => handleDelete(user.id, user.email)}>Delete</button>
                        </>
                      )}
                      {user.role === 'admin' && <span className="no-action">Protected</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* --- NEW: SECURE AUDIT TRAIL CARD --- */}
        <div className="card" style={{ marginTop: '32px' }}>
          <div className="card-header">
            <h3>Secure Audit Trail (Hash-Chained)</h3>
            <span className="card-badge" style={{ background: '#ecfdf5', color: '#065f46' }}>Integrity Verified</span>
          </div>
          <div className="admin-table-wrapper">
            <table className="admin-table">
              <thead>
                <tr>
                  <th>Action</th>
                  <th>Admin</th>
                  <th>Target</th>
                  <th>Timestamp</th>
                  <th>Security Hash (SHA-256)</th>
                </tr>
              </thead>
              <tbody>
                {logs.length === 0 ? (
                  <tr><td colSpan="5" style={{ textAlign: 'center', padding: '20px' }}>No logs recorded yet.</td></tr>
                ) : (
                  logs.map((log) => (
                    <tr key={log.id}>
                      <td><strong>{log.action}</strong></td>
                      <td>{log.performed_by}</td>
                      <td>{log.target_user || '-'}</td>
                      <td style={{ fontSize: '12px' }}>{new Date(log.timestamp).toLocaleString()}</td>
                      <td style={{ fontSize: '10px', fontFamily: 'monospace', color: '#6b7280' }}>
                        {log.log_hash.substring(0, 24)}...
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

export default Admin;
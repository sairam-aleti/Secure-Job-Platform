import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { adminAPI, profileAPI } from '../services/api';
import './Dashboard.css';

function Admin() {
  const [users, setUsers] = useState([]);
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
      
      fetchUsers();
    } catch (err) {
      setError('Failed to verify admin access');
      if (err.response?.status === 401) {
        localStorage.removeItem('access_token');
        navigate('/login');
      }
      setLoading(false);
    }
  };

  const fetchUsers = async () => {
    try {
      const response = await adminAPI.listUsers();
      setUsers(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to load users');
    } finally {
      setLoading(false);
    }
  };

  const handleSuspend = async (userId, userEmail) => {
    if (!window.confirm(`Are you sure you want to suspend ${userEmail}?`)) {
      return;
    }
    
    try {
      await adminAPI.suspendUser(userId);
      setActionMessage(`User ${userEmail} has been suspended`);
      fetchUsers();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to suspend user');
    }
  };

  const handleActivate = async (userId, userEmail) => {
    try {
      await adminAPI.activateUser(userId);
      setActionMessage(`User ${userEmail} has been activated`);
      fetchUsers();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to activate user');
    }
  };

  const handleDelete = async (userId, userEmail) => {
    if (!window.confirm(`Are you sure you want to permanently delete ${userEmail}? This action cannot be undone.`)) {
      return;
    }
    
    try {
      await adminAPI.deleteUser(userId);
      setActionMessage(`User ${userEmail} has been deleted`);
      fetchUsers();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to delete user');
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('user_email');
    navigate('/login');
  };

  if (loading) {
    return (
      <div className="app-layout">
        <nav className="app-nav">
          <a href="/dashboard" className="nav-brand">FortKnox</a>
          <div className="nav-center">
            <a href="/dashboard">Dashboard</a>
            <a href="/admin">Admin</a>
          </div>
          <div className="nav-actions">
            <button className="btn-logout" onClick={handleLogout}>Sign Out</button>
          </div>
        </nav>
        <main className="app-content">
          <p style={{ textAlign: 'center', color: '#6b7280', marginTop: '80px', fontSize: '15px' }}>Loading admin panel...</p>
        </main>
      </div>
    );
  }

  if (currentUser?.role !== 'admin') {
    return (
      <div className="app-layout">
        <nav className="app-nav">
          <a href="/dashboard" className="nav-brand">FortKnox</a>
          <div className="nav-center">
            <a href="/dashboard">Dashboard</a>
          </div>
          <div className="nav-actions">
            <button className="btn-logout" onClick={handleLogout}>Sign Out</button>
          </div>
        </nav>
        <main className="app-content">
          <div className="error-card">
            <h2>Access Denied</h2>
            <p>You do not have permission to access the Admin Panel.</p>
            <p>Only users with admin role can access this page.</p>
            <a href="/dashboard" className="back-link">Return to Dashboard</a>
          </div>
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
          <a href="/admin">Admin</a>
        </div>
        <div className="nav-actions">
          <button className="btn-logout" onClick={handleLogout}>Sign Out</button>
        </div>
      </nav>

      <div className="page-hero">
        <div className="page-hero-inner">
          <h2>Admin Panel</h2>
          <p>Manage users and platform settings</p>
        </div>
      </div>

      <main className="app-content">

        <div className="stats-row">
          <div className="stat-item">
            <div className="stat-label">Total Users</div>
            <div className="stat-value">{users.length}</div>
          </div>
          <div className="stat-item">
            <div className="stat-label">Active</div>
            <div className="stat-value" style={{ color: '#059669' }}>{users.filter(u => u.is_active).length}</div>
          </div>
          <div className="stat-item">
            <div className="stat-label">Suspended</div>
            <div className="stat-value" style={{ color: '#dc2626' }}>{users.filter(u => !u.is_active).length}</div>
          </div>
        </div>

        {actionMessage && (
          <div className="success-message">{actionMessage}</div>
        )}
        
        {error && <div className="error-message">{error}</div>}

        <div className="card">
          <div className="card-header">
            <h3>User Management</h3>
            <span className="card-badge" style={{ background: '#eef2ff', color: '#3461c7' }}>
              {users.length} user{users.length !== 1 ? 's' : ''}
            </span>
          </div>
          <div className="admin-table-wrapper">
            <table className="admin-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Email</th>
                  <th>Name</th>
                  <th>Role</th>
                  <th>Verified</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((user) => (
                  <tr key={user.id}>
                    <td>{user.id}</td>
                    <td>{user.email}</td>
                    <td>{user.full_name}</td>
                    <td>
                      <span className={`role-badge role-${user.role}`}>
                        {user.role}
                      </span>
                    </td>
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
                            <button 
                              className="btn-suspend"
                              onClick={() => handleSuspend(user.id, user.email)}
                            >
                              Suspend
                            </button>
                          ) : (
                            <button 
                              className="btn-activate"
                              onClick={() => handleActivate(user.id, user.email)}
                            >
                              Activate
                            </button>
                          )}
                          <button 
                            className="btn-delete"
                            onClick={() => handleDelete(user.id, user.email)}
                          >
                            Delete
                          </button>
                        </>
                      )}
                      {user.role === 'admin' && (
                        <span className="no-action">Protected</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </main>
    </div>
  );
}

export default Admin;
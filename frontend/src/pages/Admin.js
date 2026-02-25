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
      <div className="dashboard-container">
        <p>Loading...</p>
      </div>
    );
  }

  if (currentUser?.role !== 'admin') {
    return (
      <div className="dashboard-container">
        <nav className="dashboard-nav">
          <h1>Secure Job Platform</h1>
          <div className="nav-links">
            <a href="/dashboard">Dashboard</a>
            <button onClick={handleLogout}>Logout</button>
          </div>
        </nav>
        <main className="dashboard-main">
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
    <div className="dashboard-container">
      <nav className="dashboard-nav">
        <h1>Admin Panel</h1>
        <div className="nav-links">
          <a href="/dashboard">Dashboard</a>
          <button onClick={handleLogout}>Logout</button>
        </div>
      </nav>

      <main className="dashboard-main">
        <div className="welcome-card">
          <h2>Admin Dashboard</h2>
          <p>Logged in as: {currentUser?.email}</p>
          <p>Total Users: {users.length}</p>
        </div>

        {actionMessage && (
          <div className="success-message">{actionMessage}</div>
        )}
        
        {error && <div className="error-message">{error}</div>}

        <div className="admin-card">
          <h3>User Management</h3>
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
                  <td>{user.is_verified ? 'Yes' : 'No'}</td>
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
      </main>
    </div>
  );
}

export default Admin;
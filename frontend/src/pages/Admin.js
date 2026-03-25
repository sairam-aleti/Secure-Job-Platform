import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { adminAPI, profileAPI } from '../services/api'; 
import api from '../services/api';
import './Dashboard.css';

function Admin() {
  const [users, setUsers] = useState([]);
  const [logs, setLogs] = useState([]);
  const [actionQueue, setActionQueue] = useState([]);
  const [currentUser, setCurrentUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [actionMessage, setActionMessage] = useState('');
  const [activeTab, setActiveTab] = useState('users');
  
  // Popup state
  const [showPopup, setShowPopup] = useState(false);
  const [pendingAction, setPendingAction] = useState(null);
  const [popupSending, setPopupSending] = useState(false);

  const navigate = useNavigate();

  const isSuperAdmin = currentUser?.role === 'superadmin';
  const isAdmin = currentUser?.role === 'admin' || isSuperAdmin;

  useEffect(() => {
    const token = localStorage.getItem('access_token');
    if (!token) { navigate('/login'); return; }
    checkAdminAccess();
  }, [navigate]);

  const checkAdminAccess = async () => {
    try {
      const profileResponse = await profileAPI.getProfile();
      setCurrentUser(profileResponse.data);
      
      if (profileResponse.data.role !== 'admin' && profileResponse.data.role !== 'superadmin') {
        setError('Access Denied: Admin or Superadmin privileges required');
        setLoading(false);
        return;
      }
      
      await fetchData(profileResponse.data.role);
    } catch (err) {
      setError('Failed to verify admin access');
      if (err.response?.status === 401) {
        localStorage.removeItem('access_token');
        navigate('/login');
      }
      setLoading(false);
    }
  };

  const fetchData = async (role) => {
    try {
      const promises = [
        adminAPI.listUsers(),
        api.get('/admin/audit-logs')
      ];
      
      // Superadmin also fetches the action queue
      if (role === 'superadmin') {
        promises.push(adminAPI.getActionQueue());
      } else {
        // Admin fetches their own submitted requests
        promises.push(adminAPI.getActionQueue().catch(() => ({ data: [] })));
      }
      
      const results = await Promise.all(promises);
      setUsers(results[0].data);
      setLogs(results[1].data);
      setActionQueue(results[2].data || []);
    } catch (err) {
      setError('Failed to load system data');
    } finally {
      setLoading(false);
    }
  };

  // ---- ADMIN: Show popup before destructive action ----
  const requestAction = (actionType, userId, userEmail) => {
    if (isSuperAdmin) {
      // Superadmin does it directly
      executeDirectAction(actionType, userId, userEmail);
    } else {
      // Admin: show popup
      setPendingAction({ action_type: actionType, target_user_id: userId, target_email: userEmail });
      setShowPopup(true);
    }
  };

  // ---- ADMIN: Send notification to superadmin ----
  const sendToSuperAdmin = async () => {
    if (!pendingAction) return;
    setPopupSending(true);
    try {
      await adminAPI.requestAction({
        action_type: pendingAction.action_type,
        target_user_id: pendingAction.target_user_id
      });
      setActionMessage(`Request to ${pendingAction.action_type} ${pendingAction.target_email} sent to Superadmin for approval.`);
      setShowPopup(false);
      setPendingAction(null);
      await fetchData(currentUser.role);
    } catch (err) {
      const msg = err.response?.data?.detail || 'Failed to submit request';
      setError(msg);
    } finally {
      setPopupSending(false);
    }
  };

  // ---- SUPERADMIN: Execute action directly ----
  const executeDirectAction = async (actionType, userId, userEmail) => {
    const confirmMsg = actionType === 'delete' 
      ? `PERMANENTLY delete ${userEmail}? This cannot be undone.`
      : `${actionType} user ${userEmail}?`;
    if (!window.confirm(confirmMsg)) return;

    try {
      if (actionType === 'suspend') await adminAPI.suspendUser(userId);
      else if (actionType === 'activate') await adminAPI.activateUser(userId);
      else if (actionType === 'delete') await adminAPI.deleteUser(userId);
      setActionMessage(`User ${userEmail} has been ${actionType}d.`);
      await fetchData(currentUser.role);
    } catch (err) { setError('Action failed: ' + (err.response?.data?.detail || 'Unknown error')); }
  };

  // ---- SUPERADMIN: Approve/Reject from queue ----
  const reviewQueueItem = async (queueId, decision) => {
    try {
      await adminAPI.reviewAction({ action_id: queueId, decision: decision });
      setActionMessage(`Request ${decision}d successfully.`);
      await fetchData(currentUser.role);
    } catch (err) { 
      setError('Review failed: ' + (err.response?.data?.detail || 'Unknown error')); 
    }
  };

  // ---- SUPERADMIN: Approve admin account ----
  const approveAdminAccount = async (userId, email) => {
    try {
      await adminAPI.approveAdmin(userId);
      setActionMessage(`Admin account ${email} approved.`);
      await fetchData(currentUser.role);
    } catch (err) { setError('Approval failed'); }
  };

  const handleLogout = () => {
    localStorage.clear();
    sessionStorage.clear();
    navigate('/login');
  };

  if (loading) {
    return (
      <div className="app-layout">
        <nav className="app-nav"><a href="/dashboard" className="nav-brand">FortKnox</a></nav>
        <main className="app-content">
          <p style={{ textAlign: 'center', marginTop: '80px' }}>Loading Admin Panel...</p>
        </main>
      </div>
    );
  }

  if (!isAdmin) {
    return (
      <div className="app-layout">
        <nav className="app-nav"><a href="/dashboard" className="nav-brand">FortKnox</a></nav>
        <main className="app-content">
          <div className="error-message" style={{ margin: '80px auto', maxWidth: '400px' }}>{error || 'Access Denied'}</div>
        </main>
      </div>
    );
  }

  const pendingRequests = actionQueue.filter(q => q.status === 'pending');
  const unapprovedAdmins = users.filter(u => u.role === 'admin' && u.is_admin_approved === false);

  return (
    <div className="app-layout">
      {/* ---- POPUP MODAL for admin requesting superadmin permission ---- */}
      {showPopup && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,0,0,0.6)', display: 'flex', alignItems: 'center',
          justifyContent: 'center', zIndex: 9999
        }}>
          <div style={{
            background: '#fff', borderRadius: '16px', padding: '32px',
            maxWidth: '440px', width: '90%', boxShadow: '0 20px 60px rgba(0,0,0,0.3)',
            textAlign: 'center'
          }}>
            <div style={{ width: '56px', height: '56px', borderRadius: '50%', background: '#fee2e2', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px', border: '2px solid #fecaca' }}>
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#dc2626" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            </div>
            <h3 style={{ margin: '0 0 8px', color: '#1e293b' }}>Superadmin Approval Required</h3>
            <p style={{ color: '#64748b', margin: '0 0 24px', lineHeight: '1.6' }}>
              The action <strong style={{ color: '#dc2626' }}>{pendingAction?.action_type}</strong> on 
              user <strong>{pendingAction?.target_email}</strong> requires 
              Superadmin authorization.
            </p>
            <p style={{ color: '#475569', marginBottom: '24px' }}>
              Would you like to send a notification to the Superadmin for approval?
            </p>
            <div style={{ display: 'flex', gap: '12px', justifyContent: 'center' }}>
              <button 
                onClick={sendToSuperAdmin} 
                disabled={popupSending}
                style={{
                  padding: '10px 24px', background: '#2563eb', color: '#fff',
                  border: 'none', borderRadius: '8px', cursor: 'pointer',
                  fontWeight: '600', fontSize: '14px'
                }}>
                {popupSending ? 'Sending...' : 'Yes, Notify Superadmin'}
              </button>
              <button 
                onClick={() => { setShowPopup(false); setPendingAction(null); }}
                style={{
                  padding: '10px 24px', background: '#f1f5f9', color: '#475569',
                  border: '1px solid #e2e8f0', borderRadius: '8px', cursor: 'pointer',
                  fontWeight: '600', fontSize: '14px'
                }}>
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ---- NAVBAR ---- */}
      <nav className="app-nav">
        <a href="/dashboard" className="nav-brand">FortKnox</a>
        <div className="nav-center">
          <a href="/dashboard">Dashboard</a>
          <a href="/admin">Admin Panel</a>
        </div>
        <div className="nav-actions">
          <span style={{ color: '#94a3b8', fontSize: '13px', marginRight: '12px' }}>
            {isSuperAdmin ? 'Superadmin' : 'Admin'}
          </span>
          <button className="btn-logout" onClick={handleLogout}>Sign Out</button>
        </div>
      </nav>

      <div className="page-hero">
        <div className="page-hero-inner">
          <h2>{isSuperAdmin ? 'Superadmin Control Center' : 'Admin Control Center'}</h2>
          <p>
            {isSuperAdmin 
              ? 'Full platform control — approve admin requests and manage all users'
              : 'Monitor users and logs — destructive actions require Superadmin approval'
            }
          </p>
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
          {isSuperAdmin && (
            <div className="stat-item">
              <div className="stat-label">Pending Requests</div>
              <div className="stat-value" style={{ color: pendingRequests.length > 0 ? '#dc2626' : '#059669' }}>
                {pendingRequests.length}
              </div>
            </div>
          )}
          <div className="stat-item">
            <div className="stat-label">Your Role</div>
            <div className="stat-value" style={{ color: '#059669', fontSize: '16px' }}>
              {isSuperAdmin ? 'Superadmin' : 'Admin'}
            </div>
          </div>
        </div>

        {actionMessage && <div className="success-message">{actionMessage}</div>}
        {error && <div className="error-message">{error}</div>}

        {/* TAB NAVIGATION */}
        <div style={{ display: 'flex', gap: '0', marginBottom: '24px', borderBottom: '2px solid #e2e8f0' }}>
          {['users', 'logs', ...(isSuperAdmin ? ['requests', 'admin-approvals'] : ['my-requests'])].map(tab => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              style={{
                padding: '12px 24px', border: 'none', cursor: 'pointer',
                background: activeTab === tab ? '#fff' : 'transparent',
                borderBottom: activeTab === tab ? '3px solid #2563eb' : '3px solid transparent',
                color: activeTab === tab ? '#2563eb' : '#64748b',
                fontWeight: activeTab === tab ? '700' : '500',
                fontSize: '14px', transition: 'all 0.2s'
              }}>
              {tab === 'users' && 'Users'}
              {tab === 'logs' && 'Audit Logs'}
              {tab === 'requests' && `Requests (${pendingRequests.length})`}
              {tab === 'admin-approvals' && `Admin Approvals (${unapprovedAdmins.length})`}
              {tab === 'my-requests' && 'My Requests'}
            </button>
          ))}
        </div>

        {/* ---- TAB: USER MANAGEMENT ---- */}
        {activeTab === 'users' && (
          <div className="card">
            <div className="card-header"><h3>User Management</h3></div>
            <div className="admin-table-wrapper">
              <table className="admin-table">
                <thead>
                  <tr>
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
                      <td>{user.email}</td>
                      <td>{user.full_name || '-'}</td>
                      <td><span className={`role-badge role-${user.role}`}>{user.role}</span></td>
                      <td>{user.is_verified ? '✓ Yes' : 'No'}</td>
                      <td>
                        <span className={`status-badge ${user.is_active ? 'active' : 'suspended'}`}>
                          {user.is_active ? 'Active' : 'Suspended'}
                        </span>
                      </td>
                      <td className="action-buttons">
                        {user.role !== 'superadmin' && user.email !== currentUser?.email && (
                          <>
                            {user.is_active ? (
                              <button className="btn-suspend" onClick={() => requestAction('suspend', user.id, user.email)}>
                                Suspend
                              </button>
                            ) : (
                              <button className="btn-activate" onClick={() => requestAction('activate', user.id, user.email)}>
                                Activate
                              </button>
                            )}
                            <button className="btn-delete" onClick={() => requestAction('delete', user.id, user.email)}>
                              Delete
                            </button>
                          </>
                        )}
                        {user.role === 'superadmin' && <span className="no-action">Protected</span>}
                        {user.email === currentUser?.email && <span className="no-action">You</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ---- TAB: AUDIT LOGS ---- */}
        {activeTab === 'logs' && (
          <div className="card">
            <div className="card-header">
              <h3>Secure Audit Trail (HMAC Hash-Chained)</h3>
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
                    <th>Security Hash</th>
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
        )}

        {/* ---- TAB: SUPERADMIN — PENDING ACTION REQUESTS ---- */}
        {activeTab === 'requests' && isSuperAdmin && (
          <div className="card">
            <div className="card-header">
              <h3>Admin Action Requests</h3>
              {pendingRequests.length > 0 && (
                <span className="card-badge" style={{ background: '#fef2f2', color: '#dc2626' }}>
                  {pendingRequests.length} Pending
                </span>
              )}
            </div>
            <div className="admin-table-wrapper">
              <table className="admin-table">
                <thead>
                  <tr>
                    <th>Requested By</th>
                    <th>Action</th>
                    <th>Target User</th>
                    <th>Status</th>
                    <th>Requested At</th>
                    <th>Decision</th>
                  </tr>
                </thead>
                <tbody>
                  {actionQueue.length === 0 ? (
                    <tr><td colSpan="6" style={{ textAlign: 'center', padding: '20px' }}>No requests yet.</td></tr>
                  ) : (
                    actionQueue.map((item) => (
                      <tr key={item.id}>
                        <td>{item.requested_by}</td>
                        <td>
                          <strong style={{ 
                            color: item.action_type === 'delete' ? '#dc2626' : 
                                   item.action_type === 'suspend' ? '#d97706' : '#059669' 
                          }}>
                            {item.action_type.toUpperCase()}
                          </strong>
                        </td>
                        <td>{item.target_user_email || `User #${item.target_user_id}`}</td>
                        <td>
                          <span style={{
                            padding: '4px 10px', borderRadius: '12px', fontSize: '12px', fontWeight: '600',
                            background: item.status === 'pending' ? '#fef3c7' : 
                                       item.status === 'approved' ? '#dcfce7' : '#fecaca',
                            color: item.status === 'pending' ? '#92400e' : 
                                   item.status === 'approved' ? '#166534' : '#991b1b'
                          }}>
                            {item.status}
                          </span>
                        </td>
                        <td style={{ fontSize: '12px' }}>{new Date(item.created_at).toLocaleString()}</td>
                        <td>
                          {item.status === 'pending' ? (
                            <div style={{ display: 'flex', gap: '8px' }}>
                              <button 
                                onClick={() => reviewQueueItem(item.id, 'approve')}
                                style={{
                                  padding: '6px 14px', background: '#059669', color: '#fff',
                                  border: 'none', borderRadius: '6px', cursor: 'pointer',
                                  fontWeight: '600', fontSize: '12px'
                                }}>
                                Approve
                              </button>
                              <button 
                                onClick={() => reviewQueueItem(item.id, 'reject')}
                                style={{
                                  padding: '6px 14px', background: '#dc2626', color: '#fff',
                                  border: 'none', borderRadius: '6px', cursor: 'pointer',
                                  fontWeight: '600', fontSize: '12px'
                                }}>
                                Reject
                              </button>
                            </div>
                          ) : (
                            <span style={{ color: '#94a3b8', fontSize: '12px' }}>
                              {item.reviewed_by ? `By ${item.reviewed_by}` : '-'}
                            </span>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ---- TAB: SUPERADMIN — ADMIN ACCOUNT APPROVALS ---- */}
        {activeTab === 'admin-approvals' && isSuperAdmin && (
          <div className="card">
            <div className="card-header">
              <h3>Admin Account Approvals</h3>
            </div>
            <div className="admin-table-wrapper">
              <table className="admin-table">
                <thead>
                  <tr>
                    <th>Email</th>
                    <th>Name</th>
                    <th>Status</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {unapprovedAdmins.length === 0 ? (
                    <tr><td colSpan="4" style={{ textAlign: 'center', padding: '20px' }}>No pending admin approvals.</td></tr>
                  ) : (
                    unapprovedAdmins.map((admin) => (
                      <tr key={admin.id}>
                        <td>{admin.email}</td>
                        <td>{admin.full_name || '-'}</td>
                        <td>
                          <span style={{
                            padding: '4px 10px', borderRadius: '12px', fontSize: '12px',
                            fontWeight: '600', background: '#fef3c7', color: '#92400e'
                          }}>
                            Pending Approval
                          </span>
                        </td>
                        <td>
                          <button 
                            onClick={() => approveAdminAccount(admin.id, admin.email)}
                            style={{
                              padding: '6px 14px', background: '#2563eb', color: '#fff',
                              border: 'none', borderRadius: '6px', cursor: 'pointer',
                              fontWeight: '600', fontSize: '12px'
                            }}>
                            Approve Admin
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ---- TAB: ADMIN — MY SUBMITTED REQUESTS ---- */}
        {activeTab === 'my-requests' && !isSuperAdmin && (
          <div className="card">
            <div className="card-header">
              <h3>My Submitted Requests</h3>
            </div>
            <div className="admin-table-wrapper">
              <table className="admin-table">
                <thead>
                  <tr>
                    <th>Action</th>
                    <th>Target User</th>
                    <th>Status</th>
                    <th>Submitted At</th>
                    <th>Reviewed By</th>
                  </tr>
                </thead>
                <tbody>
                  {actionQueue.length === 0 ? (
                    <tr><td colSpan="5" style={{ textAlign: 'center', padding: '20px' }}>You haven't submitted any requests yet.</td></tr>
                  ) : (
                    actionQueue.map((item) => (
                      <tr key={item.id}>
                        <td>
                          <strong style={{ 
                            color: item.action_type === 'delete' ? '#dc2626' : 
                                   item.action_type === 'suspend' ? '#d97706' : '#059669' 
                          }}>
                            {item.action_type.toUpperCase()}
                          </strong>
                        </td>
                        <td>{item.target_user_email || `User #${item.target_user_id}`}</td>
                        <td>
                          <span style={{
                            padding: '4px 10px', borderRadius: '12px', fontSize: '12px', fontWeight: '600',
                            background: item.status === 'pending' ? '#fef3c7' : 
                                       item.status === 'approved' ? '#dcfce7' : '#fecaca',
                            color: item.status === 'pending' ? '#92400e' : 
                                   item.status === 'approved' ? '#166534' : '#991b1b'
                          }}>
                            {item.status === 'pending' ? 'Waiting for Superadmin' : 
                             item.status === 'approved' ? 'Approved & Executed' : 'Rejected'}
                          </span>
                        </td>
                        <td style={{ fontSize: '12px' }}>{new Date(item.created_at).toLocaleString()}</td>
                        <td>{item.reviewed_by || '—'}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

export default Admin;
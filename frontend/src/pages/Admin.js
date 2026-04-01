import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { adminAPI, profileAPI } from '../services/api'; 
import api from '../services/api';
import { motion } from 'framer-motion';
import './Dashboard.css';

function Admin() {
  const [users, setUsers] = useState([]);
  const [logs, setLogs] = useState([]);
  const [actionQueue, setActionQueue] = useState([]);
  const [reports, setReports] = useState([]);
  const [currentUser, setCurrentUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [actionMessage, setActionMessage] = useState('');
  const [activeTab, setActiveTab] = useState('users');
  
  // Blockchain state
  const [blocks, setBlocks] = useState([]);
  const [chainStatus, setChainStatus] = useState(null);
  const [miningBlock, setMiningBlock] = useState(false);
  
  const [showPopup, setShowPopup] = useState(false);
  const [pendingAction, setPendingAction] = useState(null);
  const [popupSending, setPopupSending] = useState(false);
  const [actionReason, setActionReason] = useState('');

  // Pagination state
  const [logsPage, setLogsPage] = useState(1);
  const logsPerPage = 10;
  const [blocksPage, setBlocksPage] = useState(1);
  const blocksPerPage = 5;

  const navigate = useNavigate();

  const isSuperAdmin = currentUser?.role === 'superadmin';
  const isAdmin = currentUser?.role === 'admin' || isSuperAdmin;

  useEffect(() => {
    const token = localStorage.getItem('access_token');
    if (!token) { navigate('/login'); return; }
    checkAdminAccess();
  }, [navigate]);

  useEffect(() => {
    if (actionMessage) {
      const timer = setTimeout(() => setActionMessage(''), 5000);
      return () => clearTimeout(timer);
    }
  }, [actionMessage]);

  useEffect(() => {
    if (error) {
      const timer = setTimeout(() => setError(''), 5000);
      return () => clearTimeout(timer);
    }
  }, [error]);

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
      
      if (role === 'superadmin') {
        promises.push(adminAPI.getActionQueue());
      } else {
        promises.push(adminAPI.getActionQueue().catch(() => ({ data: [] })));
      }
      
      const results = await Promise.all(promises);
      setUsers(results[0].data);
      setLogs(results[1].data);
      setActionQueue(results[2].data || []);
      
      try {
        const reportsRes = await adminAPI.getReports();
        setReports(reportsRes.data || []);
      } catch { setReports([]); }
    } catch (err) {
      setError('Failed to load system data');
    } finally {
      setLoading(false);
    }
  };

  const requestAction = (actionType, userId, userEmail) => {
    if (isSuperAdmin) {
      executeDirectAction(actionType, userId, userEmail);
    } else {
      setPendingAction({ action_type: actionType, target_user_id: userId, target_email: userEmail });
      setShowPopup(true);
    }
  };

  const sendToSuperAdmin = async () => {
    if (!pendingAction) return;
    setPopupSending(true);
    try {
      await adminAPI.requestAction({
        action_type: pendingAction.action_type,
        target_user_id: pendingAction.target_user_id,
        reason: actionReason
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

  const reviewQueueItem = async (queueId, decision) => {
    const backendDecision = decision === 'approve' ? 'approved' : 'rejected';
    try {
      await adminAPI.reviewAction({ action_id: queueId, decision: backendDecision });
      setActionMessage(`Request ${backendDecision} successfully.`);
      await fetchData(currentUser.role);
    } catch (err) { 
      const msg = err.response?.data?.detail;
      const errorString = typeof msg === 'object' ? JSON.stringify(msg) : (msg || err.message || 'Unknown error');
      setError('Review failed: ' + errorString); 
    }
  };

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

  const fetchBlockchain = async () => {
    try {
      const [blocksRes, verifyRes] = await Promise.all([
        adminAPI.getBlockchain(),
        adminAPI.verifyChain()
      ]);
      setBlocks(blocksRes.data);
      setChainStatus(verifyRes.data);
    } catch (err) {
      console.error('Failed to load blockchain data');
    }
  };

  const handleMineBlock = async () => {
    setMiningBlock(true);
    try {
      await adminAPI.mineBlock();
      setActionMessage('New block mined successfully!');
      await fetchBlockchain();
    } catch (err) {
      setActionMessage(err.response?.data?.detail || 'Mining failed');
    } finally {
      setMiningBlock(false);
    }
  };

  if (loading) {
    return (
      <div className="app-layout">
        <div className="app-grid-bg"></div>
        <nav className="app-nav"><a href="/dashboard" className="nav-brand">Fort<span>Knox</span></a></nav>
        <main className="app-content">
          <p style={{ textAlign: 'center', marginTop: '80px', color: 'var(--cy-text-mute)', fontFamily: 'JetBrains Mono, monospace', fontSize: '13px' }}>Loading Admin Panel...</p>
        </main>
      </div>
    );
  }

  if (!isAdmin) {
    return (
      <div className="app-layout">
        <div className="app-grid-bg"></div>
        <nav className="app-nav"><a href="/dashboard" className="nav-brand">Fort<span>Knox</span></a></nav>
        <main className="app-content">
          <div className="error-message" style={{ margin: '80px auto', maxWidth: '400px' }}>{error || 'Access Denied'}</div>
        </main>
      </div>
    );
  }

  const pendingRequests = actionQueue.filter(q => q.status === 'pending');
  const unapprovedAdmins = users.filter(u => u.role === 'admin' && u.is_admin_approved === false);

  const tabs = ['users', 'logs', 'reports', 'blockchain', ...(isSuperAdmin ? ['requests', 'admin-approvals'] : ['my-requests'])];
  const tabLabels = {
    users: 'Users',
    logs: 'Audit Logs',
    reports: `Reports (${reports.filter(r => r.status === 'pending').length})`,
    blockchain: 'Blockchain',
    requests: `Requests (${pendingRequests.length})`,
    'admin-approvals': `Admin Approvals (${unapprovedAdmins.length})`,
    'my-requests': 'My Requests'
  };

  return (
    <div className="app-layout">
      <div className="app-grid-bg"></div>

      {/* ---- POPUP MODAL ---- */}
      {showPopup && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,19,40,0.6)', backdropFilter: 'blur(8px)', display: 'flex', alignItems: 'center',
          justifyContent: 'center', zIndex: 9999
        }}>
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            style={{
              background: 'var(--cy-glass-bg)', backdropFilter: 'blur(24px)', borderRadius: '16px', padding: '36px',
              maxWidth: '440px', width: '90%', boxShadow: 'var(--cy-shadow)',
              textAlign: 'center', border: '1px solid rgba(255,255,255,0.8)', position: 'relative'
            }}
          >
            <div style={{ position: 'absolute', top: '4px', left: '4px', right: '4px', bottom: '4px', border: '1px dashed var(--cy-border)', borderRadius: '12px', pointerEvents: 'none' }}></div>
            <div style={{ width: '56px', height: '56px', borderRadius: '50%', background: 'rgba(185,28,28,0.08)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px', border: '1px dashed rgba(185,28,28,0.3)' }}>
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#dc2626" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            </div>
            <h3 style={{ margin: '0 0 8px', color: 'var(--cy-text-main)', fontFamily: 'Space Grotesk, sans-serif' }}>Superadmin Approval Required</h3>
            <p style={{ color: 'var(--cy-text-mute)', margin: '0 0 24px', lineHeight: '1.6', fontSize: '14px' }}>
              The action <strong style={{ color: '#dc2626' }}>{pendingAction?.action_type}</strong> on 
              user <strong>{pendingAction?.target_email}</strong> requires 
              Superadmin authorization.
            </p>
            <p style={{ color: 'var(--cy-text-mute)', marginBottom: '12px', fontSize: '13px' }}>
              Would you like to send a notification to the Superadmin for approval?
            </p>
            <textarea 
              placeholder="Reason for this action (optional)"
              value={actionReason}
              onChange={(e) => setActionReason(e.target.value)}
              style={{
                width: '100%', padding: '12px', borderRadius: '8px', border: '1px dashed var(--cy-border)',
                background: 'rgba(255,255,255,0.05)', color: 'var(--cy-text-main)', fontSize: '13px',
                fontFamily: 'JetBrains Mono, monospace', marginBottom: '20px', minHeight: '80px',
                outline: 'none', resize: 'vertical'
              }}
            />
            <div style={{ display: 'flex', gap: '12px', justifyContent: 'center' }}>
              <button 
                onClick={sendToSuperAdmin} 
                disabled={popupSending}
                className="btn-upload"
              >
                {popupSending ? 'Sending...' : 'Yes, Notify Superadmin'}
              </button>
              <button 
                onClick={() => { setShowPopup(false); setPendingAction(null); }}
                className="btn-logout"
              >
                Cancel
              </button>
            </div>
          </motion.div>
        </div>
      )}

      {/* ---- NAVBAR ---- */}
      <nav className="app-nav">
        <a href="/dashboard" className="nav-brand">Fort<span>Knox</span></a>
        <div className="nav-center">
          <a href="/dashboard">Dashboard</a>
          <a href="/admin">Admin Panel</a>
        </div>
        <div className="nav-actions">
          {currentUser && (
            <div style={{ display: 'flex', alignItems: 'center', marginRight: '16px' }}>
              <span style={{ color: 'var(--cy-text-mute)', fontSize: '10px', marginRight: '8px', fontFamily: 'JetBrains Mono, monospace', textTransform: 'uppercase', letterSpacing: '1px' }}>
                Welcome Back, {currentUser.full_name}
              </span>
              <div 
                style={{ 
                  width: '32px', height: '32px', borderRadius: '50%', background: 'var(--cy-glass-bg)', 
                  border: '1px dashed var(--cy-border)', display: 'flex', alignItems: 'center', justifyContent: 'center',
                  overflow: 'hidden', position: 'relative'
                }}
              >
                {currentUser.profile_picture ? (
                  <img src={`https://127.0.0.1:8000/uploads/${currentUser.profile_picture}`} alt="Profile" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
                ) : (
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--cy-text-mute)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                )}
              </div>
            </div>
          )}
          <span style={{ color: 'var(--cy-text-mute)', fontSize: '10px', marginRight: '12px', fontFamily: 'JetBrains Mono, monospace', textTransform: 'uppercase', letterSpacing: '1px' }}>
            {isSuperAdmin ? 'Superadmin' : 'Admin'}
          </span>
          <button className="btn-logout" onClick={handleLogout}>Sign Out</button>
        </div>
      </nav>

      <div className="page-hero">
        <div className="page-hero-inner">
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '10px', color: 'var(--cy-brand)', textTransform: 'uppercase', letterSpacing: '2px', marginBottom: '12px' }}>ADMIN_CONTROL</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
            <div 
              style={{ 
                width: '64px', height: '64px', borderRadius: '50%', background: 'var(--cy-glass-bg)', 
                border: '2px dashed var(--cy-border)', display: 'flex', alignItems: 'center', justifyContent: 'center',
                overflow: 'hidden', position: 'relative', flexShrink: 0
              }}
            >
              {currentUser?.profile_picture ? (
                <img src={`https://127.0.0.1:8000/uploads/${currentUser.profile_picture}`} alt="Profile" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
              ) : (
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--cy-text-mute)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
              )}
            </div>
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <h2 style={{ margin: 0 }}>{isSuperAdmin ? 'Superadmin Control Center' : 'Admin Control Center'}</h2>
              <p style={{ margin: 0, marginTop: '4px' }}>
                {isSuperAdmin 
                  ? 'Full platform control — approve admin requests and manage all users'
                  : 'Monitor users and logs — destructive actions require Superadmin approval'
                }
              </p>
            </div>
          </div>
        </div>
      </div>

      <main className="app-content">
        {/* STATS */}
        <motion.div className="stats-row" initial="hidden" animate="visible" variants={{ visible: { transition: { staggerChildren: 0.1 } } }}>
          <motion.div className="stat-item" variants={{ hidden: { opacity: 0, y: 20 }, visible: { opacity: 1, y: 0 } }}>
            <div className="stat-label">Total Users</div>
            <div className="stat-value">{users.length}</div>
          </motion.div>
          <motion.div className="stat-item" variants={{ hidden: { opacity: 0, y: 20 }, visible: { opacity: 1, y: 0 } }}>
            <div className="stat-label">System Logs</div>
            <div className="stat-value">{logs.length}</div>
          </motion.div>
          {isSuperAdmin && (
            <motion.div className="stat-item" variants={{ hidden: { opacity: 0, y: 20 }, visible: { opacity: 1, y: 0 } }}>
              <div className="stat-label">Pending Requests</div>
              <div className="stat-value" style={{ color: pendingRequests.length > 0 ? '#dc2626' : '#059669' }}>
                {pendingRequests.length}
              </div>
            </motion.div>
          )}
          <motion.div className="stat-item" variants={{ hidden: { opacity: 0, y: 20 }, visible: { opacity: 1, y: 0 } }}>
            <div className="stat-label">Your Role</div>
            <div className="stat-value" style={{ color: '#059669', fontSize: '16px' }}>
              {isSuperAdmin ? 'Superadmin' : 'Admin'}
            </div>
          </motion.div>
        </motion.div>

        {actionMessage && <div className="success-message">{actionMessage}</div>}
        {error && <div className="error-message">{error}</div>}

        {/* TAB NAVIGATION */}
        <div style={{ display: 'flex', gap: '0', marginBottom: '24px', borderBottom: '1px dashed var(--cy-border)' }}>
          {tabs.map(tab => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              style={{
                padding: '14px 24px', border: 'none', cursor: 'pointer',
                background: 'transparent',
                borderBottom: activeTab === tab ? '2px solid var(--cy-brand)' : '2px solid transparent',
                color: activeTab === tab ? 'var(--cy-brand)' : 'var(--cy-text-mute)',
                fontWeight: activeTab === tab ? '700' : '500',
                fontSize: '12px', transition: 'all 0.3s',
                fontFamily: 'Space Grotesk, sans-serif',
                textTransform: 'uppercase',
                letterSpacing: '0.5px'
              }}>
              {tabLabels[tab]}
            </button>
          ))}
        </div>

        {/* ---- TAB: USER MANAGEMENT ---- */}
        {activeTab === 'users' && (
          <motion.div className="card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
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
          </motion.div>
        )}

        {/* ---- TAB: AUDIT LOGS ---- */}
        {activeTab === 'logs' && (
          <motion.div className="card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
            <div className="card-header">
              <h3>Secure Audit Trail (HMAC Hash-Chained)</h3>
              <span className="card-badge" style={{ background: 'rgba(5,150,105,0.08)', color: '#065f46', border: '1px dashed rgba(5,150,105,0.3)' }}>Integrity Verified</span>
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
                    <tr><td colSpan="5" style={{ textAlign: 'center', padding: '20px', fontFamily: 'JetBrains Mono, monospace', fontSize: '12px', color: 'var(--cy-text-mute)' }}>No logs recorded yet.</td></tr>
                  ) : (
                    [...logs].sort((a,b) => b.id - a.id)
                      .slice((logsPage - 1) * logsPerPage, logsPage * logsPerPage)
                      .map((log) => (
                      <tr key={log.id}>
                        <td><strong>{log.action}</strong></td>
                        <td>{log.performed_by}</td>
                        <td>{log.target_user || '-'}</td>
                        <td style={{ fontSize: '12px', fontFamily: 'JetBrains Mono, monospace' }}>{new Date(log.timestamp).toLocaleString('en-GB')}</td>
                        <td style={{ fontSize: '10px', fontFamily: 'JetBrains Mono, monospace', color: 'var(--cy-text-mute)' }}>
                          {log.log_hash.substring(0, 24)}...
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls for Logs */}
            {logs.length > logsPerPage && (
              <div style={{ display: 'flex', justifyContent: 'center', gap: '8px', padding: '16px', borderTop: '1px dashed var(--cy-border)' }}>
                <button 
                  className="download-btn" 
                  disabled={logsPage === 1}
                  onClick={() => setLogsPage(p => Math.max(1, p - 1))}
                  style={{ opacity: logsPage === 1 ? 0.5 : 1 }}
                >
                  Previous
                </button>
                <span style={{ color: 'var(--cy-text-mute)', fontSize: '12px', display: 'flex', alignItems: 'center', fontFamily: 'JetBrains Mono, monospace' }}>
                  Page {logsPage} of {Math.ceil(logs.length / logsPerPage)}
                </span>
                <button 
                  className="download-btn" 
                  disabled={logsPage >= Math.ceil(logs.length / logsPerPage)}
                  onClick={() => setLogsPage(p => p + 1)}
                  style={{ opacity: logsPage >= Math.ceil(logs.length / logsPerPage) ? 0.5 : 1 }}
                >
                  Next
                </button>
              </div>
            )}
          </motion.div>
        )}

        {/* ---- TAB: REPORTS ---- */}
        {activeTab === 'reports' && (
          <motion.div className="card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
            <div className="card-header">
              <h3>Content Reports</h3>
              {reports.filter(r => r.status === 'pending').length > 0 && (
                <span className="card-badge" style={{ background: 'rgba(185,28,28,0.08)', color: '#dc2626', border: '1px dashed rgba(185,28,28,0.3)' }}>
                  {reports.filter(r => r.status === 'pending').length} Pending
                </span>
              )}
            </div>
            <div className="admin-table-wrapper">
              <table className="admin-table">
                <thead>
                  <tr>
                    <th>Reporter</th>
                    <th>Type</th>
                    <th>Target ID</th>
                    <th>Reason</th>
                    <th>Status</th>
                    <th>Date</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {reports.length === 0 ? (
                    <tr><td colSpan="7" style={{ textAlign: 'center', padding: '20px', fontFamily: 'JetBrains Mono, monospace', fontSize: '12px', color: 'var(--cy-text-mute)' }}>No reports yet.</td></tr>
                  ) : (
                    reports.map((r) => (
                      <tr key={r.id}>
                        <td>User #{r.reporter_id}</td>
                        <td><strong>{r.target_type}</strong></td>
                        <td>#{r.target_id}</td>
                        <td>{r.reason}</td>
                        <td>
                          <span className="card-badge" style={{
                            background: r.status === 'pending' ? 'rgba(245,158,11,0.1)' : r.status === 'resolved' ? 'rgba(5,150,105,0.1)' : 'var(--cy-bg-off)',
                            color: r.status === 'pending' ? '#92400e' : r.status === 'resolved' ? '#166534' : 'var(--cy-text-mute)',
                            border: `1px dashed ${r.status === 'pending' ? 'rgba(245,158,11,0.3)' : r.status === 'resolved' ? 'rgba(5,150,105,0.3)' : 'var(--cy-border)'}`
                          }}>
                            {r.status}
                          </span>
                        </td>
                        <td style={{ fontSize: '12px', fontFamily: 'JetBrains Mono, monospace' }}>{new Date(r.created_at).toLocaleString('en-GB')}</td>
                        <td>
                          {r.status === 'pending' ? (
                            <div style={{ display: 'flex', gap: '6px' }}>
                              <button className="btn-activate" onClick={async () => { try { await adminAPI.reviewReport(r.id, 'resolved'); setActionMessage('Report resolved.'); await fetchData(currentUser.role); } catch { setError('Failed to resolve report'); } }}>Resolve</button>
                              <button className="btn-suspend" onClick={async () => { try { await adminAPI.reviewReport(r.id, 'dismissed'); setActionMessage('Report dismissed.'); await fetchData(currentUser.role); } catch { setError('Failed to dismiss report'); } }}>Dismiss</button>
                            </div>
                          ) : (
                            <span style={{ color: 'var(--cy-text-mute)', fontSize: '11px', fontFamily: 'JetBrains Mono, monospace' }}>{r.reviewed_by || '-'}</span>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </motion.div>
        )}

        {/* ---- TAB: SUPERADMIN REQUESTS ---- */}
        {activeTab === 'requests' && isSuperAdmin && (
          <motion.div className="card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
            <div className="card-header">
              <h3>Admin Action Requests</h3>
              {pendingRequests.length > 0 && (
                <span className="card-badge" style={{ background: 'rgba(185,28,28,0.08)', color: '#dc2626', border: '1px dashed rgba(185,28,28,0.3)' }}>
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
                    <tr><td colSpan="6" style={{ textAlign: 'center', padding: '20px', fontFamily: 'JetBrains Mono, monospace', fontSize: '12px', color: 'var(--cy-text-mute)' }}>No requests yet.</td></tr>
                  ) : (
                    actionQueue.map((item) => (
                      <tr key={item.id}>
                        <td>{item.requested_by}</td>
                        <td>
                          <span className={`action-badge ${item.action_type}`}>
                            {item.action_type === 'suspend' ? 'Suspending user account' : 
                             item.action_type === 'delete' ? 'Deleting user account' : 
                             item.action_type === 'activate' ? 'Activating user account' : 
                             item.action_type.toUpperCase()}
                          </span>
                        </td>
                        <td>{item.target_user_email || `User #${item.target_user_id}`}</td>
                        <td>
                          <span className="card-badge" style={{
                            background: item.status === 'pending' ? 'rgba(245,158,11,0.1)' : item.status === 'approved' ? 'rgba(5,150,105,0.1)' : 'rgba(185,28,28,0.1)',
                            color: item.status === 'pending' ? '#92400e' : item.status === 'approved' ? '#166534' : '#991b1b',
                            border: `1px dashed ${item.status === 'pending' ? 'rgba(245,158,11,0.3)' : item.status === 'approved' ? 'rgba(5,150,105,0.3)' : 'rgba(185,28,28,0.3)'}`
                          }}>
                            {item.status}
                          </span>
                        </td>
                        <td style={{ fontSize: '12px', fontFamily: 'JetBrains Mono, monospace' }}>{new Date(item.created_at).toLocaleString('en-GB')}</td>
                        <td>
                          {item.status === 'pending' ? (
                            <div style={{ display: 'flex', gap: '8px' }}>
                              <button className="btn-activate" onClick={() => reviewQueueItem(item.id, 'approve')}>Approve</button>
                              <button className="btn-delete" onClick={() => reviewQueueItem(item.id, 'reject')}>Reject</button>
                            </div>
                          ) : (
                            <span style={{ color: 'var(--cy-text-mute)', fontSize: '11px', fontFamily: 'JetBrains Mono, monospace' }}>
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
          </motion.div>
        )}

        {/* ---- TAB: ADMIN APPROVALS ---- */}
        {activeTab === 'admin-approvals' && isSuperAdmin && (
          <motion.div className="card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
            <div className="card-header"><h3>Admin Account Approvals</h3></div>
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
                    <tr><td colSpan="4" style={{ textAlign: 'center', padding: '20px', fontFamily: 'JetBrains Mono, monospace', fontSize: '12px', color: 'var(--cy-text-mute)' }}>No pending admin approvals.</td></tr>
                  ) : (
                    unapprovedAdmins.map((admin) => (
                      <tr key={admin.id}>
                        <td>{admin.email}</td>
                        <td>{admin.full_name || '-'}</td>
                        <td>
                          <span className="card-badge" style={{ background: 'rgba(245,158,11,0.1)', color: '#92400e', border: '1px dashed rgba(245,158,11,0.3)' }}>
                            Pending Approval
                          </span>
                        </td>
                        <td>
                          <button className="btn-upload" style={{ padding: '6px 16px', fontSize: '11px' }} onClick={() => approveAdminAccount(admin.id, admin.email)}>
                            Approve Admin
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </motion.div>
        )}

        {/* ---- TAB: MY REQUESTS ---- */}
        {activeTab === 'my-requests' && !isSuperAdmin && (
          <motion.div className="card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
            <div className="card-header"><h3>My Submitted Requests</h3></div>
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
                    <tr><td colSpan="5" style={{ textAlign: 'center', padding: '20px', fontFamily: 'JetBrains Mono, monospace', fontSize: '12px', color: 'var(--cy-text-mute)' }}>You haven't submitted any requests yet.</td></tr>
                  ) : (
                    actionQueue.map((item) => (
                      <tr key={item.id}>
                        <td>
                          <span className={`action-badge ${item.action_type}`}>
                            {item.action_type === 'suspend' ? 'Suspending user account' : 
                             item.action_type === 'delete' ? 'Deleting user account' : 
                             item.action_type === 'activate' ? 'Activating user account' : 
                             item.action_type.toUpperCase()}
                          </span>
                        </td>
                        <td>{item.target_user_email || `User #${item.target_user_id}`}</td>
                        <td>
                          <span className="card-badge" style={{
                            background: item.status === 'pending' ? 'rgba(245,158,11,0.1)' : item.status === 'approved' ? 'rgba(5,150,105,0.1)' : 'rgba(185,28,28,0.1)',
                            color: item.status === 'pending' ? '#92400e' : item.status === 'approved' ? '#166534' : '#991b1b',
                            border: `1px dashed ${item.status === 'pending' ? 'rgba(245,158,11,0.3)' : item.status === 'approved' ? 'rgba(5,150,105,0.3)' : 'rgba(185,28,28,0.3)'}`
                          }}>
                            {item.status === 'pending' ? 'Waiting for Superadmin' : 
                             item.status === 'approved' ? 'Approved & Executed' : 'Rejected'}
                          </span>
                        </td>
                        <td style={{ fontSize: '12px', fontFamily: 'JetBrains Mono, monospace' }}>{new Date(item.created_at).toLocaleString('en-GB')}</td>
                        <td>{item.reviewed_by || '—'}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </motion.div>
        )}

        {/* ======= BLOCKCHAIN TAB ======= */}
        {activeTab === 'blockchain' && (
          <motion.div className="card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
            <div className="card-header">
              <h3>Blockchain Audit Explorer</h3>
              <div style={{ display: 'flex', gap: '10px' }}>
                <button className="download-btn" onClick={fetchBlockchain}>Refresh</button>
                <button className="btn-upload" style={{ padding: '6px 16px', fontSize: '11px' }} onClick={handleMineBlock} disabled={miningBlock}>
                  {miningBlock ? 'Mining...' : '⛏ Mine Block'}
                </button>
              </div>
            </div>

            {/* Chain Status Banner */}
            {chainStatus && (
              <div style={{
                padding: '16px 20px', borderRadius: '8px', marginBottom: '20px',
                border: `1px dashed ${chainStatus.is_valid ? 'rgba(5,150,105,0.3)' : 'rgba(185,28,28,0.3)'}`,
                background: chainStatus.is_valid ? 'rgba(5,150,105,0.06)' : 'rgba(185,28,28,0.06)',
                display: 'flex', justifyContent: 'space-between', alignItems: 'center'
              }}>
                <div>
                  <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '10px', textTransform: 'uppercase', letterSpacing: '1.5px', color: chainStatus.is_valid ? '#059669' : '#dc2626', fontWeight: '700' }}>
                    {chainStatus.is_valid ? '✓ CHAIN VERIFIED' : '✗ CHAIN COMPROMISED'}
                  </span>
                  <p style={{ fontSize: '12px', color: 'var(--cy-text-mute)', margin: '4px 0 0', fontFamily: 'JetBrains Mono, monospace' }}>{chainStatus.message}</p>
                </div>
                <span className="card-badge" style={{ background: 'rgba(10,102,194,0.08)', color: 'var(--cy-brand)' }}>
                  {chainStatus.total_blocks} Blocks
                </span>
              </div>
            )}

            {/* Blocks List */}
            {blocks.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '40px', color: 'var(--cy-text-mute)', fontFamily: 'JetBrains Mono, monospace', fontSize: '12px' }}>
                No blocks mined yet. Click "Mine Block" to create blocks from pending audit logs.
              </div>
            ) : (
              <>
                <div style={{ display: 'grid', gap: '12px' }}>
                  {[...blocks].sort((a,b) => b.block_index - a.block_index)
                    .slice((blocksPage - 1) * blocksPerPage, blocksPage * blocksPerPage)
                    .map((block) => (
                    <div key={block.id} style={{
                      border: '1px dashed var(--cy-border)', borderRadius: '12px', padding: '18px 20px',
                      background: 'rgba(255,255,255,0.4)', transition: 'all 0.3s'
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                        <span style={{ fontFamily: 'Space Grotesk, sans-serif', fontWeight: '700', fontSize: '16px', color: 'var(--cy-brand)' }}>
                          Block #{block.block_index}
                        </span>
                        <span className="card-badge" style={{ background: 'rgba(10,102,194,0.08)', color: 'var(--cy-brand)' }}>
                          {block.log_count} logs
                        </span>
                      </div>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                        <div>
                          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '9px', color: 'var(--cy-text-mute)', textTransform: 'uppercase', letterSpacing: '1px' }}>Block Hash</span>
                          <p style={{ fontSize: '11px', fontFamily: 'JetBrains Mono, monospace', color: 'var(--cy-text-main)', wordBreak: 'break-all', margin: '2px 0 0' }}>{block.block_hash}</p>
                        </div>
                        <div>
                          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '9px', color: 'var(--cy-text-mute)', textTransform: 'uppercase', letterSpacing: '1px' }}>Previous Hash</span>
                          <p style={{ fontSize: '11px', fontFamily: 'JetBrains Mono, monospace', color: 'var(--cy-text-main)', wordBreak: 'break-all', margin: '2px 0 0' }}>{block.previous_block_hash}</p>
                        </div>
                      </div>
                      <div style={{ marginTop: '10px', fontSize: '11px', fontFamily: 'JetBrains Mono, monospace', color: 'var(--cy-text-mute)' }}>
                        Mined: {new Date(block.timestamp).toLocaleString('en-GB')}
                      </div>
                    </div>
                  ))}
                </div>

                {/* Pagination Controls for Blockchain */}
                {blocks.length > blocksPerPage && (
                  <div style={{ display: 'flex', justifyContent: 'center', gap: '8px', padding: '24px 16px 8px' }}>
                    <button 
                      className="download-btn" 
                      disabled={blocksPage === 1}
                      onClick={() => setBlocksPage(p => Math.max(1, p - 1))}
                      style={{ opacity: blocksPage === 1 ? 0.5 : 1 }}
                    >
                      Previous
                    </button>
                    <span style={{ color: 'var(--cy-text-mute)', fontSize: '12px', display: 'flex', alignItems: 'center', fontFamily: 'JetBrains Mono, monospace' }}>
                      Page {blocksPage} of {Math.ceil(blocks.length / blocksPerPage)}
                    </span>
                    <button 
                      className="download-btn" 
                      disabled={blocksPage >= Math.ceil(blocks.length / blocksPerPage)}
                      onClick={() => setBlocksPage(p => p + 1)}
                      style={{ opacity: blocksPage >= Math.ceil(blocks.length / blocksPerPage) ? 0.5 : 1 }}
                    >
                      Next
                    </button>
                  </div>
                )}
              </>
            )}
          </motion.div>
        )}
      </main>
    </div>
  );
}

export default Admin;
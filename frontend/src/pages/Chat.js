import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { messageAPI, authAPI, profileAPI, groupAPI, connectionAPI } from '../services/api';
import cryptoService from '../services/cryptoService';
import { motion, AnimatePresence } from 'framer-motion';
import './Dashboard.css';

function Chat() {
  const { receiverId } = useParams();
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [receiverKey, setReceiverKey] = useState(null);
  const [myPrivateKey, setMyPrivateKey] = useState(null);
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isSending, setIsSending] = useState(false);
  const navigate = useNavigate();
  const messagesEndRef = useRef(null);

  // Group messaging state
  const [chatMode, setChatMode] = useState('dm'); // 'dm' | 'groups'
  const [groups, setGroups] = useState([]);
  const [selectedGroup, setSelectedGroup] = useState(null);
  const [groupMessages, setGroupMessages] = useState([]);
  const [groupMembers, setGroupMembers] = useState([]);
  const [showCreateGroup, setShowCreateGroup] = useState(false);
  const [connections, setConnections] = useState([]);
  const [newGroupName, setNewGroupName] = useState('');
  const [selectedMembers, setSelectedMembers] = useState([]);

  useEffect(() => {
    initializeChat();
    const interval = setInterval(() => {
      if (chatMode === 'dm') fetchMessages();
      if (chatMode === 'groups' && selectedGroup) fetchGroupMessages(selectedGroup.id);
    }, 4000);
    return () => clearInterval(interval);
  }, [receiverId, chatMode, selectedGroup]);

  const initializeChat = async () => {
    try {
      let profRes = await profileAPI.getProfile();
      if (!profRes.data.public_key && localStorage.getItem('encrypted_private_key')) {
          await new Promise(r => setTimeout(r, 1000)); 
          profRes = await profileAPI.getProfile();
      }
      setProfile(profRes.data);
      const encryptedKeyJson = localStorage.getItem('encrypted_private_key');
      const derivedKeyB64 = sessionStorage.getItem('derived_key');
      if (encryptedKeyJson && derivedKeyB64) {
        const decryptedKey = cryptoService.decryptPrivateKey(encryptedKeyJson, derivedKeyB64);
        setMyPrivateKey(decryptedKey);
      }

      // DM init
      if (receiverId) {
        try {
          const keyRes = await authAPI.getUserPublicKey(receiverId);
          setReceiverKey(keyRes.data.public_key);
        } catch (e) {
          console.error("Error fetching receiver key:", e);
        }
        await fetchMessages();
      }

      // KEY SYNC: Ensure current user's public key is in the backend if we have it locally
      if (profRes.data && !profRes.data.public_key && derivedKeyB64 && encryptedKeyJson) {
        const decryptedKey = cryptoService.decryptPrivateKey(encryptedKeyJson, derivedKeyB64);
        if (decryptedKey) {
          const pubKey = cryptoService.getPublicKeyFromPrivate(decryptedKey);
          await authAPI.updatePublicKey({ public_key: pubKey });
          setProfile(prev => ({ ...prev, public_key: pubKey }));
        }
      }

      // Groups init
      try {
        const groupsRes = await groupAPI.myGroups();
        setGroups(groupsRes.data || []);
      } catch { setGroups([]); }

    } catch (err) {
      console.error("Chat initialization error:", err);
    } finally {
      setLoading(false);
    }
  };

  const fetchMessages = async () => {
    if (!receiverId) return;
    try {
      const res = await messageAPI.getMessages(receiverId);
      setMessages(res.data);
      scrollToBottom();
    } catch (err) { console.error(err); }
  };

  const fetchGroupMessages = async (groupId) => {
    try {
      const [msgRes, memRes] = await Promise.all([
        groupAPI.getMessages(groupId),
        groupAPI.getMembers(groupId)
      ]);
      setGroupMessages(msgRes.data || []);
      setGroupMembers(memRes.data || []);
      scrollToBottom();
    } catch (err) { console.error(err); }
  };

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  const handleSendMessage = async (e) => {
    e.preventDefault();
    if (!newMessage.trim() || isSending) return;
    if (!receiverKey) { 
      // Try refetching key once more
      try {
        const keyRes = await authAPI.getUserPublicKey(receiverId);
        if (keyRes.data.public_key) {
          setReceiverKey(keyRes.data.public_key);
          // Continue with sending below if key is found
        } else {
          alert("Encryption blocked: The recipient has not yet initialized their secure identity (PGP keys). They must log in to generate their keys."); 
          return;
        }
      } catch {
        alert("Encryption blocked: Recipient's secure identity could not be retrieved.");
        return;
      }
    }
    setIsSending(true);
    try {
      let myPublicKey = profile?.public_key;
      if (!myPublicKey && myPrivateKey) { myPublicKey = cryptoService.getPublicKeyFromPrivate(myPrivateKey); }
      const doubleCiphertext = cryptoService.encryptDouble(newMessage, receiverKey, myPublicKey);
      if (!doubleCiphertext) throw new Error("Encryption failed");
      let digitalSignature = null;
      if (myPrivateKey) { digitalSignature = cryptoService.signMessage(newMessage, myPrivateKey); }
      await messageAPI.sendMessage({
        receiver_id: parseInt(receiverId),
        encrypted_content: doubleCiphertext,
        signature: digitalSignature
      });
      setNewMessage('');
      fetchMessages();
    } catch (err) {
      console.error(err);
      alert("Failed to send secure message.");
    } finally {
      setIsSending(false);
    }
  };

  const handleSendGroupMessage = async (e) => {
    e.preventDefault();
    if (!newMessage.trim() || isSending || !selectedGroup) return;
    setIsSending(true);
    try {
      let sig = null;
      if (myPrivateKey) { sig = cryptoService.signMessage(newMessage, myPrivateKey); }

      await groupAPI.sendMessage(selectedGroup.id, {
        encrypted_content: newMessage, // In production, use group-specific key exchange
        signature: sig
      });
      setNewMessage('');
      fetchGroupMessages(selectedGroup.id);
    } catch (err) {
      console.error(err);
      alert("Failed to send group message.");
    } finally {
      setIsSending(false);
    }
  };

  const handleCreateGroup = async () => {
    if (!newGroupName.trim() || selectedMembers.length === 0) return;
    try {
      await groupAPI.create({
        name: newGroupName,
        member_ids: selectedMembers
      });
      setShowCreateGroup(false);
      setNewGroupName('');
      setSelectedMembers([]);
      const groupsRes = await groupAPI.myGroups();
      setGroups(groupsRes.data || []);
    } catch (err) {
      alert("Failed to create group.");
    }
  };

  const handleDeleteGroup = async (groupId) => {
    if (!window.confirm("Are you sure you want to PERMANENTLY delete this group channel and all its history?")) return;
    try {
      await groupAPI.deleteGroup(groupId);
      const groupsRes = await groupAPI.myGroups();
      setGroups(groupsRes.data || []);
      if (selectedGroup?.id === groupId) {
        setSelectedGroup(null);
        setGroupMessages([]);
      }
    } catch (err) {
      alert("Failed to delete group.");
    }
  };

  const openGroupCreation = async () => {
    try {
      const connRes = await connectionAPI.getMyConnections();
      setConnections(connRes.data || []);
    } catch { setConnections([]); }
    setShowCreateGroup(true);
  };

  const renderMessage = (msg) => {
    const isMe = msg.sender_id === profile?.id;
    let content = "[Encrypted Content]";
    let isVerified = false;
    if (myPrivateKey) {
      content = cryptoService.decryptMessage(msg.encrypted_content, myPrivateKey);
      if (content !== "[Unable to decrypt: Key mismatch]" && msg.signature) {
          const keyToVerifyWith = isMe ? profile?.public_key : receiverKey;
          if (keyToVerifyWith) { isVerified = cryptoService.verifySignature(content, msg.signature, keyToVerifyWith); }
      }
    } else {
      content = "[Decryption Error: Private Key Locked]";
    }

    return (
      <motion.div key={msg.id}
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        style={{
          alignSelf: isMe ? 'flex-end' : 'flex-start',
          background: isMe ? 'var(--cy-brand)' : 'var(--cy-glass-bg)',
          backdropFilter: isMe ? 'none' : 'blur(24px)',
          color: isMe ? 'white' : 'var(--cy-text-main)',
          padding: '14px 20px',
          borderRadius: '16px',
          borderBottomRightRadius: isMe ? '4px' : '16px',
          borderBottomLeftRadius: isMe ? '16px' : '4px',
          maxWidth: '80%',
          marginBottom: '12px',
          boxShadow: isMe ? '0 8px 24px rgba(10,102,194,0.2)' : '0 4px 12px rgba(0,0,0,0.04)',
          border: isMe ? 'none' : '1px solid rgba(255,255,255,0.8)',
          position: 'relative'
        }}>
        <div style={{ fontSize: '14px', lineHeight: '1.5' }}>{content}</div>
        <div style={{ fontSize: '10px', opacity: 0.7, marginTop: '6px', display: 'flex', justifyContent: 'flex-end', gap: '6px', alignItems: 'center', fontFamily: 'JetBrains Mono, monospace' }}>
          {isVerified && <span title="Digital Signature Verified" style={{ color: isMe ? '#a5d8ff' : '#059669', fontWeight: '700' }}>✓ VERIFIED</span>}
          <span>{new Date(msg.timestamp).toLocaleString('en-GB', { hour: '2-digit', minute: '2-digit' })}</span>
        </div>
      </motion.div>
    );
  };

  const renderGroupMessage = (msg) => {
    const isMe = msg.sender_id === profile?.id;
    const sender = groupMembers.find(m => m.user_id === msg.sender_id);
    
    return (
      <motion.div key={msg.id}
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        style={{
          alignSelf: isMe ? 'flex-end' : 'flex-start',
          background: isMe ? 'var(--cy-brand)' : 'var(--cy-glass-bg)',
          backdropFilter: isMe ? 'none' : 'blur(24px)',
          color: isMe ? 'white' : 'var(--cy-text-main)',
          padding: '14px 20px',
          borderRadius: '16px',
          borderBottomRightRadius: isMe ? '4px' : '16px',
          borderBottomLeftRadius: isMe ? '16px' : '4px',
          maxWidth: '80%',
          marginBottom: '12px',
          boxShadow: isMe ? '0 8px 24px rgba(10,102,194,0.2)' : '0 4px 12px rgba(0,0,0,0.04)',
          border: isMe ? 'none' : '1px solid rgba(255,255,255,0.8)',
        }}>
        {!isMe && (
          <div style={{ fontSize: '10px', fontFamily: 'JetBrains Mono, monospace', fontWeight: '700', marginBottom: '6px', color: isMe ? '#a5d8ff' : 'var(--cy-brand)' }}>
            {sender?.full_name || 'Unknown'}
          </div>
        )}
        <div style={{ fontSize: '14px', lineHeight: '1.5' }}>{msg.encrypted_content}</div>
        <div style={{ fontSize: '10px', opacity: 0.7, marginTop: '6px', display: 'flex', justifyContent: 'flex-end', gap: '6px', fontFamily: 'JetBrains Mono, monospace' }}>
          <span>{new Date(msg.timestamp).toLocaleString('en-GB', { hour: '2-digit', minute: '2-digit' })}</span>
        </div>
      </motion.div>
    );
  };

  if (loading) return <div className="app-layout"><div className="app-grid-bg"></div><main className="app-content"><p style={{textAlign:'center', marginTop:'50px', color: 'var(--cy-text-mute)', fontFamily: 'JetBrains Mono, monospace', fontSize: '13px'}}>Establishing secure channel...</p></main></div>;

  return (
    <div className="app-layout">
      <div className="app-grid-bg"></div>

      <nav className="app-nav">
        <a href="/dashboard" className="nav-brand">Fort<span>Knox</span></a>
        <div className="nav-center">
          <button 
            className={`cy-tab-btn ${chatMode === 'dm' ? 'active' : ''}`}
            onClick={() => setChatMode('dm')}
          >Direct Messages</button>
          <button 
            className={`cy-tab-btn ${chatMode === 'groups' ? 'active' : ''}`}
            onClick={() => setChatMode('groups')}
          >Group Channels</button>
        </div>
        <div className="nav-actions">
          {profile && (
            <div style={{ display: 'flex', alignItems: 'center', marginRight: '16px' }}>
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
          <button className="btn-logout" onClick={() => navigate('/dashboard')}>Exit Chat</button>
        </div>
      </nav>
      
      <div className="page-hero">
        <div className="page-hero-inner">
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '10px', color: 'var(--cy-brand)', textTransform: 'uppercase', letterSpacing: '2px', marginBottom: '12px' }}>SECURE_MESSAGING</div>
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
              <h2 style={{ margin: 0 }}>Secure Communication</h2>
              <p style={{ margin: 0, marginTop: '4px' }}>End-to-end encrypted messaging for secure networking</p>
            </div>
          </div>
        </div>
      </div>

      <main className="app-content" style={{ maxWidth: '800px' }}>

        {/* ========= DM MODE ========= */}
        {chatMode === 'dm' && (
          <motion.div className="card" style={{ height: '75vh', display: 'flex', flexDirection: 'column', padding: '0' }}
            initial={{ opacity: 0, scale: 0.98 }} animate={{ opacity: 1, scale: 1 }} transition={{ duration: 0.4 }}
          >
            <div className="card-header" style={{ padding: '20px 28px', borderBottom: '1px dashed var(--cy-border)', margin: 0 }}>
              <h3 style={{ margin: 0 }}>Secure Chat</h3>
              <span className="card-badge" style={{ background: 'rgba(5,150,105,0.08)', color: '#065f46', border: '1px dashed rgba(5,150,105,0.3)' }}>E2EE Active</span>
            </div>
            <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', padding: '28px' }}>
              {messages.length === 0 ? <p style={{ textAlign: 'center', color: 'var(--cy-text-mute)', marginTop: '20%', fontFamily: 'JetBrains Mono, monospace', fontSize: '12px' }}>No messages recorded.</p> : messages.map(renderMessage)}
              <div ref={messagesEndRef} />
            </div>
            <form onSubmit={handleSendMessage} style={{ padding: '20px 28px', borderTop: '1px dashed var(--cy-border)', display: 'flex', gap: '12px' }}>
              <input 
                type="text" placeholder="Write a secure message..." value={newMessage}
                onChange={(e) => setNewMessage(e.target.value)} disabled={isSending}
                style={{ flex: 1, borderRadius: '8px', padding: '12px 16px', border: '1px dashed var(--cy-border)', background: 'rgba(255,255,255,0.4)', backdropFilter: 'blur(10px)', fontFamily: 'Inter, sans-serif', fontSize: '14px', color: 'var(--cy-text-main)', outline: 'none' }}
              />
              <button className="btn-upload" type="submit" disabled={isSending} style={{ width: 'auto' }}>
                {isSending ? "..." : "Send"}
              </button>
            </form>
          </motion.div>
        )}

        {/* ========= GROUP MODE ========= */}
        {chatMode === 'groups' && !selectedGroup && (
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
              <div>
                <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '10px', color: 'var(--cy-brand)', textTransform: 'uppercase', letterSpacing: '2px', marginBottom: '6px' }}>GROUP_CHANNELS</div>
                <h3 style={{ fontFamily: 'Space Grotesk, sans-serif', fontWeight: '700', fontSize: '20px', margin: 0 }}>Your Groups</h3>
              </div>
              {profile?.role === 'recruiter' && (
                <button className="btn-upload" style={{ padding: '8px 20px', fontSize: '11px' }} onClick={openGroupCreation}>
                  + New Group
                </button>
              )}
            </div>

            {groups.length === 0 ? (
              <div className="card" style={{ textAlign: 'center', padding: '60px 28px' }}>
                <p style={{ fontSize: '14px', color: 'var(--cy-text-mute)', marginBottom: '8px' }}>You haven't joined any groups yet.</p>
                <p style={{ fontSize: '12px', color: 'var(--cy-text-mute)', fontFamily: 'JetBrains Mono, monospace' }}>Create a group to start encrypted group conversations.</p>
              </div>
            ) : (
              <div style={{ display: 'grid', gap: '12px' }}>
                {groups.map(g => (
                  <motion.div 
                    key={g.id} className="card" 
                    onClick={() => { setSelectedGroup(g); fetchGroupMessages(g.id); }}
                    style={{ cursor: 'pointer', marginBottom: 0 }}
                    whileHover={{ scale: 1.01 }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div>
                        <h4 style={{ fontFamily: 'Space Grotesk, sans-serif', fontWeight: '700', fontSize: '16px', color: 'var(--cy-brand)', margin: '0 0 4px' }}>{g.name}</h4>
                        <span style={{ fontSize: '11px', fontFamily: 'JetBrains Mono, monospace', color: 'var(--cy-text-mute)' }}>
                          Created: {new Date(g.created_at).toLocaleDateString('en-GB')}
                        </span>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                        {profile?.role === 'recruiter' && (
                          <button 
                            className="btn-delete" 
                            style={{ padding: '6px 10px', fontSize: '10px', minWidth: 'auto', background: 'transparent', border: '1px solid rgba(185, 28, 28, 0.2)' }}
                            onClick={(e) => { e.stopPropagation(); handleDeleteGroup(g.id); }}
                            title="Delete Group"
                          >
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#dc2626" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>
                          </button>
                        )}
                        <span className="card-badge" style={{ background: 'rgba(10,102,194,0.08)', color: 'var(--cy-brand)' }}>
                          Enter →
                        </span>
                      </div>
                    </div>
                  </motion.div>
                ))}
              </div>
            )}
          </motion.div>
        )}

        {/* ========= GROUP CHAT VIEW ========= */}
        {chatMode === 'groups' && selectedGroup && (
          <motion.div className="card" style={{ height: '75vh', display: 'flex', flexDirection: 'column', padding: '0' }}
            initial={{ opacity: 0, scale: 0.98 }} animate={{ opacity: 1, scale: 1 }} transition={{ duration: 0.4 }}
          >
            <div className="card-header" style={{ padding: '20px 28px', borderBottom: '1px dashed var(--cy-border)', margin: 0 }}>
              <div>
                <h3 style={{ margin: 0 }}>{selectedGroup.name}</h3>
                <span style={{ fontSize: '10px', fontFamily: 'JetBrains Mono, monospace', color: 'var(--cy-text-mute)' }}>
                  {groupMembers.length} member{groupMembers.length !== 1 ? 's' : ''}
                </span>
              </div>
              <button className="download-btn" onClick={() => { setSelectedGroup(null); setGroupMessages([]); }}>← Back</button>
            </div>
            <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', padding: '28px' }}>
              {groupMessages.length === 0 ? (
                <p style={{ textAlign: 'center', color: 'var(--cy-text-mute)', marginTop: '20%', fontFamily: 'JetBrains Mono, monospace', fontSize: '12px' }}>
                  No messages in this group yet.
                </p>
              ) : groupMessages.map(renderGroupMessage)}
              <div ref={messagesEndRef} />
            </div>
            <form onSubmit={handleSendGroupMessage} style={{ padding: '20px 28px', borderTop: '1px dashed var(--cy-border)', display: 'flex', gap: '12px' }}>
              <input 
                type="text" placeholder="Write a group message..." value={newMessage}
                onChange={(e) => setNewMessage(e.target.value)} disabled={isSending}
                style={{ flex: 1, borderRadius: '8px', padding: '12px 16px', border: '1px dashed var(--cy-border)', background: 'rgba(255,255,255,0.4)', backdropFilter: 'blur(10px)', fontFamily: 'Inter, sans-serif', fontSize: '14px', color: 'var(--cy-text-main)', outline: 'none' }}
              />
              <button className="btn-upload" type="submit" disabled={isSending} style={{ width: 'auto' }}>
                {isSending ? "..." : "Send"}
              </button>
            </form>
          </motion.div>
        )}

        {/* ========= CREATE GROUP MODAL ========= */}
        <AnimatePresence>
          {showCreateGroup && (
            <motion.div
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              style={{
                position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
                background: 'rgba(0,19,40,0.6)', backdropFilter: 'blur(8px)',
                display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 9999
              }}
              onClick={() => setShowCreateGroup(false)}
            >
              <motion.div
                initial={{ scale: 0.9, y: 20 }} animate={{ scale: 1, y: 0 }} exit={{ scale: 0.9, opacity: 0 }}
                className="card" 
                style={{ width: '480px', maxHeight: '80vh', overflow: 'auto', margin: 0 }}
                onClick={e => e.stopPropagation()}
              >
                <div className="card-header">
                  <h3>Create Group</h3>
                  <button className="download-btn" onClick={() => setShowCreateGroup(false)}>Cancel</button>
                </div>
                
                <div className="form-group">
                  <label>Group Name</label>
                  <input 
                    type="text" placeholder="e.g., Security Team" 
                    value={newGroupName} onChange={e => setNewGroupName(e.target.value)} 
                  />
                </div>

                <div className="form-group" style={{ marginTop: '16px' }}>
                  <label>Add Members ({selectedMembers.length} selected)</label>
                  <div style={{ maxHeight: '200px', overflowY: 'auto', border: '1px dashed var(--cy-border)', borderRadius: '8px', padding: '8px' }}>
                    {connections.length === 0 ? (
                      <p style={{ fontSize: '12px', color: 'var(--cy-text-mute)', textAlign: 'center', padding: '16px', fontFamily: 'JetBrains Mono, monospace' }}>No connections found.</p>
                    ) : (
                      connections.map(conn => (
                        <div 
                          key={conn.user_id} 
                          onClick={() => {
                            setSelectedMembers(prev => 
                              prev.includes(conn.user_id) 
                                ? prev.filter(uid => uid !== conn.user_id) 
                                : [...prev, conn.user_id]
                            );
                          }}
                          style={{
                            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                            padding: '10px 14px', borderRadius: '6px', cursor: 'pointer',
                            background: selectedMembers.includes(conn.user_id) ? 'rgba(10,102,194,0.08)' : 'transparent',
                            border: selectedMembers.includes(conn.user_id) ? '1px solid rgba(10,102,194,0.2)' : '1px solid transparent',
                            marginBottom: '4px', transition: 'all 0.2s'
                          }}
                        >
                          <span style={{ fontSize: '14px', fontWeight: '500' }}>{conn.full_name}</span>
                          <span style={{ fontSize: '18px', color: selectedMembers.includes(conn.user_id) ? 'var(--cy-brand)' : 'var(--cy-text-mute)' }}>
                            {selectedMembers.includes(conn.user_id) ? '✓' : '○'}
                          </span>
                        </div>
                      ))
                    )}
                  </div>
                </div>

                <button 
                  type="button" 
                  className="btn-upload"
                  style={{ width: '100%', marginTop: '16px' }}
                  onClick={handleCreateGroup}
                  disabled={!newGroupName.trim() || selectedMembers.length === 0}
                >
                  Create Group ({selectedMembers.length} members)
                </button>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>
      </main>
    </div>
  );
}

export default Chat;
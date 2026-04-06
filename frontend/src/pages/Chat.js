import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { messageAPI, authAPI, profileAPI, groupAPI, connectionAPI } from '../services/api';
import cryptoService from '../services/cryptoService';
import { motion, AnimatePresence } from 'framer-motion';
import './Dashboard.css';

const MAX_MSG_LENGTH = 500;
const MAX_GROUP_NAME = 30;
const MAX_GROUP_MEMBERS = 49; // +1 creator = 50

// Role-specific context banner config
const getRoleBanner = (role, mode) => {
  if (role === 'superadmin') {
    return mode === 'dm'
      ? { label: 'DIRECT_MESSAGING', title: 'Superadmin Control', desc: 'Full platform oversight — monitor and access all secure channels' }
      : { label: 'GROUP_CHANNELS', title: 'Superadmin Control', desc: 'Full platform oversight — manage and monitor all group communications' };
  }
  if (role === 'admin') {
    return mode === 'dm'
      ? { label: 'DIRECT_MESSAGING', title: 'Admin Secure Channel', desc: 'Platform moderation — end-to-end encrypted private communications' }
      : { label: 'GROUP_CHANNELS', title: 'Admin Group Access', desc: 'Platform moderation — view and manage group communications' };
  }
  if (role === 'recruiter') {
    return mode === 'dm'
      ? { label: 'DIRECT_MESSAGING', title: 'Recruiter Private Chat', desc: 'End-to-end encrypted private channel with verified connections' }
      : { label: 'GROUP_CHANNELS', title: 'Recruiter Group Network', desc: 'Create and manage encrypted group channels for your job postings' };
  }
  return mode === 'dm'
    ? { label: 'DIRECT_MESSAGING', title: 'Secure Private Channel', desc: 'End-to-end encrypted — your messages are private and digitally signed' }
    : { label: 'GROUP_CHANNELS', title: 'Group Communications', desc: 'Server-side encrypted group chat — join channels you have been invited to' };
};

// Avatar stack for group members
const AvatarStack = ({ members, max = 4 }) => {
  const visible = members.slice(0, max);
  const overflow = members.length - max;
  const colors = ['#0a66c2', '#059669', '#d97706', '#7c3aed', '#dc2626'];
  return (
    <div style={{ display: 'flex', alignItems: 'center' }}>
      {visible.map((m, i) => (
        <div key={m.user_id || i} style={{
          width: '28px', height: '28px', borderRadius: '50%',
          background: colors[i % colors.length],
          border: '2px solid white',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: '11px', fontWeight: '700', color: 'white',
          marginLeft: i === 0 ? '0' : '-8px',
          fontFamily: 'Space Grotesk, sans-serif',
          zIndex: max - i
        }}>
          {(m.full_name || m.email || '?').charAt(0).toUpperCase()}
        </div>
      ))}
      {overflow > 0 && (
        <div style={{
          width: '28px', height: '28px', borderRadius: '50%',
          background: 'rgba(255,255,255,0.15)', border: '2px solid white',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: '10px', fontWeight: '700', color: 'var(--cy-text-mute)',
          marginLeft: '-8px', fontFamily: 'JetBrains Mono, monospace'
        }}>
          +{overflow}
        </div>
      )}
    </div>
  );
};

function Chat() {
  const { receiverId } = useParams();
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [myPrivateKey, setMyPrivateKey] = useState(null);
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isSending, setIsSending] = useState(false);
  const navigate = useNavigate();
  const messagesEndRef = useRef(null);

  // Group messaging state
  const [chatMode, setChatMode] = useState(receiverId === 'groups' ? 'groups' : 'dm');
  const [groups, setGroups] = useState([]);
  const [selectedGroup, setSelectedGroup] = useState(null);
  const [groupMessages, setGroupMessages] = useState([]);
  const [groupMembers, setGroupMembers] = useState([]);
  const [showCreateGroup, setShowCreateGroup] = useState(false);
  const [showAddMembers, setShowAddMembers] = useState(false);
  const [connections, setConnections] = useState([]);
  const [newGroupName, setNewGroupName] = useState('');
  const [selectedMembers, setSelectedMembers] = useState([]);
  const [dmSearch, setDmSearch] = useState('');
  const [groupSearch, setGroupSearch] = useState('');
  const [lastMessages, setLastMessages] = useState({});

  const activeReceiver = connections.find(c => c.id?.toString() === receiverId || c.user_id?.toString() === receiverId);
  const filteredConnections = connections.filter(c => c.full_name?.toLowerCase().includes(dmSearch.toLowerCase()));
  const filteredGroups = groups.filter(g => g.name?.toLowerCase().includes(groupSearch.toLowerCase()));

  useEffect(() => {
    initializeChat();
    const interval = setInterval(() => {
      if (chatMode === 'dm' && receiverId && !isNaN(parseInt(receiverId))) fetchMessages();
      if (chatMode === 'groups' && selectedGroup) fetchGroupMessages(selectedGroup.id);
    }, 4000);
    return () => clearInterval(interval);
  }, [receiverId, chatMode, selectedGroup]);

  const initializeChat = async () => {
    try {
      let profRes = await profileAPI.getProfile();
      setProfile(profRes.data);

      const derivedKeyB64 = sessionStorage.getItem('derived_key');
      let encryptedKeyJson = localStorage.getItem('encrypted_private_key');
      if (!encryptedKeyJson && profRes.data.encrypted_private_key) {
        encryptedKeyJson = profRes.data.encrypted_private_key;
        localStorage.setItem('encrypted_private_key', encryptedKeyJson);
      }
      if (encryptedKeyJson && derivedKeyB64) {
        const decryptedKey = cryptoService.decryptPrivateKey(encryptedKeyJson, derivedKeyB64);
        setMyPrivateKey(decryptedKey);
        if (decryptedKey) {
          const pubKey = cryptoService.getPublicKeyFromPrivate(decryptedKey);
          if (pubKey) {
            await authAPI.updatePublicKey({ public_key: pubKey, encrypted_private_key: encryptedKeyJson });
            setProfile(prev => ({ ...prev, public_key: pubKey }));
          }
        }
      } else if (derivedKeyB64 && !encryptedKeyJson) {
        const { publicKey, privateKey } = cryptoService.generateKeyPair();
        const encryptedPrivKey = cryptoService.encryptPrivateKey(privateKey, derivedKeyB64);
        localStorage.setItem('encrypted_private_key', encryptedPrivKey);
        await authAPI.updatePublicKey({ public_key: publicKey, encrypted_private_key: encryptedPrivKey });
        setMyPrivateKey(privateKey);
        setProfile(prev => ({ ...prev, public_key: publicKey }));
      }

      if (receiverId && !isNaN(parseInt(receiverId))) {
        await fetchMessages();
      }

      try {
        const groupsRes = await groupAPI.myGroups();
        setGroups(groupsRes.data || []);
      } catch { setGroups([]); }

      try {
        const connRes = await connectionAPI.getMyConnections();
        setConnections(connRes.data || []);
      } catch { setConnections([]); }

    } catch (err) {
      console.error("Chat initialization error:", err);
    } finally {
      setLoading(false);
    }
  };

  const fetchMessages = async () => {
    if (!receiverId || isNaN(parseInt(receiverId))) return;
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
    const rId = parseInt(receiverId);
    if (isNaN(rId) || !newMessage.trim() || isSending) return;
    setIsSending(true);
    try {
      const keyRes = await authAPI.getUserPublicKey(rId);
      const recipientPubKey = keyRes.data.public_key;
      if (!recipientPubKey) {
        alert("The recipient hasn't generated their encryption keys yet.");
        setIsSending(false);
        return;
      }
      const encryptedPayload = cryptoService.encryptDouble(newMessage, recipientPubKey, profile.public_key);
      if (!encryptedPayload) {
        alert("Failed to encrypt message.");
        setIsSending(false);
        return;
      }
      let sig = null;
      if (myPrivateKey) { sig = cryptoService.signMessage(newMessage, myPrivateKey); }
      await messageAPI.sendMessage({ receiver_id: rId, encrypted_content: encryptedPayload, signature: sig });
      setNewMessage('');
      fetchMessages();
    } catch (err) {
      console.error(err);
      const detail = err.response?.data?.detail;
      alert(typeof detail === 'string' ? detail : 'Failed to send message.');
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
      await groupAPI.sendMessage(selectedGroup.id, { encrypted_content: newMessage, signature: sig });
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
      await groupAPI.create({ name: newGroupName, member_ids: selectedMembers });
      setShowCreateGroup(false);
      setNewGroupName('');
      setSelectedMembers([]);
      const groupsRes = await groupAPI.myGroups();
      setGroups(groupsRes.data || []);
    } catch (err) {
      const msg = err.response?.data?.detail;
      alert(typeof msg === 'string' ? msg : "Failed to create group.");
    }
  };

  const handleDeleteGroup = async (groupId) => {
    if (!window.confirm("Permanently delete this group channel and all its history?")) return;
    try {
      await groupAPI.deleteGroup(groupId);
      const groupsRes = await groupAPI.myGroups();
      setGroups(groupsRes.data || []);
      if (selectedGroup?.id === groupId) { setSelectedGroup(null); setGroupMessages([]); }
    } catch (err) { alert("Failed to delete group."); }
  };

  const openGroupCreation = async () => {
    try { const connRes = await connectionAPI.getMyConnections(); setConnections(connRes.data || []); } catch { setConnections([]); }
    setSelectedMembers([]);
    setShowCreateGroup(true);
  };

  const openAddMembers = async () => {
    try { const connRes = await connectionAPI.getMyConnections(); setConnections(connRes.data || []); } catch { setConnections([]); }
    setSelectedMembers([]);
    setShowAddMembers(true);
  };

  const handleAddMembers = async () => {
    if (selectedMembers.length === 0 || !selectedGroup) return;
    const currentCount = groupMembers.length;
    if (currentCount + selectedMembers.length > 50) {
      alert(`Cannot add ${selectedMembers.length} member(s). Group limit is 50, currently at ${currentCount}.`);
      return;
    }
    try {
      await groupAPI.addMembers(selectedGroup.id, { member_ids: selectedMembers });
      setShowAddMembers(false);
      setSelectedMembers([]);
      fetchGroupMessages(selectedGroup.id);
    } catch (err) { alert("Failed to add members."); }
  };

  const renderMessage = (msg) => {
    const isMe = msg.sender_id === profile?.id;
    let content = msg.encrypted_content;
    if (content && content.startsWith('{') && myPrivateKey) {
      try {
        const decrypted = cryptoService.decryptMessage(content, myPrivateKey);
        if (decrypted && !decrypted.includes("[Unable to decrypt")) content = decrypted;
      } catch (e) { }
    }
    return (
      <motion.div key={msg.id} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
        style={{
          alignSelf: isMe ? 'flex-end' : 'flex-start',
          background: isMe ? 'var(--cy-brand)' : 'var(--cy-glass-bg)',
          backdropFilter: isMe ? 'none' : 'blur(24px)',
          color: isMe ? 'white' : 'var(--cy-text-main)',
          padding: '10px 14px', borderRadius: '14px',
          borderBottomRightRadius: isMe ? '4px' : '14px',
          borderBottomLeftRadius: isMe ? '14px' : '4px',
          maxWidth: '70%', marginBottom: '6px',
          boxShadow: isMe ? '0 4px 16px rgba(10,102,194,0.2)' : '0 2px 8px rgba(0,0,0,0.04)',
          border: isMe ? 'none' : '1px solid rgba(255,255,255,0.8)',
        }}>
        <div style={{ fontSize: '14px', lineHeight: '1.5', wordBreak: 'break-word' }}>{content}</div>
        <div style={{ fontSize: '10px', opacity: 0.65, marginTop: '4px', display: 'flex', justifyContent: 'flex-end', gap: '6px', fontFamily: 'JetBrains Mono, monospace' }}>
          {msg.signature && <span style={{ color: isMe ? '#a5d8ff' : '#059669', fontWeight: '700' }}>✓ SIGNED</span>}
          <span>{new Date(msg.timestamp).toLocaleString('en-GB', { hour: '2-digit', minute: '2-digit' })}</span>
        </div>
      </motion.div>
    );
  };

  const renderGroupMessage = (msg) => {
    const isMe = msg.sender_id === profile?.id;
    const sender = groupMembers.find(m => m.user_id === msg.sender_id);
    return (
      <motion.div key={msg.id} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
        style={{
          alignSelf: isMe ? 'flex-end' : 'flex-start',
          background: isMe ? 'var(--cy-brand)' : 'var(--cy-glass-bg)',
          backdropFilter: isMe ? 'none' : 'blur(24px)',
          color: isMe ? 'white' : 'var(--cy-text-main)',
          padding: '10px 14px', borderRadius: '14px',
          borderBottomRightRadius: isMe ? '4px' : '14px',
          borderBottomLeftRadius: isMe ? '14px' : '4px',
          maxWidth: '70%', marginBottom: '6px',
          boxShadow: isMe ? '0 4px 16px rgba(10,102,194,0.2)' : '0 2px 8px rgba(0,0,0,0.04)',
          border: isMe ? 'none' : '1px solid rgba(255,255,255,0.8)',
        }}>
        {!isMe && <div style={{ fontSize: '10px', fontFamily: 'JetBrains Mono, monospace', fontWeight: '700', marginBottom: '4px', color: 'var(--cy-brand)' }}>{sender?.full_name || 'Unknown'}</div>}
        <div style={{ fontSize: '14px', lineHeight: '1.5', wordBreak: 'break-word' }}>{msg.encrypted_content}</div>
        <div style={{ fontSize: '10px', opacity: 0.65, marginTop: '4px', display: 'flex', justifyContent: 'flex-end', gap: '6px', fontFamily: 'JetBrains Mono, monospace' }}>
          {msg.signature && <span style={{ color: isMe ? '#a5d8ff' : '#059669', fontWeight: '700' }}>✓ SIGNED</span>}
          <span>{new Date(msg.timestamp).toLocaleString('en-GB', { hour: '2-digit', minute: '2-digit' })}</span>
        </div>
      </motion.div>
    );
  };

  if (loading) return <div className="app-layout"><main className="app-content"><p style={{ textAlign: 'center', marginTop: '50px', color: 'var(--cy-text-mute)', fontFamily: 'JetBrains Mono, monospace', fontSize: '13px' }}>Establishing secure channel...</p></main></div>;

  const hasActiveChat = (chatMode === 'dm' && receiverId && !isNaN(parseInt(receiverId))) || (chatMode === 'groups' && selectedGroup);
  const charsLeft = MAX_MSG_LENGTH - newMessage.length;
  const banner = getRoleBanner(profile?.role, chatMode);

  return (
    <div className="app-layout">
      {/* NAV */}
      <nav className="app-nav">
        <a href="/dashboard" className="nav-brand">Fort<span>Knox</span></a>
        <div className="nav-center">
          <button
            onClick={() => setChatMode('dm')}
            style={{
              background: 'none', border: 'none', cursor: 'pointer', padding: '8px 16px',
              fontFamily: 'Space Grotesk, sans-serif', fontSize: '13px', fontWeight: chatMode === 'dm' ? '700' : '500',
              color: chatMode === 'dm' ? 'var(--cy-brand)' : 'var(--cy-text-mute)',
              borderBottom: chatMode === 'dm' ? '2px solid var(--cy-brand)' : '2px solid transparent',
              textTransform: 'uppercase', letterSpacing: '1px',
              transition: 'all 0.2s'
            }}
          >Direct Messages</button>
          <button
            onClick={() => { setChatMode('groups'); setSelectedGroup(null); setGroupMessages([]); }}
            style={{
              background: 'none', border: 'none', cursor: 'pointer', padding: '8px 16px',
              fontFamily: 'Space Grotesk, sans-serif', fontSize: '13px', fontWeight: chatMode === 'groups' ? '700' : '500',
              color: chatMode === 'groups' ? 'var(--cy-brand)' : 'var(--cy-text-mute)',
              borderBottom: chatMode === 'groups' ? '2px solid var(--cy-brand)' : '2px solid transparent',
              textTransform: 'uppercase', letterSpacing: '1px',
              transition: 'all 0.2s'
            }}
          >Group Channels</button>
        </div>
        <div className="nav-actions">
          {profile && (
            <div style={{ display: 'flex', alignItems: 'center', marginRight: '16px' }}>
              <div style={{ width: '32px', height: '32px', borderRadius: '50%', background: 'var(--cy-glass-bg)', border: '1px dashed var(--cy-border)', display: 'flex', alignItems: 'center', justifyContent: 'center', overflow: 'hidden' }}>
                {profile.profile_picture ? (
                  <img src={`https://127.0.0.1:8000/uploads/${profile.profile_picture}`} alt="Profile" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
                ) : (
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--cy-text-mute)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" /><circle cx="12" cy="7" r="4" /></svg>
                )}
              </div>
            </div>
          )}
          {hasActiveChat
            ? <button className="btn-logout" onClick={() => { if (chatMode === 'groups') { setSelectedGroup(null); setGroupMessages([]); } else { navigate('/chat'); } }}>← Exit Chat</button>
            : <button className="btn-logout" onClick={() => navigate('/network')}>← Back</button>
          }
        </div>
      </nav>

      {/* ROLE CONTEXT BANNER — page-hero style */}
      <div className="page-hero" style={{ padding: '20px 32px' }}>
        <div className="page-hero-inner" style={{ padding: 0 }}>
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '10px', color: 'var(--cy-brand)', textTransform: 'uppercase', letterSpacing: '2px', marginBottom: '10px' }}>{banner.label}</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <div style={{ width: '48px', height: '48px', borderRadius: '50%', background: 'var(--cy-glass-bg)', border: '2px dashed var(--cy-border)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="var(--cy-text-mute)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                {chatMode === 'dm'
                  ? <><rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></>
                  : <><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></>
                }
              </svg>
            </div>
            <div>
              <h2 style={{ margin: 0, fontFamily: 'Space Grotesk, sans-serif', fontWeight: '700', fontSize: '22px', color: 'var(--cy-text-main)' }}>{banner.title}</h2>
              <p style={{ margin: '4px 0 0', fontSize: '13px', color: 'var(--cy-text-mute)', borderLeft: '2px solid var(--cy-border)', paddingLeft: '12px' }}>{banner.desc}</p>
            </div>
          </div>
        </div>
      </div>

      <main style={{ flex: 1, display: 'flex', overflow: 'hidden', padding: '0 20px 20px', gap: '0', maxWidth: '1200px', margin: '0 auto', width: '100%' }}>

        {/* ========= DM MODE — 2-PANEL ========= */}
        {chatMode === 'dm' && (
          <div style={{ display: 'flex', gap: '12px', width: '100%', maxWidth: '960px', margin: '0 auto', height: 'calc(100vh - 260px)', marginTop: '24px' }}>

            {/* LEFT PANEL */}
            <div style={{
              width: '200px', flexShrink: 0, background: 'rgba(255,255,255,0.6)', backdropFilter: 'blur(20px)',
              borderRadius: '14px', border: '1px solid rgba(255,255,255,0.8)', boxShadow: '0 4px 24px rgba(0,0,0,0.06)',
              display: 'flex', flexDirection: 'column', overflow: 'hidden'
            }}>
              <div style={{ padding: '12px 14px', borderBottom: '1px dashed var(--cy-border)' }}>
                <div style={{ fontSize: '9px', fontFamily: 'JetBrains Mono, monospace', color: 'var(--cy-brand)', textTransform: 'uppercase', letterSpacing: '1.5px' }}>Connections · {connections.length}</div>
              </div>
              <div style={{ flex: 1, overflowY: 'auto' }}>
                {filteredConnections.length === 0 ? (
                  <p style={{ padding: '20px 14px', textAlign: 'center', color: 'var(--cy-text-mute)', fontSize: '12px', fontFamily: 'JetBrains Mono, monospace' }}>No connections yet.</p>
                ) : (
                  filteredConnections.map(c => {
                    const cId = (c.id || c.user_id)?.toString();
                    const isActive = receiverId === cId;
                    return (
                      <div
                        key={cId}
                        onClick={() => navigate('/chat/' + cId)}
                        style={{
                          padding: '10px 14px', cursor: 'pointer', borderBottom: '1px solid rgba(0,0,0,0.04)',
                          background: isActive ? 'rgba(10,102,194,0.08)' : 'transparent',
                          borderLeft: isActive ? '3px solid var(--cy-brand)' : '3px solid transparent',
                          transition: 'all 0.15s'
                        }}
                        onMouseEnter={e => { if (!isActive) e.currentTarget.style.background = 'rgba(10,102,194,0.04)'; }}
                        onMouseLeave={e => { if (!isActive) e.currentTarget.style.background = 'transparent'; }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <div style={{ width: '32px', height: '32px', borderRadius: '50%', background: isActive ? 'rgba(10,102,194,0.15)' : 'rgba(10,102,194,0.06)', border: `1px dashed ${isActive ? 'var(--cy-brand)' : 'var(--cy-border)'}`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, fontSize: '12px', fontWeight: '700', color: 'var(--cy-brand)', fontFamily: 'Space Grotesk, sans-serif' }}>
                            {c.full_name?.charAt(0).toUpperCase()}
                          </div>
                          <div style={{ overflow: 'hidden', flex: 1, minWidth: 0 }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                              <div style={{ fontSize: '12px', fontWeight: isActive ? '700' : '500', color: isActive ? 'var(--cy-brand)' : 'var(--cy-text-main)', fontFamily: 'Space Grotesk, sans-serif', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{c.full_name}</div>
                            </div>
                            <div style={{ fontSize: '10px', color: 'var(--cy-text-mute)', fontFamily: 'JetBrains Mono, monospace', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', textTransform: 'capitalize' }}>
                              {c.role?.replace('_', ' ')}
                            </div>
                          </div>
                          {c.unread_count > 0 && (
                            <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--cy-brand)', flexShrink: 0 }} />
                          )}
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </div>

            {/* RIGHT PANEL — Chat window */}
            <div style={{
              flex: 1, background: 'rgba(255,255,255,0.6)', backdropFilter: 'blur(20px)',
              borderRadius: '14px', border: '1px solid rgba(255,255,255,0.8)', boxShadow: '0 4px 24px rgba(0,0,0,0.06)',
              display: 'flex', flexDirection: 'column', overflow: 'hidden'
            }}>
              {!hasActiveChat ? (
                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '40px', textAlign: 'center' }}>
                  <div style={{ width: '52px', height: '52px', borderRadius: '50%', background: 'rgba(10,102,194,0.08)', border: '1px dashed rgba(10,102,194,0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '16px' }}>
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="var(--cy-brand)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></svg>
                  </div>
                  <h3 style={{ margin: '0 0 8px', fontFamily: 'Space Grotesk, sans-serif', fontWeight: '700', fontSize: '17px', color: 'var(--cy-text-main)' }}>Secure Messaging</h3>
                  <p style={{ margin: '0 0 10px', fontSize: '13px', color: 'var(--cy-text-mute)' }}>Select a connection to start an encrypted chat.</p>
                  <p style={{ margin: 0, fontSize: '11px', fontFamily: 'JetBrains Mono, monospace', color: 'var(--cy-text-mute)', background: 'rgba(5,150,105,0.08)', border: '1px dashed rgba(5,150,105,0.2)', borderRadius: '6px', padding: '5px 10px' }}>Messages are end-to-end encrypted</p>
                </div>
              ) : (
                <>
                  <div style={{ padding: '12px 20px', borderBottom: '1px dashed var(--cy-border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0 }}>
                    <div>
                      <div style={{ fontFamily: 'Space Grotesk, sans-serif', fontWeight: '700', fontSize: '15px', color: 'var(--cy-text-main)' }}>
                        {activeReceiver?.full_name || `User #${receiverId}`}
                      </div>
                      <div style={{ fontSize: '10px', fontFamily: 'JetBrains Mono, monospace', color: '#059669', marginTop: '2px' }}>End-to-End Encrypted</div>
                    </div>
                    <span className="card-badge" style={{ background: 'rgba(5,150,105,0.08)', color: '#065f46', border: '1px dashed rgba(5,150,105,0.3)', fontSize: '10px' }}>E2EE Active</span>
                  </div>
                  <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', padding: '16px 20px' }}>
                    {messages.length === 0
                      ? <p style={{ textAlign: 'center', color: 'var(--cy-text-mute)', marginTop: '15%', fontFamily: 'JetBrains Mono, monospace', fontSize: '12px' }}>No messages yet. Say hello!</p>
                      : messages.map(renderMessage)}
                    <div ref={messagesEndRef} />
                  </div>
                  <form onSubmit={handleSendMessage} style={{ padding: '12px 20px', borderTop: '1px dashed var(--cy-border)', display: 'flex', flexDirection: 'column', gap: '6px', flexShrink: 0 }}>
                    <div style={{ display: 'flex', gap: '8px' }}>
                      <input
                        type="text" placeholder="Write a secure message..." value={newMessage}
                        onChange={(e) => e.target.value.length <= MAX_MSG_LENGTH && setNewMessage(e.target.value)}
                        disabled={isSending}
                        style={{ flex: 1, borderRadius: '8px', padding: '9px 12px', border: '1px dashed var(--cy-border)', background: 'rgba(255,255,255,0.4)', backdropFilter: 'blur(10px)', fontFamily: 'Inter, sans-serif', fontSize: '13px', color: 'var(--cy-text-main)', outline: 'none' }}
                      />
                      <button className="btn-upload" type="submit" disabled={isSending || !newMessage.trim()} style={{ width: 'auto', opacity: !newMessage.trim() ? 0.4 : 1 }}>
                        {isSending ? "..." : "Send"}
                      </button>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: '10px', fontFamily: 'JetBrains Mono, monospace', color: '#059669' }}>🔒 Messages are end-to-end encrypted & signed</span>
                      <span style={{ fontSize: '10px', fontFamily: 'JetBrains Mono, monospace', color: charsLeft < 50 ? '#dc2626' : 'var(--cy-text-mute)' }}>{charsLeft} chars left</span>
                    </div>
                  </form>
                </>
              )}
            </div>
          </div>
        )}

        {/* ========= GROUP MODE — Full-width card list ========= */}
        {chatMode === 'groups' && !selectedGroup && (
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} style={{ width: '100%', marginTop: '16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <div>
                <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '10px', color: 'var(--cy-brand)', textTransform: 'uppercase', letterSpacing: '2px', marginBottom: '4px' }}>GROUP_CHANNELS</div>
                <h3 style={{ fontFamily: 'Space Grotesk, sans-serif', fontWeight: '700', fontSize: '18px', margin: 0 }}>Your Groups</h3>
              </div>
              {profile?.role === 'recruiter' && (
                <button className="btn-upload" style={{ padding: '8px 20px', fontSize: '11px' }} onClick={openGroupCreation}>+ New Group</button>
              )}
            </div>

            {groups.length === 0 ? (
              <div className="card" style={{ textAlign: 'center', padding: '50px 28px' }}>
                <p style={{ fontSize: '14px', color: 'var(--cy-text-mute)', marginBottom: '8px' }}>You haven't joined any groups yet.</p>
                <p style={{ fontSize: '12px', color: 'var(--cy-text-mute)', fontFamily: 'JetBrains Mono, monospace' }}>Create a group to start encrypted group conversations.</p>
              </div>
            ) : (
              <div style={{ display: 'grid', gap: '12px' }}>
                {groups.map(g => (
                  <motion.div key={g.id} className="card"
                    onClick={() => { setSelectedGroup(g); fetchGroupMessages(g.id); }}
                    style={{ cursor: 'pointer', marginBottom: 0 }}
                    whileHover={{ scale: 1.005 }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                        <div>
                          <h4 style={{ fontFamily: 'Space Grotesk, sans-serif', fontWeight: '700', fontSize: '15px', color: 'var(--cy-brand)', margin: '0 0 4px' }}>{g.name}</h4>
                          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center' }}>
                            <span style={{ fontSize: '11px', fontFamily: 'JetBrains Mono, monospace', color: 'var(--cy-text-mute)' }}>Created: {new Date(g.created_at).toLocaleDateString('en-GB')}</span>
                            <span style={{ fontSize: '9px', fontFamily: 'JetBrains Mono, monospace', color: 'var(--cy-text-mute)' }}>·</span>
                            <span style={{ fontSize: '11px', fontFamily: 'JetBrains Mono, monospace', color: 'var(--cy-text-mute)' }}>{g.member_count || '—'} members</span>
                          </div>
                          <div style={{ display: 'flex', gap: '6px', marginTop: '6px' }}>
                            <span style={{ fontSize: '9px', fontFamily: 'JetBrains Mono, monospace', background: 'rgba(5,150,105,0.1)', color: '#059669', border: '1px solid rgba(5,150,105,0.25)', borderRadius: '4px', padding: '2px 6px' }}>Active</span>
                            <span style={{ fontSize: '9px', fontFamily: 'JetBrains Mono, monospace', background: 'rgba(10,102,194,0.08)', color: 'var(--cy-brand)', border: '1px solid rgba(10,102,194,0.2)', borderRadius: '4px', padding: '2px 6px' }}>Recruiter Group</span>
                          </div>
                        </div>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        {profile?.role === 'recruiter' && (
                          <button
                            className="btn-delete"
                            style={{ padding: '6px 10px', fontSize: '10px', minWidth: 'auto', background: 'transparent', border: '1px solid rgba(185,28,28,0.2)' }}
                            onClick={(e) => { e.stopPropagation(); handleDeleteGroup(g.id); }}
                          >
                            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#dc2626" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="3 6 5 6 21 6" /><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" /></svg>
                          </button>
                        )}
                        <span className="card-badge" style={{ background: 'rgba(10,102,194,0.08)', color: 'var(--cy-brand)' }}>Enter →</span>
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
          <div style={{ display: 'flex', gap: '12px', width: '100%', height: 'calc(100vh - 260px)', marginTop: '16px' }}>
            
            {/* LEFT PANEL — Group Info Card */}
            <div className="card" style={{
              width: '180px', flexShrink: 0, padding: '16px', margin: 0,
              alignSelf: 'flex-start', height: 'fit-content'
            }}>
              <h4 style={{ fontFamily: 'Space Grotesk, sans-serif', fontWeight: '700', fontSize: '15px', color: 'var(--cy-brand)', margin: '0 0 8px', wordBreak: 'break-word' }}>{selectedGroup.name}</h4>
              <div style={{ fontSize: '11px', fontFamily: 'JetBrains Mono, monospace', color: 'var(--cy-text-mute)', marginBottom: '4px' }}>Created: {new Date(selectedGroup.created_at).toLocaleDateString('en-GB')}</div>
              <div style={{ fontSize: '11px', fontFamily: 'JetBrains Mono, monospace', color: 'var(--cy-text-mute)', marginBottom: '16px' }}>{groupMembers.length} members</div>
              
              <div style={{ display: 'flex', gap: '6px', marginBottom: '16px', flexWrap: 'wrap' }}>
                <span style={{ fontSize: '9px', fontFamily: 'JetBrains Mono, monospace', background: 'rgba(5,150,105,0.1)', color: '#059669', border: '1px solid rgba(5,150,105,0.25)', borderRadius: '4px', padding: '3px 6px' }}>Active</span>
                <span style={{ fontSize: '9px', fontFamily: 'JetBrains Mono, monospace', background: 'rgba(10,102,194,0.08)', color: 'var(--cy-brand)', border: '1px solid rgba(10,102,194,0.2)', borderRadius: '4px', padding: '3px 6px' }}>Recruiter Group</span>
              </div>
              
              <div style={{ marginTop: 'auto', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '4px', marginBottom: '8px' }}>
                  <AvatarStack members={groupMembers} max={4} />
                </div>
                {profile?.role === 'recruiter' && (
                  <>
                    <button 
                      style={{ width: '100%', padding: '8px', fontSize: '11px', background: 'rgba(10,102,194,0.1)', color: 'var(--cy-brand)', border: '1px solid rgba(10,102,194,0.2)', borderRadius: '6px', cursor: 'pointer', boxShadow: '0 4px 12px rgba(10,102,194,0.15)', fontWeight: '600' }} 
                      onClick={openAddMembers}
                    >+ Add Members</button>
                    <button 
                      style={{ width: '100%', padding: '8px', fontSize: '11px', background: 'rgba(220,38,38,0.1)', color: '#dc2626', border: '1px solid rgba(220,38,38,0.2)', borderRadius: '6px', cursor: 'pointer', boxShadow: '0 4px 12px rgba(220,38,38,0.15)', fontWeight: '600' }}
                      onClick={() => handleDeleteGroup(selectedGroup.id)}
                    >Delete Group</button>
                  </>
                )}
              </div>
            </div>

            {/* RIGHT PANEL — Chat window */}
            <div style={{
              flex: 1, background: 'rgba(255,255,255,0.6)', backdropFilter: 'blur(20px)',
              borderRadius: '14px', border: '1px solid rgba(255,255,255,0.8)', boxShadow: '0 4px 24px rgba(0,0,0,0.06)',
              display: 'flex', flexDirection: 'column', overflow: 'hidden'
            }}>
              {/* Group Chat Header */}
              <div style={{ padding: '12px 20px', borderBottom: '1px dashed var(--cy-border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0 }}>
                <div>
                  <div style={{ fontFamily: 'Space Grotesk, sans-serif', fontWeight: '700', fontSize: '15px', color: 'var(--cy-text-main)' }}>{selectedGroup.name}</div>
                  <div style={{ fontSize: '10px', fontFamily: 'JetBrains Mono, monospace', color: '#059669', marginTop: '2px' }}>Server-side Encrypted Chat</div>
                </div>
                <span className="card-badge" style={{ background: 'rgba(5,150,105,0.08)', color: '#065f46', border: '1px dashed rgba(5,150,105,0.3)', fontSize: '10px' }}>Secure Channel</span>
              </div>

            {/* Messages */}
            <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', padding: '16px 20px' }}>
              {groupMessages.length === 0
                ? <p style={{ textAlign: 'center', color: 'var(--cy-text-mute)', marginTop: '15%', fontFamily: 'JetBrains Mono, monospace', fontSize: '12px' }}>No messages in this group yet.</p>
                : groupMessages.map(renderGroupMessage)}
              <div ref={messagesEndRef} />
            </div>
            {/* Input */}
            <form onSubmit={handleSendGroupMessage} style={{ padding: '12px 20px', borderTop: '1px dashed var(--cy-border)', display: 'flex', flexDirection: 'column', gap: '6px', flexShrink: 0 }}>
              <div style={{ display: 'flex', gap: '8px' }}>
                <input
                  type="text" placeholder="Write a message to the group..." value={newMessage}
                  onChange={(e) => e.target.value.length <= MAX_MSG_LENGTH && setNewMessage(e.target.value)}
                  disabled={isSending}
                  style={{ flex: 1, borderRadius: '8px', padding: '9px 12px', border: '1px dashed var(--cy-border)', background: 'rgba(255,255,255,0.4)', backdropFilter: 'blur(10px)', fontFamily: 'Inter, sans-serif', fontSize: '13px', color: 'var(--cy-text-main)', outline: 'none' }}
                />
                <button className="btn-upload" type="submit" disabled={isSending || !newMessage.trim()} style={{ width: 'auto', opacity: !newMessage.trim() ? 0.4 : 1 }}>
                  {isSending ? "..." : "Send"}
                </button>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '10px', fontFamily: 'JetBrains Mono, monospace', color: '#059669' }}>Server-side encrypted group chat</span>
                <span style={{ fontSize: '10px', fontFamily: 'JetBrains Mono, monospace', color: charsLeft < 50 ? '#dc2626' : 'var(--cy-text-mute)' }}>{charsLeft} chars left</span>
              </div>
            </form>
            </div>
          </div>
        )}





        {/* ========= CREATE GROUP MODAL ========= */}
        <AnimatePresence>
          {showCreateGroup && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,19,40,0.6)', backdropFilter: 'blur(8px)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 9999 }}
              onClick={() => setShowCreateGroup(false)}>
              <motion.div initial={{ scale: 0.9, y: 20 }} animate={{ scale: 1, y: 0 }} exit={{ scale: 0.9, opacity: 0 }}
                className="card" style={{ width: '480px', maxHeight: '80vh', overflow: 'auto', margin: 0 }}
                onClick={e => e.stopPropagation()}>
                <div className="card-header">
                  <h3>Create Group</h3>
                  <button className="download-btn" onClick={() => setShowCreateGroup(false)}>Cancel</button>
                </div>
                <div className="form-group">
                  <label>Group Name <span style={{ fontSize: '11px', color: newGroupName.length > MAX_GROUP_NAME * 0.8 ? '#dc2626' : 'var(--cy-text-mute)', fontFamily: 'JetBrains Mono, monospace' }}>({newGroupName.length}/{MAX_GROUP_NAME})</span></label>
                  <input
                    type="text"
                    placeholder="e.g., Security Team"
                    value={newGroupName}
                    maxLength={MAX_GROUP_NAME}
                    onChange={e => setNewGroupName(e.target.value)}
                  />
                </div>
                <div style={{ marginTop: '8px', marginBottom: '4px', fontSize: '11px', fontFamily: 'JetBrains Mono, monospace', color: 'var(--cy-text-mute)', padding: '6px 10px', background: 'rgba(5,150,105,0.06)', borderRadius: '6px', border: '1px dashed rgba(5,150,105,0.2)' }}>
                  ℹ️ Max 50 members · 1 group per job posting
                </div>
                <div className="form-group" style={{ marginTop: '12px' }}>
                  <label>Add Members ({selectedMembers.length}/{MAX_GROUP_MEMBERS} selected)</label>
                  <div style={{ maxHeight: '200px', overflowY: 'auto', border: '1px dashed var(--cy-border)', borderRadius: '8px', padding: '8px' }}>
                    {connections.length === 0 ? (
                      <p style={{ fontSize: '12px', color: 'var(--cy-text-mute)', textAlign: 'center', padding: '16px', fontFamily: 'JetBrains Mono, monospace' }}>No connections found.</p>
                    ) : connections.map(conn => {
                      const atLimit = selectedMembers.length >= MAX_GROUP_MEMBERS && !selectedMembers.includes(conn.user_id);
                      return (
                        <div key={conn.user_id}
                          onClick={() => !atLimit && setSelectedMembers(prev => prev.includes(conn.user_id) ? prev.filter(uid => uid !== conn.user_id) : [...prev, conn.user_id])}
                          style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 14px', borderRadius: '6px', cursor: atLimit ? 'not-allowed' : 'pointer', background: selectedMembers.includes(conn.user_id) ? 'rgba(10,102,194,0.08)' : 'transparent', border: selectedMembers.includes(conn.user_id) ? '1px solid rgba(10,102,194,0.2)' : '1px solid transparent', marginBottom: '4px', transition: 'all 0.2s', opacity: atLimit ? 0.5 : 1 }}>
                          <span style={{ fontSize: '14px', fontWeight: '500' }}>{conn.full_name}</span>
                          <span style={{ fontSize: '18px', color: selectedMembers.includes(conn.user_id) ? 'var(--cy-brand)' : 'var(--cy-text-mute)' }}>{selectedMembers.includes(conn.user_id) ? '✓' : '○'}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
                <button type="button" className="btn-upload" style={{ width: '100%', marginTop: '16px' }} onClick={handleCreateGroup} disabled={!newGroupName.trim() || selectedMembers.length === 0}>
                  Create Group ({selectedMembers.length} members)
                </button>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* ========= ADD MEMBERS MODAL ========= */}
        <AnimatePresence>
          {showAddMembers && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,19,40,0.6)', backdropFilter: 'blur(8px)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 9999 }}
              onClick={() => setShowAddMembers(false)}>
              <motion.div initial={{ scale: 0.9, y: 20 }} animate={{ scale: 1, y: 0 }} exit={{ scale: 0.9, opacity: 0 }}
                className="card" style={{ width: '480px', maxHeight: '80vh', overflow: 'auto', margin: 0 }}
                onClick={e => e.stopPropagation()}>
                <div className="card-header">
                  <h3>Add Members to {selectedGroup?.name}</h3>
                  <button className="download-btn" onClick={() => setShowAddMembers(false)}>Cancel</button>
                </div>
                <div style={{ fontSize: '11px', fontFamily: 'JetBrains Mono, monospace', color: 'var(--cy-text-mute)', padding: '6px 10px', background: 'rgba(10,102,194,0.04)', borderRadius: '6px', border: '1px dashed rgba(10,102,194,0.15)', marginBottom: '12px' }}>
                  Current: {groupMembers.length}/50 members
                </div>
                <div className="form-group" style={{ marginTop: '8px' }}>
                  <label>Select Connections ({selectedMembers.length} selected)</label>
                  <div style={{ maxHeight: '300px', overflowY: 'auto', border: '1px dashed var(--cy-border)', borderRadius: '8px', padding: '8px' }}>
                    {(() => {
                      const existingMemberIds = groupMembers.map(m => m.user_id);
                      const available = connections.filter(c => !existingMemberIds.includes(c.user_id));
                      if (available.length === 0) return <p style={{ fontSize: '12px', color: 'var(--cy-text-mute)', textAlign: 'center', padding: '16px', fontFamily: 'JetBrains Mono, monospace' }}>All connections already in this group.</p>;
                      return available.map(conn => (
                        <div key={conn.user_id}
                          onClick={() => setSelectedMembers(prev => prev.includes(conn.user_id) ? prev.filter(uid => uid !== conn.user_id) : [...prev, conn.user_id])}
                          style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 14px', borderRadius: '6px', cursor: 'pointer', background: selectedMembers.includes(conn.user_id) ? 'rgba(10,102,194,0.08)' : 'transparent', border: selectedMembers.includes(conn.user_id) ? '1px solid rgba(10,102,194,0.2)' : '1px solid transparent', marginBottom: '4px', transition: 'all 0.2s' }}>
                          <span style={{ fontSize: '14px', fontWeight: '500' }}>{conn.full_name}</span>
                          <span style={{ fontSize: '18px', color: selectedMembers.includes(conn.user_id) ? 'var(--cy-brand)' : 'var(--cy-text-mute)' }}>{selectedMembers.includes(conn.user_id) ? '✓' : '○'}</span>
                        </div>
                      ));
                    })()}
                  </div>
                </div>
                <button type="button" className="btn-upload" style={{ width: '100%', marginTop: '16px' }} onClick={handleAddMembers} disabled={selectedMembers.length === 0}>
                  Add {selectedMembers.length} Member{selectedMembers.length !== 1 ? 's' : ''}
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
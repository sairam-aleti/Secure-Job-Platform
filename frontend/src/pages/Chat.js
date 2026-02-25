import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { messageAPI, authAPI, profileAPI } from '../services/api';
import cryptoService from '../services/cryptoService';
import './Dashboard.css';

function Chat() {
  const { receiverId } = useParams();
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [receiverKey, setReceiverKey] = useState(null);
  const [myPrivateKey, setMyPrivateKey] = useState(null);
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();
  const messagesEndRef = useRef(null);

  useEffect(() => {
    initializeChat();
    const interval = setInterval(fetchMessages, 4000);
    return () => clearInterval(interval);
  }, [receiverId]);

  const initializeChat = async () => {
    try {
      const profRes = await profileAPI.getProfile();
      setProfile(profRes.data);

      const encryptedKeyJson = localStorage.getItem('encrypted_private_key');
      const password = sessionStorage.getItem('user_pwd');
      
      if (encryptedKeyJson && password) {
        const decryptedKey = cryptoService.decryptPrivateKey(encryptedKeyJson, password);
        setMyPrivateKey(decryptedKey);
      } else {
        console.error("DEBUG: Local Private Key or Session Password missing");
      }

      const keyRes = await authAPI.getUserPublicKey(receiverId);
      setReceiverKey(keyRes.data.public_key);

      await fetchMessages();
    } catch (err) {
      console.error("Handshake failed:", err);
    } finally {
      setLoading(false);
    }
  };

  const fetchMessages = async () => {
    try {
      const res = await messageAPI.getMessages(receiverId);
      setMessages(res.data);
      scrollToBottom();
    } catch (err) { console.error(err); }
  };

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  const handleSendMessage = async (e) => {
    e.preventDefault();
    
    // DEBUGGING ALERTS: To find out why "nothing happens"
    if (!newMessage.trim()) return;
    if (!receiverKey) {
        alert("Blocked: Recipient Public Key not loaded from server.");
        return;
    }
    if (!profile?.public_key) {
        alert("Blocked: Your Public Key is missing from profile. Please refresh Dashboard.");
        return;
    }
    if (!myPrivateKey) {
        alert("Blocked: Your Private Key is locked. Please log out and log in again.");
        return;
    }

    try {
      const doubleCiphertext = cryptoService.encryptDouble(newMessage, receiverKey, profile.public_key);
      await messageAPI.sendMessage({
        receiver_id: parseInt(receiverId),
        encrypted_content: doubleCiphertext
      });
      setNewMessage('');
      fetchMessages();
    } catch (err) {
      alert("System Error: Check backend terminal.");
    }
  };

  const renderMessage = (msg) => {
    const isMe = msg.sender_id === profile?.id;
    let content = "[Encrypted Content]";
    if (myPrivateKey) {
      content = cryptoService.decryptMessage(msg.encrypted_content, myPrivateKey);
    }
    return (
      <div key={msg.id} style={{
        alignSelf: isMe ? 'flex-end' : 'flex-start',
        background: isMe ? '#3461c7' : '#f3f4f6',
        color: isMe ? 'white' : '#1a1a2e',
        padding: '12px 18px',
        borderRadius: '14px',
        maxWidth: '80%',
        marginBottom: '12px'
      }}>
        <div style={{ fontSize: '14px' }}>{content}</div>
        <div style={{ fontSize: '10px', opacity: 0.7, marginTop: '5px', textAlign: 'right' }}>
          {new Date(msg.timestamp).toLocaleString()}
        </div>
      </div>
    );
  };

  if (loading) return <div className="app-layout"><main className="app-content"><p style={{textAlign:'center'}}>Establishing secure channel...</p></main></div>;

  return (
    <div className="app-layout">
      <nav className="app-nav">
        <a href="/dashboard" className="nav-brand">FortKnox</a>
        <button className="btn-logout" onClick={() => navigate('/dashboard')}>Exit Chat</button>
      </nav>
      <main className="app-content" style={{ maxWidth: '700px' }}>
        <div className="card" style={{ height: '75vh', display: 'flex', flexDirection: 'column', padding: '0' }}>
          <div className="card-header" style={{ padding: '20px 28px', borderBottom: '1px solid #f3f4f6' }}>
            <h3 style={{ margin: 0 }}>Secure Chat</h3>
            <span className="card-badge" style={{ background: '#ecfdf5', color: '#065f46' }}>E2EE Active</span>
          </div>
          <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', padding: '28px' }}>
            {messages.length === 0 ? <p style={{ textAlign: 'center', color: '#6b7280' }}>No messages recorded.</p> : messages.map(renderMessage)}
            <div ref={messagesEndRef} />
          </div>
          <form onSubmit={handleSendMessage} style={{ padding: '20px 28px', borderTop: '1px solid #f3f4f6', display: 'flex', gap: '12px' }}>
            <input 
              type="text" 
              placeholder="Write a message..." 
              value={newMessage}
              onChange={(e) => setNewMessage(e.target.value)}
              style={{ flex: 1, borderRadius: '8px', padding: '10px', border: '1px solid #e5e7eb' }}
            />
            <button className="btn-upload" type="submit" style={{ width: 'auto' }}>Send</button>
          </form>
        </div>
      </main>
    </div>
  );
}

export default Chat;
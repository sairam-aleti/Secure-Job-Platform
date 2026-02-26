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
  const [isSending, setIsSending] = useState(false);
  const navigate = useNavigate();
  const messagesEndRef = useRef(null);

  useEffect(() => {
    initializeChat();
    const interval = setInterval(fetchMessages, 4000);
    return () => clearInterval(interval);
  }, [receiverId]);

  const initializeChat = async () => {
    try {
      // 1. Get My Profile
      let profRes = await profileAPI.getProfile();
      setProfile(profRes.data);

      // 2. Unlock My Private Key
      const encryptedKeyJson = localStorage.getItem('encrypted_private_key');
      const password = sessionStorage.getItem('user_pwd');
      
      if (encryptedKeyJson && password) {
        const decryptedKey = cryptoService.decryptPrivateKey(encryptedKeyJson, password);
        setMyPrivateKey(decryptedKey);
      } else {
        console.warn("Private Key locked. Messages will be encrypted but you cannot read them.");
      }

      // 3. Get Recipient's Public Key
      const keyRes = await authAPI.getUserPublicKey(receiverId);
      setReceiverKey(keyRes.data.public_key);

      await fetchMessages();
    } catch (err) {
      console.error("Chat initialization error:", err);
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
    if (!newMessage.trim() || isSending) return;

    if (!receiverKey) {
        alert("Cannot send: Recipient has no encryption key.");
        return;
    }

    setIsSending(true);
    try {
      // FIX: Derive public key locally from private key (more reliable than server fetch)
      let myPublicKey = profile?.public_key;
      if (!myPublicKey && myPrivateKey) {
          myPublicKey = cryptoService.getPublicKeyFromPrivate(myPrivateKey);
      }

      // Encrypt
      const doubleCiphertext = cryptoService.encryptDouble(
        newMessage, 
        receiverKey, 
        myPublicKey
      );
      
      if (!doubleCiphertext) throw new Error("Encryption failed");

      // Send
      await messageAPI.sendMessage({
        receiver_id: parseInt(receiverId),
        encrypted_content: doubleCiphertext
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

  const renderMessage = (msg) => {
    const isMe = msg.sender_id === profile?.id;
    let content = "[Encrypted Content]";

    if (myPrivateKey) {
      content = cryptoService.decryptMessage(msg.encrypted_content, myPrivateKey);
    } else {
      content = "🔒 key locked";
    }

    return (
      <div key={msg.id} style={{
        alignSelf: isMe ? 'flex-end' : 'flex-start',
        background: isMe ? '#3461c7' : '#f3f4f6',
        color: isMe ? 'white' : '#1a1a2e',
        padding: '12px 18px',
        borderRadius: '14px',
        borderBottomRightRadius: isMe ? '2px' : '14px',
        borderBottomLeftRadius: isMe ? '14px' : '2px',
        maxWidth: '80%',
        marginBottom: '12px',
        boxShadow: '0 1px 2px rgba(0,0,0,0.1)'
      }}>
        <div style={{ fontSize: '14px' }}>{content}</div>
        <div style={{ fontSize: '10px', opacity: 0.7, marginTop: '5px', textAlign: 'right' }}>
          {new Date(msg.timestamp).toLocaleString([], { hour: '2-digit', minute: '2-digit' })}
        </div>
      </div>
    );
  };

  if (loading) return <div className="app-layout"><main className="app-content"><p style={{textAlign:'center', marginTop:'50px'}}>Establishing secure channel...</p></main></div>;

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
              placeholder="Write a secure message..." 
              value={newMessage}
              onChange={(e) => setNewMessage(e.target.value)}
              disabled={isSending}
              style={{ flex: 1, borderRadius: '8px', padding: '10px', border: '1px solid #e5e7eb' }}
            />
            <button className="btn-upload" type="submit" disabled={isSending} style={{ width: 'auto' }}>
              {isSending ? "..." : "Send"}
            </button>
          </form>
        </div>
      </main>
    </div>
  );
}

export default Chat;
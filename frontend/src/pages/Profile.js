import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { profileAPI, authAPI, userAPI } from '../services/api';
import VirtualKeyboard from '../components/VirtualKeyboard';
import { motion } from 'framer-motion';
import './Dashboard.css';

function Profile() {
  const [profile, setProfile] = useState({
    full_name: '',
    headline: '',
    location: '',
    bio: '',
    skills: '',
    experience: '',
    education: '',
    headline_privacy: 'public',
    location_privacy: 'public',
    bio_privacy: 'public',
    skills_privacy: 'public',
    experience_privacy: 'public',
    education_privacy: 'public',
    share_view_history: true,
  });
  
  const [userEmail, setUserEmail] = useState('');
  const [currentPicture, setCurrentPicture] = useState(null);
  const [picturePreview, setPicturePreview] = useState(null);
  const [pictureFile, setPictureFile] = useState(null);
  const [pictureUploading, setPictureUploading] = useState(false);
  const [pictureMessage, setPictureMessage] = useState('');
  const fileInputRef = useRef(null);
  
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const [showDeleteZone, setShowDeleteZone] = useState(false);
  const [deleteOtp, setDeleteOtp] = useState('');
  const [deleteStatus, setDeleteStatus] = useState('');
  const [isDeleting, setIsDeleting] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem('access_token');
    if (!token) {
      navigate('/login');
      return;
    }
    fetchProfile();
  }, [navigate]);

  const fetchProfile = async () => {
    try {
      const response = await profileAPI.getProfile();
      const data = response.data;
      setUserEmail(data.email || '');
      setCurrentPicture(data.profile_picture || null);
      setProfile({
        full_name: data.full_name || '',
        headline: data.headline || '',
        location: data.location || '',
        bio: data.bio || '',
        skills: data.skills || '',
        experience: data.experience || '',
        education: data.education || '',
        headline_privacy: data.headline_privacy || 'public',
        location_privacy: data.location_privacy || 'public',
        bio_privacy: data.bio_privacy || 'public',
        skills_privacy: data.skills_privacy || 'public',
        experience_privacy: data.experience_privacy || 'public',
        education_privacy: data.education_privacy || 'public',
        share_view_history: data.share_view_history ?? true,
      });
    } catch (err) {
      setError('Failed to load profile');
      if (err.response?.status === 401) {
        localStorage.removeItem('access_token');
        navigate('/login');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (e) => {
    setProfile({
      ...profile,
      [e.target.name]: e.target.value,
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSaving(true);
    setMessage('');
    setError('');

    try {
      await profileAPI.updateProfile(profile);
      setMessage('Profile updated successfully!');
    } catch (err) {
      let errorMsg = err.response?.data?.detail || 'Update failed';
      if (Array.isArray(errorMsg)) errorMsg = errorMsg[0].msg;
      setError(errorMsg);
    } finally {
      setSaving(false);
    }
  };

  const handlePictureSelect = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    
    const allowed = ['image/jpeg', 'image/png', 'image/webp'];
    if (!allowed.includes(file.type)) {
      setPictureMessage('Only JPEG, PNG, and WebP images are allowed');
      return;
    }
    if (file.size > 5 * 1024 * 1024) {
      setPictureMessage('Image must be under 5MB');
      return;
    }

    setPictureFile(file);
    setPictureMessage('');
    const reader = new FileReader();
    reader.onload = (ev) => setPicturePreview(ev.target.result);
    reader.readAsDataURL(file);
  };

  const handlePictureUpload = async () => {
    if (!pictureFile) return;
    setPictureUploading(true);
    setPictureMessage('');
    
    try {
      const formData = new FormData();
      formData.append('file', pictureFile);
      const res = await profileAPI.uploadPicture(formData);
      setCurrentPicture(res.data.filename);
      setPictureFile(null);
      setPicturePreview(null);
      setPictureMessage('Profile picture updated!');
    } catch (err) {
      setPictureMessage(err.response?.data?.detail || 'Upload failed');
    } finally {
      setPictureUploading(false);
    }
  };

  const handleLogout = () => {
    localStorage.clear();
    sessionStorage.clear();
    navigate('/login');
  };

  const requestDeleteOTP = async () => {
    try {
      setDeleteStatus("Requesting OTP...");
      const email = userEmail || localStorage.getItem('user_email');
      await authAPI.sendOTP(email);
      setDeleteStatus("OTP sent to your email. Use the Virtual Keyboard below.");
    } catch (err) {
      setDeleteStatus("Failed to send OTP.");
    }
  };

  const handleDeleteKeyPress = (key) => {
    if (deleteOtp.length < 6) {
      setDeleteOtp(prev => prev + key);
    }
  };

  const handleDeleteBackspace = () => {
    setDeleteOtp(prev => prev.slice(0, -1));
  };

  const handleDeleteClear = () => {
    setDeleteOtp('');
  };

  const confirmDeleteAccount = async () => {
    if (deleteOtp.length !== 6) {
      setDeleteStatus("Please enter a 6-digit OTP.");
      return;
    }
    
    setIsDeleting(true);
    setDeleteStatus("Verifying OTP and deleting account...");
    
    try {
      await userAPI.deleteAccount({ otp_code: deleteOtp }); 
      alert("Account permanently deleted.");
      handleLogout();
    } catch (err) {
      let errorMsg = 'Deletion failed. Check console.';
      if (err.response?.data?.detail) {
          errorMsg = Array.isArray(err.response.data.detail) 
            ? err.response.data.detail[0].msg 
            : err.response.data.detail;
      }
      setDeleteStatus("Error: " + errorMsg);
      setIsDeleting(false);
    }
  };

  if (loading) {
    return (
      <div className="app-layout">
        <div className="app-grid-bg"></div>
        <main className="app-content">
          <p style={{ textAlign: 'center', marginTop: '80px', color: 'var(--cy-text-mute)', fontFamily: 'JetBrains Mono, monospace', fontSize: '13px' }}>Loading profile...</p>
        </main>
      </div>
    );
  }

  const pictureUrl = currentPicture ? `https://127.0.0.1:8000/uploads/${currentPicture}` : null;

  return (
    <div className="app-layout">
      <div className="app-grid-bg"></div>

      <nav className="app-nav">
        <a href="/dashboard" className="nav-brand">Fort<span>Knox</span></a>
        <div className="nav-center">
          <a href="/dashboard">Dashboard</a>
          <a href="/profile">Profile</a>
        </div>
        <div className="nav-actions">
          {profile && (
            <div style={{ display: 'flex', alignItems: 'center', marginRight: '16px' }}>
              <span style={{ color: 'var(--cy-text-mute)', fontSize: '10px', marginRight: '8px', fontFamily: 'JetBrains Mono, monospace', textTransform: 'uppercase', letterSpacing: '1px' }}>
                Welcome Back, {profile.full_name}
              </span>
              <div 
                style={{ 
                  width: '32px', height: '32px', borderRadius: '50%', background: 'var(--cy-glass-bg)', 
                  border: '1px dashed var(--cy-border)', display: 'flex', alignItems: 'center', justifyContent: 'center',
                  overflow: 'hidden', position: 'relative'
                }}
              >
                {currentPicture ? (
                  <img src={`https://127.0.0.1:8000/uploads/${currentPicture}`} alt="Profile" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
                ) : (
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--cy-text-mute)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                )}
              </div>
            </div>
          )}
          <button className="btn-logout" onClick={handleLogout}>Sign Out</button>
        </div>
      </nav>

      <div className="page-hero">
        <div className="page-hero-inner">
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '10px', color: 'var(--cy-brand)', textTransform: 'uppercase', letterSpacing: '2px', marginBottom: '12px' }}>PROFILE_EDITOR</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
            <div 
              style={{ 
                width: '64px', height: '64px', borderRadius: '50%', background: 'var(--cy-glass-bg)', 
                border: '2px dashed var(--cy-border)', display: 'flex', alignItems: 'center', justifyContent: 'center',
                overflow: 'hidden', position: 'relative', flexShrink: 0
              }}
            >
              {currentPicture ? (
                <img src={`https://127.0.0.1:8000/uploads/${currentPicture}`} alt="Profile" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
              ) : (
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--cy-text-mute)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
              )}
            </div>
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <h2 style={{ margin: 0 }}>Edit Profile</h2>
              <p style={{ margin: 0, marginTop: '4px' }}>Update your information, picture, and privacy preferences</p>
            </div>
          </div>
        </div>
      </div>

      <main className="app-content">
        {/* PROFILE PICTURE CARD */}
        <motion.div className="card" initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}>
          <div className="card-header">
            <h3>Profile Picture</h3>
            <span className="card-badge" style={{ background: 'rgba(10,102,194,0.08)', color: 'var(--cy-brand)' }}>Identity</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '24px', flexWrap: 'wrap' }}>
            <div 
              onClick={() => fileInputRef.current?.click()}
              style={{
                width: '100px', height: '100px', borderRadius: '50%',
                border: '2px dashed var(--cy-border)', overflow: 'hidden',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                cursor: 'pointer', background: 'rgba(10,102,194,0.04)',
                transition: 'all 0.3s', flexShrink: 0,
                backgroundImage: picturePreview ? `url(${picturePreview})` : (pictureUrl ? `url(${pictureUrl})` : 'none'),
                backgroundSize: 'cover', backgroundPosition: 'center'
              }}
            >
              {!picturePreview && !pictureUrl && (
                <span style={{ fontSize: '32px', color: 'var(--cy-text-mute)', opacity: 0.5 }}>👤</span>
              )}
            </div>
            <div style={{ flex: 1 }}>
              <input 
                ref={fileInputRef}
                type="file" 
                accept="image/jpeg,image/png,image/webp" 
                onChange={handlePictureSelect}
                style={{ display: 'none' }}
              />
              <p style={{ fontSize: '13px', color: 'var(--cy-text-mute)', marginBottom: '10px', fontFamily: 'JetBrains Mono, monospace' }}>
                Click the avatar to select a new picture (JPEG, PNG, WebP • max 5MB)
              </p>
              {pictureFile && (
                <button 
                  type="button" className="btn-upload" 
                  onClick={handlePictureUpload} disabled={pictureUploading}
                  style={{ padding: '8px 20px', fontSize: '11px', marginRight: '8px' }}
                >
                  {pictureUploading ? 'Uploading...' : 'Upload Picture'}
                </button>
              )}
              {currentPicture && !pictureFile && (
                <button 
                  type="button" className="btn-logout" 
                  onClick={async () => {
                    if (window.confirm('Remove profile picture?')) {
                      try {
                        await profileAPI.deletePicture();
                        setCurrentPicture(null);
                        setPictureMessage('Profile picture removed');
                      } catch (err) {
                        setPictureMessage('Failed to remove picture');
                      }
                    }
                  }}
                  style={{ padding: '8px 20px', fontSize: '11px', background: '#dc2626', color: 'white', border: 'none' }}
                >
                  Remove Picture
                </button>
              )}
              {pictureMessage && (
                <p style={{ 
                  fontSize: '12px', marginTop: '8px', fontFamily: 'JetBrains Mono, monospace',
                  color: pictureMessage.includes('updated') ? '#15803d' : '#dc2626'
                }}>{pictureMessage}</p>
              )}
            </div>
          </div>
        </motion.div>

        {/* PROFILE FORM */}
        <motion.div className="card" initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5, delay: 0.1 }}>
          <form onSubmit={handleSubmit}>
            {/* FULL NAME FIELD */}
            <div className="form-group">
              <label>Full Name</label>
              <input type="text" name="full_name" value={profile.full_name} onChange={handleChange} placeholder="Your full name" />
            </div>

            <div className="form-row">
              <div className="form-group">
                <label>Headline</label>
                <input type="text" name="headline" value={profile.headline} onChange={handleChange} placeholder="e.g., Software Engineer at Google" />
              </div>
              <div className="form-group privacy-select">
                <label>Privacy</label>
                <select name="headline_privacy" value={profile.headline_privacy} onChange={handleChange}>
                  <option value="public">Public</option>
                  <option value="connections">Connections Only</option>
                  <option value="private">Private</option>
                </select>
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label>Location</label>
                <input type="text" name="location" value={profile.location} onChange={handleChange} placeholder="e.g., New Delhi, India" />
              </div>
              <div className="form-group privacy-select">
                <label>Privacy</label>
                <select name="location_privacy" value={profile.location_privacy} onChange={handleChange}>
                  <option value="public">Public</option>
                  <option value="connections">Connections Only</option>
                  <option value="private">Private</option>
                </select>
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label>Bio</label>
                <textarea name="bio" value={profile.bio} onChange={handleChange} placeholder="Tell us about yourself..." rows="4" />
              </div>
              <div className="form-group privacy-select">
                <label>Privacy</label>
                <select name="bio_privacy" value={profile.bio_privacy} onChange={handleChange}>
                  <option value="public">Public</option>
                  <option value="connections">Connections Only</option>
                  <option value="private">Private</option>
                </select>
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label>Skills (comma separated)</label>
                <input type="text" name="skills" value={profile.skills} onChange={handleChange} placeholder="e.g., Python, React, Security" />
              </div>
              <div className="form-group privacy-select">
                <label>Privacy</label>
                <select name="skills_privacy" value={profile.skills_privacy} onChange={handleChange}>
                  <option value="public">Public</option>
                  <option value="connections">Connections Only</option>
                  <option value="private">Private</option>
                </select>
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label>Experience</label>
                <textarea name="experience" value={profile.experience} onChange={handleChange} placeholder="Describe your work experience..." rows="4" />
              </div>
              <div className="form-group privacy-select">
                <label>Privacy</label>
                <select name="experience_privacy" value={profile.experience_privacy} onChange={handleChange}>
                  <option value="public">Public</option>
                  <option value="connections">Connections Only</option>
                  <option value="private">Private</option>
                </select>
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label>Education</label>
                <textarea name="education" value={profile.education} onChange={handleChange} placeholder="Describe your education..." rows="4" />
              </div>
              <div className="form-group privacy-select">
                <label>Privacy</label>
                <select name="education_privacy" value={profile.education_privacy} onChange={handleChange}>
                  <option value="public">Public</option>
                  <option value="connections">Connections Only</option>
                  <option value="private">Private</option>
                </select>
              </div>
            </div>

            {/* ANONYMOUS MODE TOGGLE */}
            <div style={{ background: 'rgba(10,102,194,0.03)', border: '1px dashed var(--cy-border)', borderRadius: '12px', padding: '20px', marginTop: '20px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <input
                  type="checkbox"
                  name="share_view_history"
                  checked={profile.share_view_history}
                  onChange={(e) => setProfile({...profile, share_view_history: e.target.checked})}
                  style={{ width: '20px', height: '20px', cursor: 'pointer', accentColor: 'var(--cy-brand)' }}
                />
                <div>
                  <label style={{ fontWeight: '600', marginBottom: '2px', display: 'block', fontFamily: 'Space Grotesk, sans-serif', fontSize: '14px', color: 'var(--cy-text-main)', textTransform: 'none', letterSpacing: '0' }}>
                    Share View History
                  </label>
                  <p style={{ fontSize: '12px', color: 'var(--cy-text-mute)', margin: 0, fontFamily: 'JetBrains Mono, monospace' }}>
                    If turned off, you will appear as "Anonymous Professional" when viewing others' profiles.
                  </p>
                </div>
              </div>
            </div>

            {error && <div className="error-message" style={{ marginTop: '20px' }}>{error}</div>}
            {message && <div className="success-message" style={{ marginTop: '20px' }}>{message}</div>}

            <button type="submit" disabled={saving}>
              {saving ? 'Saving...' : 'Save Profile'}
            </button>
          </form>
        </motion.div>

        <motion.div className="card" style={{ marginTop: '40px', borderLeft: '3px solid #dc2626' }} initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5, delay: 0.3 }}>
          
          {!showDeleteZone ? (
            <div>
              <div className="card-header" style={{ borderBottom: 'none', paddingBottom: 0 }}>
                <h3 style={{ color: '#991b1b' }}>Danger Zone</h3>
              </div>
              <p style={{ color: 'var(--cy-text-mute)', marginBottom: '15px', fontSize: '14px' }}>
                Permanently delete your account and all associated data. This action requires OTP verification via virtual keyboard to prevent malware hijacking.
              </p>
              <button 
                type="button" 
                onClick={() => { setShowDeleteZone(true); requestDeleteOTP(); }}
                style={{ background: '#dc2626', color: 'white', padding: '12px 24px', border: 'none', borderRadius: '4px', cursor: 'pointer', fontWeight: '700', fontFamily: 'Space Grotesk, sans-serif', textTransform: 'uppercase', letterSpacing: '1px', fontSize: '12px', boxShadow: '0 8px 16px rgba(220,38,38,0.2)' }}
              >
                Initiate Account Deletion
              </button>
            </div>
          ) : (
            <div style={{ textAlign: 'center', padding: '20px', background: 'rgba(185,28,28,0.04)', borderRadius: '12px', border: '1px dashed rgba(185,28,28,0.2)' }}>
              <h4 style={{ color: '#991b1b', marginBottom: '10px', fontFamily: 'Space Grotesk, sans-serif' }}>Verify Deletion</h4>
              <p style={{ color: '#991b1b', fontSize: '12px', marginBottom: '20px', fontFamily: 'JetBrains Mono, monospace' }}>{deleteStatus}</p>
              
              <div style={{ 
                fontSize: '24px', letterSpacing: '8px', fontWeight: '700', 
                fontFamily: 'Space Grotesk, sans-serif',
                color: 'var(--cy-text-main)', background: 'rgba(255,255,255,0.6)',
                padding: '15px', borderRadius: '8px', border: '1px dashed var(--cy-border)',
                width: 'fit-content', margin: '0 auto 20px', minWidth: '200px', minHeight: '60px'
              }}>
                {deleteOtp.padEnd(6, '·')}
              </div>

              <VirtualKeyboard 
                onKeyPress={handleDeleteKeyPress}
                onBackspace={handleDeleteBackspace}
                onClear={handleDeleteClear}
                disabled={isDeleting}
              />

              <div style={{ marginTop: '20px', display: 'flex', justifyContent: 'center', gap: '15px' }}>
                <button 
                  type="button" 
                  onClick={() => setShowDeleteZone(false)}
                  disabled={isDeleting}
                  className="btn-logout"
                >
                  Cancel
                </button>
                <button 
                  type="button" 
                  onClick={confirmDeleteAccount}
                  disabled={isDeleting || deleteOtp.length !== 6}
                  style={{ background: '#dc2626', color: 'white', border: 'none', padding: '10px 24px', borderRadius: '4px', cursor: isDeleting ? 'not-allowed' : 'pointer', fontWeight: '700', fontFamily: 'Space Grotesk, sans-serif', textTransform: 'uppercase', letterSpacing: '1px', fontSize: '12px' }}
                >
                  {isDeleting ? 'Deleting...' : 'Permanently Delete Account'}
                </button>
              </div>
            </div>
          )}
        </motion.div>
      </main>
    </div>
  );
}

export default Profile;
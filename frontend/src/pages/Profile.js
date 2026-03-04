import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { profileAPI, authAPI, userAPI } from '../services/api';
import VirtualKeyboard from '../components/VirtualKeyboard';
import './Dashboard.css';

function Profile() {
  const [profile, setProfile] = useState({
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
  
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();

  // --- NEW: Account Deletion States ---
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
      setProfile({
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

  const handleLogout = () => {
    localStorage.clear();
    sessionStorage.clear();
    navigate('/login');
  };

  // --- NEW: Account Deletion Logic ---
  const requestDeleteOTP = async () => {
    try {
      setDeleteStatus("Requesting OTP...");
      const userEmail = localStorage.getItem('user_email');
      await authAPI.sendOTP(userEmail);
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
    setDeleteStatus("Verifying OTP and deleting account..."); // Added feedback
    
    try {
      // Send the data exactly as the backend Pydantic schema expects
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
        <main className="app-content">
          <p style={{ textAlign: 'center', marginTop: '80px' }}>Loading profile...</p>
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
          <a href="/profile">Profile</a>
        </div>
        <div className="nav-actions">
          <button className="btn-logout" onClick={handleLogout}>Sign Out</button>
        </div>
      </nav>

      <div className="page-hero">
        <div className="page-hero-inner">
          <h2>Edit Profile</h2>
          <p>Update your information and privacy preferences</p>
        </div>
      </div>

      <main className="app-content">
        <div className="card">
          <form onSubmit={handleSubmit}>
            <div className="form-row">
              <div className="form-group">
                <label>Headline</label>
                <input
                  type="text"
                  name="headline"
                  value={profile.headline}
                  onChange={handleChange}
                  placeholder="e.g., Software Engineer at Google"
                />
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
                <input
                  type="text"
                  name="location"
                  value={profile.location}
                  onChange={handleChange}
                  placeholder="e.g., New Delhi, India"
                />
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
                <textarea
                  name="bio"
                  value={profile.bio}
                  onChange={handleChange}
                  placeholder="Tell us about yourself..."
                  rows="4"
                />
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
                <input
                  type="text"
                  name="skills"
                  value={profile.skills}
                  onChange={handleChange}
                  placeholder="e.g., Python, React, Security"
                />
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
                <textarea
                  name="experience"
                  value={profile.experience}
                  onChange={handleChange}
                  placeholder="Describe your work experience..."
                  rows="4"
                />
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
                <textarea
                  name="education"
                  value={profile.education}
                  onChange={handleChange}
                  placeholder="Describe your education..."
                  rows="4"
                />
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
            <div className="card" style={{ background: '#f9fafb', border: '1px solid #e5e7eb', marginTop: '20px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <input
                  type="checkbox"
                  name="share_view_history"
                  checked={profile.share_view_history}
                  onChange={(e) => setProfile({...profile, share_view_history: e.target.checked})}
                  style={{ width: '20px', height: '20px', cursor: 'pointer' }}
                />
                <div>
                  <label style={{ fontWeight: '600', marginBottom: '2px', display: 'block' }}>
                    Share View History
                  </label>
                  <p style={{ fontSize: '13px', color: '#6b7280', margin: 0 }}>
                    If turned off, you will appear as "Anonymous Professional" when viewing others' profiles.
                  </p>
                </div>
              </div>
            </div>

            {error && <div className="error-message">{error}</div>}
            {message && <div className="success-message">{message}</div>}

            <button type="submit" disabled={saving}>
              {saving ? 'Saving...' : 'Save Profile'}
            </button>
          </form>
        </div>

        <div className="card" style={{ marginTop: '40px', border: '1px solid #fecaca' }}>
          
          {!showDeleteZone ? (
            <div>
              <p style={{ color: '#4b5563', marginBottom: '15px' }}>
                Permanently delete your account and all associated data. This action requires OTP verification via virtual keyboard to prevent malware hijacking.
              </p>
              <button 
                type="button" 
                onClick={() => { setShowDeleteZone(true); requestDeleteOTP(); }}
                style={{ background: '#dc2626', color: 'white', padding: '10px 20px', border: 'none', borderRadius: '8px', cursor: 'pointer', fontWeight: 'bold' }}
              >
                Initiate Account Deletion
              </button>
            </div>
          ) : (
            <div style={{ textAlign: 'center', padding: '20px', background: '#fef2f2', borderRadius: '8px' }}>
              <h4 style={{ color: '#991b1b', marginBottom: '10px' }}>Verify Deletion</h4>
              <p style={{ color: '#991b1b', fontSize: '14px', marginBottom: '20px' }}>{deleteStatus}</p>
              
              <div style={{ 
                fontSize: '24px', 
                letterSpacing: '8px', 
                fontWeight: 'bold', 
                color: '#1a1a2e',
                background: '#fff',
                padding: '15px',
                borderRadius: '8px',
                border: '1px solid #d1d5db',
                width: 'fit-content',
                margin: '0 auto 20px',
                minWidth: '200px',
                minHeight: '60px'
              }}>
                {deleteOtp.padEnd(6, '*')}
              </div>

              {/* Secure Virtual Keyboard Component */}
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
                  style={{ background: 'white', border: '1px solid #d1d5db', padding: '10px 20px', borderRadius: '8px', cursor: 'pointer' }}
                >
                  Cancel
                </button>
                <button 
                  type="button" 
                  onClick={confirmDeleteAccount}
                  disabled={isDeleting || deleteOtp.length !== 6}
                  style={{ background: '#dc2626', color: 'white', border: 'none', padding: '10px 20px', borderRadius: '8px', cursor: isDeleting ? 'not-allowed' : 'pointer', fontWeight: 'bold' }}
                >
                  {isDeleting ? 'Deleting...' : 'Permanently Delete Account'}
                </button>
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

export default Profile;
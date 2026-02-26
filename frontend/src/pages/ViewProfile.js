import React, { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { userAPI } from '../services/api';
import './Dashboard.css';

function ViewProfile() {
  const { userId } = useParams();
  const [targetProfile, setTargetProfile] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    fetchProfile();
  }, [userId]);

  const fetchProfile = async () => {
    try {
      const res = await userAPI.getOtherProfile(userId);
      setTargetProfile(res.data);
    } catch (err) {
      console.error(err);
      setError("This profile is private or does not exist.");
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <div className="app-layout"><main className="app-content"><p style={{textAlign:'center'}}>Loading secure profile...</p></main></div>;

  if (error || !targetProfile) {
    return (
      <div className="app-layout">
        <main className="app-content">
          <div className="error-card">
            <h2>Access Restricted</h2>
            <p>{error}</p>
            <button className="back-link" onClick={() => navigate('/network')}>Back to Network</button>
          </div>
        </main>
      </div>
    );
  }

  // Helper to format restricted fields
  const formatField = (value, fallback = "Not specified") => {
    if (value === "RESTRICTED_BY_PRIVACY") return "Information restricted by user privacy settings.";
    return value || fallback;
  };

  return (
    <div className="app-layout">
      <nav className="app-nav">
        <a href="/dashboard" className="nav-brand">FortKnox</a>
        <div className="nav-center">
            <a href="/dashboard">Dashboard</a>
            <a href="/network">Network</a>
        </div>
        <div className="nav-actions">
           <button className="btn-logout" onClick={() => navigate('/network')}>Back</button>
        </div>
      </nav>

      <div className="page-hero">
        <div className="page-hero-inner">
          <h2>{targetProfile.full_name}</h2>
          <p>{targetProfile.headline || 'Professional Member'}</p>
          
          {/* NEW: MUTUAL CONNECTIONS DISPLAY */}
          <div style={{ marginTop: '12px', display: 'flex', alignItems: 'center', gap: '15px' }}>
            <span className="card-badge" style={{ background: '#eef2ff', color: '#3461c7' }}>
                {targetProfile.role.replace('_', ' ')}
            </span>
            <span style={{ fontSize: '14px', color: '#3461c7', fontWeight: '600' }}>
                {targetProfile.mutual_connections} Mutual Connection{targetProfile.mutual_connections !== 1 ? 's' : ''}
            </span>
          </div>
        </div>
      </div>

      <main className="app-content">
        <div className="card">
          <div className="card-header"><h3>Professional Bio</h3></div>
          <p style={{ 
            color: targetProfile.bio === "RESTRICTED_BY_PRIVACY" ? '#6b7280' : '#1a1a2e',
            fontStyle: targetProfile.bio === "RESTRICTED_BY_PRIVACY" ? 'italic' : 'normal'
          }}>
            {formatField(targetProfile.bio)}
          </p>
        </div>

        <div className="card">
          <div className="card-header"><h3>Professional Details</h3></div>
          <div className="profile-info">
            <div className="profile-field">
                <span className="profile-field-label">Location</span>
                <span className="profile-field-value" style={{ 
                    color: targetProfile.location === "RESTRICTED_BY_PRIVACY" ? '#6b7280' : '#1a1a2e' 
                }}>
                    {targetProfile.location === "RESTRICTED_BY_PRIVACY" ? "Private" : (targetProfile.location || "Not specified")}
                </span>
            </div>
            <div className="profile-field">
                <span className="profile-field-label">Skills</span>
                <span className="profile-field-value" style={{ 
                    color: targetProfile.skills === "RESTRICTED_BY_PRIVACY" ? '#6b7280' : '#1a1a2e' 
                }}>
                    {targetProfile.skills === "RESTRICTED_BY_PRIVACY" ? "Private" : (targetProfile.skills || "Not specified")}
                </span>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-header"><h3>Experience & Education</h3></div>
          <div className="profile-info">
            <div className="profile-field">
                <span className="profile-field-label">Work Experience</span>
                <span className="profile-field-value">
                    {formatField(targetProfile.experience, "No experience listed")}
                </span>
            </div>
            <div className="profile-field">
                <span className="profile-field-label">Education</span>
                <span className="profile-field-value">
                    {formatField(targetProfile.education, "No education listed")}
                </span>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

export default ViewProfile;
import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { userAPI } from '../services/api';
import { motion } from 'framer-motion';
import './Dashboard.css';

function ViewProfile() {
  const { userId } = useParams();
  const [targetProfile, setTargetProfile] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const fetchProfile = useCallback(async () => {
    try {
      const res = await userAPI.getOtherProfile(userId);
      setTargetProfile(res.data);
    } catch (err) {
      console.error(err);
      setError("This profile is private or does not exist.");
    } finally {
      setLoading(false);
    }
  }, [userId]);

  useEffect(() => {
    fetchProfile();
  }, [fetchProfile]);

  if (loading) return <div className="app-layout"><div className="app-grid-bg"></div><main className="app-content"><p style={{textAlign:'center', color: 'var(--cy-text-mute)', fontFamily: 'JetBrains Mono, monospace', fontSize: '13px', marginTop: '80px'}}>Loading secure profile...</p></main></div>;

  if (error || !targetProfile) {
    return (
      <div className="app-layout">
        <div className="app-grid-bg"></div>
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

  const formatField = (value, fallback = "Not specified") => {
    if (value === "RESTRICTED_BY_PRIVACY") return "Information restricted by user privacy settings.";
    return value || fallback;
  };

  return (
    <div className="app-layout">
      <div className="app-grid-bg"></div>

      <nav className="app-nav">
        <a href="/dashboard" className="nav-brand">Fort<span>Knox</span></a>
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
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '10px', color: 'var(--cy-brand)', textTransform: 'uppercase', letterSpacing: '2px', marginBottom: '12px' }}>USER_PROFILE</div>
          <h2>{targetProfile.full_name}</h2>
          <p style={{ borderLeft: 'none', paddingLeft: 0 }}>{targetProfile.headline || 'Professional Member'}</p>
          
          <div style={{ marginTop: '16px', display: 'flex', alignItems: 'center', gap: '15px' }}>
            <span className="card-badge" style={{ background: 'rgba(10,102,194,0.08)', color: 'var(--cy-brand)' }}>
                {targetProfile.role.replace('_', ' ')}
            </span>
            <span style={{ fontSize: '12px', color: 'var(--cy-brand)', fontWeight: '700', fontFamily: 'JetBrains Mono, monospace' }}>
                {targetProfile.mutual_connections} Mutual Connection{targetProfile.mutual_connections !== 1 ? 's' : ''}
            </span>
          </div>
        </div>
      </div>

      <main className="app-content">
        <motion.div className="card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
          <div className="card-header"><h3>Professional Bio</h3></div>
          <p style={{ 
            color: targetProfile.bio === "RESTRICTED_BY_PRIVACY" ? 'var(--cy-text-mute)' : 'var(--cy-text-main)',
            fontStyle: targetProfile.bio === "RESTRICTED_BY_PRIVACY" ? 'italic' : 'normal',
            fontFamily: targetProfile.bio === "RESTRICTED_BY_PRIVACY" ? 'JetBrains Mono, monospace' : 'Inter, sans-serif',
            fontSize: '14px', lineHeight: '1.7'
          }}>
            {formatField(targetProfile.bio)}
          </p>
        </motion.div>

        <motion.div className="card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
          <div className="card-header"><h3>Professional Details</h3></div>
          <div className="profile-info">
            <div className="profile-field">
                <span className="profile-field-label">Location</span>
                <span className="profile-field-value" style={{ 
                    color: targetProfile.location === "RESTRICTED_BY_PRIVACY" ? 'var(--cy-text-mute)' : 'var(--cy-text-main)' 
                }}>
                    {targetProfile.location === "RESTRICTED_BY_PRIVACY" ? "Private" : (targetProfile.location || "Not specified")}
                </span>
            </div>
            <div className="profile-field">
                <span className="profile-field-label">Skills</span>
                <span className="profile-field-value" style={{ 
                    color: targetProfile.skills === "RESTRICTED_BY_PRIVACY" ? 'var(--cy-text-mute)' : 'var(--cy-text-main)' 
                }}>
                    {targetProfile.skills === "RESTRICTED_BY_PRIVACY" ? "Private" : (targetProfile.skills || "Not specified")}
                </span>
            </div>
          </div>
        </motion.div>

        <motion.div className="card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}>
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
        </motion.div>
      </main>
    </div>
  );
}

export default ViewProfile;
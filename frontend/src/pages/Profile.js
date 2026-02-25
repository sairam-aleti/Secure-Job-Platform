import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { profileAPI } from '../services/api';
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
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();

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
      setError(err.response?.data?.detail || 'Failed to update profile');
    } finally {
      setSaving(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('user_email');
    navigate('/login');
  };

  if (loading) {
    return (
      <div className="dashboard-container">
        <p>Loading...</p>
      </div>
    );
  }

  return (
    <div className="dashboard-container">
      <nav className="dashboard-nav">
        <h1>Secure Job Platform</h1>
        <div className="nav-links">
          <a href="/dashboard">Dashboard</a>
          <button onClick={handleLogout}>Logout</button>
        </div>
      </nav>

      <main className="dashboard-main">
        <div className="profile-card">
          <h2>Edit Your Profile</h2>
          
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
                <select
                  name="headline_privacy"
                  value={profile.headline_privacy}
                  onChange={handleChange}
                >
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
                <select
                  name="location_privacy"
                  value={profile.location_privacy}
                  onChange={handleChange}
                >
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
                <select
                  name="bio_privacy"
                  value={profile.bio_privacy}
                  onChange={handleChange}
                >
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
                <select
                  name="skills_privacy"
                  value={profile.skills_privacy}
                  onChange={handleChange}
                >
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
                <select
                  name="experience_privacy"
                  value={profile.experience_privacy}
                  onChange={handleChange}
                >
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
                <select
                  name="education_privacy"
                  value={profile.education_privacy}
                  onChange={handleChange}
                >
                  <option value="public">Public</option>
                  <option value="connections">Connections Only</option>
                  <option value="private">Private</option>
                </select>
              </div>
            </div>

            {error && <div className="error-message">{error}</div>}
            {message && <div className="success-message">{message}</div>}

            <button type="submit" disabled={saving}>
              {saving ? 'Saving...' : 'Save Profile'}
            </button>
          </form>
        </div>
      </main>
    </div>
  );
}

export default Profile;
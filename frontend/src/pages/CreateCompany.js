import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { companyAPI, profileAPI } from '../services/api';
import { motion } from 'framer-motion';
import './Dashboard.css';

function CreateCompany() {
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    location: '',
    website: '',
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const navigate = useNavigate();
  const location = useLocation();

  const [companiesCount, setCompaniesCount] = useState(0);
  const [isEditMode, setIsEditMode] = useState(false);
  const [editCompanyId, setEditCompanyId] = useState(null);

  React.useEffect(() => {
    const searchParams = new URLSearchParams(location.search);
    const editId = searchParams.get('edit');
    if (editId) {
      setIsEditMode(true);
      setEditCompanyId(editId);
    }
    fetchCompanies(editId);
  }, [location.search]);

  const fetchCompanies = async (editId) => {
    try {
      const profileRes = await profileAPI.getProfile();
      const response = await companyAPI.list();
      const myComps = response.data.filter(c => c.recruiter_id === profileRes.data.id);
      setCompaniesCount(myComps.length);

      if (editId) {
        const compTarget = myComps.find(c => c.id.toString() === editId);
        if (compTarget) {
            setFormData({
                name: compTarget.name,
                description: compTarget.description,
                location: compTarget.location,
                website: compTarget.website || ''
            });
        }
      }
    } catch (err) {}
  };

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccessMessage('');

    if (!formData.name.trim() || !formData.description.trim() || !formData.location.trim()) {
      setError('Required fields cannot be empty spaces.');
      setLoading(false);
      return;
    }

    const payload = {
      ...formData,
      name: formData.name.trim(),
      description: formData.description.trim(),
      location: formData.location.trim(),
      website: formData.website.trim(),
    };

    try {
      if (isEditMode) {
        await companyAPI.update(editCompanyId, payload);
        setSuccessMessage('Company updated successfully! Redirecting...');
      } else {
        await companyAPI.create(payload);
        setSuccessMessage('Company created successfully! Redirecting...');
      }
      setTimeout(() => navigate('/dashboard'), 2000);
    } catch (err) {
      setError(err.response?.data?.detail || `Failed to ${isEditMode ? 'update' : 'create'} company`);
      setLoading(false);
    }
  };

  return (
    <div className="app-layout">


      <nav className="app-nav">
        <a href="/dashboard" className="nav-brand">Fort<span>Knox</span></a>
        <div className="nav-center">
          <a href="/dashboard">Dashboard</a>
        </div>
        <div className="nav-actions">
          <button className="btn-logout" onClick={() => navigate('/dashboard')}>Back</button>
        </div>
      </nav>

      <div className="page-hero">
        <div className="page-hero-inner">
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '10px', color: 'var(--cy-brand)', textTransform: 'uppercase', letterSpacing: '2px', marginBottom: '12px' }}>COMPANY_SETUP</div>
          <h2>Create Company Page</h2>
          <p>Establish your company presence on FortKnox</p>
        </div>
      </div>

      <main className="app-content">
        <motion.div className="card" initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}>
          {!isEditMode && companiesCount >= 3 ? (
             <div style={{ background: 'rgba(220, 38, 38, 0.1)', border: '1px solid #dc2626', padding: '24px', borderRadius: '8px', color: '#dc2626', textAlign: 'center', marginBottom: '20px' }}>
               <h3 style={{ margin: 0, fontSize: '18px', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}>
                 <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                 Action Required
               </h3>
               <p style={{ marginTop: '12px', fontSize: '15px' }}>You have reached the maximum limit of 3 company profiles.</p>
             </div>
          ) : null}

          <form onSubmit={handleSubmit} style={{ opacity: !isEditMode && companiesCount >= 3 ? 0.4 : 1, pointerEvents: !isEditMode && companiesCount >= 3 ? 'none' : 'auto' }}>
            <div className="form-group">
              <label>Company Name</label>
              <input type="text" name="name" value={formData.name} onChange={handleChange} required placeholder="e.g. SecureTech Inc." maxLength={200} />
              <div style={{fontSize:'10px', color:'var(--cy-text-mute)', textAlign:'right', marginTop:'2px'}}>{(formData.name || '').length}/200</div>
            </div>

            <div className="form-group">
              <label>Description</label>
              <textarea name="description" value={formData.description} onChange={handleChange} required placeholder="Tell us about your company..." rows="4" maxLength={2000} />
              <div style={{fontSize:'10px', color:'var(--cy-text-mute)', textAlign:'right', marginTop:'2px'}}>{(formData.description || '').length}/2000</div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label>Location</label>
                <input type="text" name="location" value={formData.location} onChange={handleChange} required placeholder="e.g. San Francisco, CA" maxLength={200} />
                <div style={{fontSize:'10px', color:'var(--cy-text-mute)', textAlign:'right', marginTop:'2px'}}>{(formData.location || '').length}/200</div>
              </div>
              <div className="form-group">
                <label>Website (Optional)</label>
                <input type="url" name="website" value={formData.website} onChange={handleChange} placeholder="https://example.com" maxLength={200} />
                <div style={{fontSize:'10px', color:'var(--cy-text-mute)', textAlign:'right', marginTop:'2px'}}>{(formData.website || '').length}/200</div>
              </div>
            </div>

            {successMessage && <div className="success-message">{successMessage}</div>}
            {error && <div className="error-message">{error}</div>}

            <button type="submit" disabled={loading || (!isEditMode && companiesCount >= 3)}>
              {loading ? 'Processing...' : (isEditMode ? 'Update Company' : 'Create Company')}
            </button>
          </form>
        </motion.div>
      </main>
    </div>
  );
}

export default CreateCompany;
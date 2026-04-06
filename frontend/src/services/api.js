import axios from 'axios';

const API_BASE_URL = 'https://127.0.0.1:8000';

// Create axios instance
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add token to requests if available
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// SECURITY: Auto-logout on session conflict (401 with specific message)
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      const detail = error.response?.data?.detail || '';
      if (detail.includes('Session expired') || detail.includes('logged in from another')) {
        // Another device logged in — force logout on this one
        alert('Session terminated: You have been logged in from another device.');
        localStorage.clear();
        sessionStorage.clear();
        window.location.href = '/login';
        return Promise.reject(error);
      }
    }
    return Promise.reject(error);
  }
);

// API Functions
export const authAPI = {
  register: (data) => api.post('/register', data),
  login: (data) => api.post('/login', data),
  loginVerifyOTP: (data) => api.post('/login/verify-otp', data),
  refresh: () => api.post('/auth/refresh'),
  sendOTP: (email) => api.post('/send-otp', { email }),
  verifyOTP: (data) => api.post('/verify-otp', data),
  updatePublicKey: (data) => api.post('/users/public-key', data),
  getUserPublicKey: (id) => api.get(`/users/${id}/public-key`),
  requestPasswordReset: (email) => api.post('/password-reset/request', { email }),
  confirmPasswordReset: (data) => api.post('/password-reset/confirm', data),
};

export const profileAPI = {
  getProfile: () => api.get('/profile'),
  updateProfile: (data) => api.put('/profile', data),
  uploadPicture: (formData) => api.put('/profile/picture', formData, { headers: { 'Content-Type': undefined } }),
  deletePicture: () => api.delete('/profile/picture'),
  getRecentActivity: () => api.get('/profile/recent-activity'),
  getLastLogin: () => api.get('/profile/last-login'),
};


export const userAPI = {
  getDirectory: (q = '', page = 1) => api.get(`/users/directory?q=${q}&page=${page}`),
  getOtherProfile: (id) => api.get(`/users/${id}/profile`),
  getViewers: () => api.get('/profile/viewers'),
  deleteAccount: (data) => api.post('/users/me/delete', data), 
};

export const connectionAPI = {
  sendRequest: (receiverId) => api.post('/connections/request', { receiver_id: receiverId }),
  getPending: () => api.get('/connections/pending'),
  updateRequest: (requestId, status) => api.put('/connections/accept', { request_id: requestId, status: status }),
  getMyConnections: () => api.get('/connections/my'),
};

export const companyAPI = {
  create: (data) => api.post('/companies', data),
  list: () => api.get('/companies'),
  update: (id, data) => api.put(`/companies/${id}`, data),
  delete: (id) => api.delete(`/companies/${id}`)
};

export const jobAPI = {
  create: (data) => api.post('/jobs', data),
  list: () => api.get('/jobs'),
  myJobs: () => api.get('/my-jobs'),
  getRecommendations: () => api.get('/jobs/recommendations'),
  update: (id, data) => api.put(`/jobs/${id}`, data),
  delete: (id) => api.delete(`/jobs/${id}`),
};

export const resumeAPI = {
  upload: (formData) => api.post('/upload-resume', formData, { headers: { 'Content-Type': undefined } }),
  download: (id) => api.get(`/download-resume/${id}`, { responseType: 'blob' }),
  list: () => api.get('/my-resumes'),
  delete: (id) => api.delete(`/resumes/${id}`),
};

export const applicationAPI = {
  apply: (data) => api.post('/applications', data),
  myApplications: () => api.get('/applications/my'),
  recruiterApplications: () => api.get('/applications/recruiter'),
  updateStatus: (id, status) => api.put(`/applications/${id}/status`, { status }),
  updateNotes: (id, notes) => api.put(`/applications/${id}/notes`, { notes }),
};

export const messageAPI = {
  sendMessage: (data) => api.post('/messages', data),
  getMessages: (id) => api.get(`/messages/${id}`),
};

export const adminAPI = {
  listUsers: () => api.get('/admin/users'),
  suspendUser: (id) => api.post(`/admin/suspend/${id}`),
  activateUser: (id) => api.post(`/admin/activate/${id}`),
  deleteUser: (id) => api.delete(`/admin/delete/${id}`),
  getStats: () => api.get('/admin/stats'),
  
  // Admin action queue
  requestAction: (data) => api.post('/admin/request-action', data),
  getActionQueue: () => api.get('/admin/action-queue'),
  
  // Superadmin: Review actions
  reviewAction: (data) => api.post('/superadmin/review-action', data),
  approveAdmin: (userId) => api.post(`/superadmin/approve-admin/${userId}`),
  
  // Reports / Content Moderation
  getReports: () => api.get('/admin/reports'),
  reviewReport: (id, status) => api.put(`/admin/reports/${id}`, { status }),
  
  // Blockchain
  getBlockchain: () => api.get('/admin/blockchain'),
  mineBlock: () => api.post('/admin/blockchain/mine'),
  verifyChain: () => api.get('/admin/blockchain/verify'),
};

export const reportAPI = {
  create: (data) => api.post('/reports', data),
};

export const groupAPI = {
  create: (data) => api.post('/groups', data),
  myGroups: () => api.get('/groups/my'),
  sendMessage: (groupId, data) => api.post(`/groups/${groupId}/messages`, data),
  getMessages: (groupId) => api.get(`/groups/${groupId}/messages`),
  getMembers: (groupId) => api.get(`/groups/${groupId}/members`),
  addMembers: (groupId, data) => api.post(`/groups/${groupId}/members`, data),
  deleteGroup: (id) => api.delete(`/groups/${id}`),
};
export const contactAPI = {
  sendMessage: (data) => api.post('/contact', data),
};

export default api;
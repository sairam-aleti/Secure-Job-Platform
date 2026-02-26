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

// API Functions
export const authAPI = {
  register: (data) => api.post('/register', data),
  login: (data) => api.post('/login', data),
  sendOTP: (email) => api.post('/send-otp', { email }),
  verifyOTP: (data) => api.post('/verify-otp', data),
  updatePublicKey: (data) => api.post('/users/public-key', data),
  getUserPublicKey: (id) => api.get(`/users/${id}/public-key`),
};

export const profileAPI = {
  getProfile: () => api.get('/profile'),
  updateProfile: (data) => api.put('/profile', data),
};

// NEW: User Directory for Networking
export const userAPI = {
  getDirectory: (q = '', page = 1) => api.get(`/users/directory?q=${q}&page=${page}`),
  getOtherProfile: (id) => api.get(`/users/${id}/profile`),
  getViewers: () => api.get('/profile/viewers'),
};

// NEW: Connection Management
export const connectionAPI = {
  sendRequest: (receiverId) => api.post('/connections/request', { receiver_id: receiverId }),
  getPending: () => api.get('/connections/pending'),
  updateRequest: (requestId, status) => api.put('/connections/accept', { request_id: requestId, status: status }),
};

export const companyAPI = {
  create: (data) => api.post('/companies', data),
  list: () => api.get('/companies'),
};

export const jobAPI = {
  create: (data) => api.post('/jobs', data),
  list: () => api.get('/jobs'),
  myJobs: () => api.get('/my-jobs'),
  getRecommendations: () => api.get('/jobs/recommendations'),
};

export const resumeAPI = {
  upload: (formData) => api.post('/upload-resume', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  }),
  download: (id) => api.get(`/download-resume/${id}`, { responseType: 'blob' }),
  list: () => api.get('/my-resumes'),
};

export const applicationAPI = {
  apply: (data) => api.post('/applications', data),
  myApplications: () => api.get('/applications/my'),
  recruiterApplications: () => api.get('/applications/recruiter'),
  updateStatus: (id, status) => api.put(`/applications/${id}/status`, { status }),
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
};

export default api;
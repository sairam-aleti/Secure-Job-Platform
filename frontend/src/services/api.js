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
  updatePublicKey: (data) => api.post('/users/public-key', data), // NEW
  getUserPublicKey: (id) => api.get(`/users/${id}/public-key`), // NEW
};

export const profileAPI = {
  getProfile: () => api.get('/profile'),
  updateProfile: (data) => api.put('/profile', data),
};

export const companyAPI = {
  create: (data) => api.post('/companies', data),
  list: () => api.get('/companies'),
};

export const jobAPI = {
  create: (data) => api.post('/jobs', data),
  list: () => api.get('/jobs'),
  myJobs: () => api.get('/my-jobs'),
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
};

export const messageAPI = {
  sendMessage: (data) => api.post('/messages', data), // NEW
  getMessages: (id) => api.get(`/messages/${id}`), // NEW
};

export const adminAPI = {
  listUsers: () => api.get('/admin/users'),
  suspendUser: (id) => api.post(`/admin/suspend/${id}`),
  activateUser: (id) => api.post(`/admin/activate/${id}`),
  deleteUser: (id) => api.delete(`/admin/delete/${id}`),
};

export default api;
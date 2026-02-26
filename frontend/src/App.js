import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Login from './pages/Login';
import Register from './pages/Register';
import VerifyOTP from './pages/VerifyOTP';
import Dashboard from './pages/Dashboard';
import Profile from './pages/Profile';
import Admin from './pages/Admin';
import CreateCompany from './pages/CreateCompany';
import PostJob from './pages/PostJob';
import JobBoard from './pages/JobBoard';
import Apply from './pages/Apply';
import Chat from './pages/Chat';
import Network from './pages/Network';
import ViewProfile from './pages/ViewProfile';
import './App.css';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Navigate to="/login" />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/verify-otp" element={<VerifyOTP />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/profile" element={<Profile />} />
        <Route path="/admin" element={<Admin />} />
        <Route path="/create-company" element={<CreateCompany />} />
        <Route path="/post-job" element={<PostJob />} />
        <Route path="/jobs" element={<JobBoard />} />
        <Route path="/apply/:jobId" element={<Apply />} />
        <Route path="/chat/:receiverId" element={<Chat />} />
        <Route path="/network" element={<Network />} />
        <Route path="/user-profile/:userId" element={<ViewProfile />} />
      </Routes>
    </Router>
  );
}

export default App;
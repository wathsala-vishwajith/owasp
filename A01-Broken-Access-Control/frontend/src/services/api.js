import axios from 'axios';

const API_BASE_URL = 'http://localhost:8080/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const userAPI = {
  // Get all users (vulnerable - should be admin only)
  getAllUsers: () => api.get('/users'),

  // Get user by ID (vulnerable - IDOR)
  getUserById: (id) => api.get(`/users/${id}`),

  // Get current user (simulated)
  getCurrentUser: (userId) => api.get(`/current-user?userId=${userId}`),

  // Update user salary (vulnerable - no authorization)
  updateSalary: (id, salary) => api.put(`/users/${id}/salary`, { salary }),

  // Update user role (vulnerable - privilege escalation)
  updateRole: (id, role) => api.put(`/users/${id}/role`, { role }),

  // Admin endpoints (vulnerable - no admin check)
  adminGetAllUsers: () => api.get('/admin/users'),

  // Delete user (vulnerable - no admin check)
  deleteUser: (id) => api.delete(`/admin/users/${id}`),

  // Create user
  createUser: (user) => api.post('/users', user),
};

export default api;

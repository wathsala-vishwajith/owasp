import React, { useState, useEffect } from 'react';
import { userAPI } from '../services/api';
import './UserList.css';

function UserList({ currentUserId, onSelectUser }) {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    loadUsers();
  }, []);

  const loadUsers = async () => {
    try {
      setLoading(true);
      // VULNERABLE: Any user can list all users
      const response = await userAPI.getAllUsers();
      setUsers(response.data);
      setError(null);
    } catch (err) {
      setError('Failed to load users');
      console.error('Error loading users:', err);
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <div className="user-list loading">Loading users...</div>;
  if (error) return <div className="user-list error">{error}</div>;

  return (
    <div className="user-list">
      <div className="user-list-header">
        <h2>All Users</h2>
        <span className="vulnerability-tag">No Authorization Check!</span>
      </div>

      <div className="user-cards">
        {users.map((user) => (
          <div
            key={user.id}
            className={`user-card ${user.id === currentUserId ? 'current' : ''}`}
            onClick={() => onSelectUser(user.id)}
          >
            <div className="user-card-header">
              <h3>{user.username}</h3>
              <span className={`role-badge ${user.role.toLowerCase()}`}>
                {user.role}
              </span>
            </div>
            <div className="user-card-body">
              <p><strong>ID:</strong> {user.id}</p>
              <p><strong>Email:</strong> {user.email}</p>
              {user.id === currentUserId && (
                <div className="current-user-indicator">← You</div>
              )}
            </div>
            <div className="user-card-footer">
              <button className="view-btn">View Profile →</button>
            </div>
          </div>
        ))}
      </div>

      <div className="vulnerability-info">
        <h4>🔓 Vulnerability Demonstrated:</h4>
        <ul>
          <li>Any authenticated user can list all users</li>
          <li>Should be restricted to administrators</li>
          <li>Exposes user enumeration</li>
        </ul>
      </div>
    </div>
  );
}

export default UserList;

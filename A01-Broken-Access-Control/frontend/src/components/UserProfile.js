import React, { useState, useEffect } from 'react';
import { userAPI } from '../services/api';
import './UserProfile.css';

function UserProfile({ userId, currentUser, onExploitSalary, onExploitRole, onDeleteUser }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [newSalary, setNewSalary] = useState('');
  const [newRole, setNewRole] = useState('ADMIN');

  useEffect(() => {
    loadUser();
  }, [userId]);

  const loadUser = async () => {
    try {
      setLoading(true);
      // VULNERABLE: Can view any user's profile by ID (IDOR)
      const response = await userAPI.getUserById(userId);
      setUser(response.data);
      setNewSalary(response.data.salary || '');
    } catch (error) {
      console.error('Error loading user:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <div className="user-profile loading">Loading...</div>;
  if (!user) return <div className="user-profile error">User not found</div>;

  const isOwnProfile = currentUser && user.id === currentUser.id;
  const isAdmin = currentUser && currentUser.role === 'ADMIN';

  return (
    <div className="user-profile">
      <div className="profile-header">
        <h2>User Profile: {user.username}</h2>
        {!isOwnProfile && (
          <span className="vulnerability-tag danger">
            IDOR Vulnerability - Viewing Another User's Data!
          </span>
        )}
      </div>

      <div className="profile-content">
        <div className="profile-section">
          <h3>Basic Information</h3>
          <div className="info-grid">
            <div className="info-item">
              <span className="label">ID:</span>
              <span className="value">{user.id}</span>
            </div>
            <div className="info-item">
              <span className="label">Username:</span>
              <span className="value">{user.username}</span>
            </div>
            <div className="info-item">
              <span className="label">Email:</span>
              <span className="value">{user.email}</span>
            </div>
            <div className="info-item">
              <span className="label">Role:</span>
              <span className={`value role-${user.role.toLowerCase()}`}>{user.role}</span>
            </div>
          </div>
        </div>

        <div className="profile-section sensitive">
          <h3>🔒 Sensitive Information (Should Be Protected!)</h3>
          <div className="info-grid">
            <div className="info-item">
              <span className="label">Phone:</span>
              <span className="value">{user.phoneNumber}</span>
            </div>
            <div className="info-item">
              <span className="label">Address:</span>
              <span className="value">{user.address}</span>
            </div>
            <div className="info-item">
              <span className="label">Salary:</span>
              <span className="value">${user.salary?.toLocaleString()}</span>
            </div>
            <div className="info-item">
              <span className="label">SSN:</span>
              <span className="value">{user.ssn}</span>
            </div>
          </div>
          {!isOwnProfile && (
            <div className="warning-box">
              ⚠️ You shouldn't be able to see this sensitive information!
            </div>
          )}
        </div>

        <div className="profile-section exploit">
          <h3>🎯 Exploit Actions</h3>

          <div className="exploit-action">
            <h4>Horizontal Privilege Escalation - Modify Salary</h4>
            <p>Anyone can modify anyone else's salary (no authorization check)</p>
            <div className="exploit-form">
              <input
                type="number"
                value={newSalary}
                onChange={(e) => setNewSalary(e.target.value)}
                placeholder="New salary"
              />
              <button
                onClick={() => onExploitSalary(user.id, parseFloat(newSalary))}
                className="exploit-btn"
              >
                Update Salary
              </button>
            </div>
          </div>

          <div className="exploit-action">
            <h4>Vertical Privilege Escalation - Change Role</h4>
            <p>Change user role to ADMIN (no permission check)</p>
            <div className="exploit-form">
              <select value={newRole} onChange={(e) => setNewRole(e.target.value)}>
                <option value="USER">USER</option>
                <option value="ADMIN">ADMIN</option>
              </select>
              <button
                onClick={() => onExploitRole(user.id, newRole)}
                className="exploit-btn danger"
              >
                Change Role
              </button>
            </div>
          </div>

          <div className="exploit-action">
            <h4>Missing Function Level Access Control</h4>
            <p>Delete user via admin endpoint (no admin check)</p>
            <button
              onClick={() => onDeleteUser(user.id)}
              className="exploit-btn danger"
              disabled={isOwnProfile}
            >
              Delete User
            </button>
            {isOwnProfile && <p className="note">Cannot delete yourself</p>}
          </div>
        </div>

        <div className="profile-section info">
          <h3>What's Wrong Here?</h3>
          <ul>
            <li><strong>IDOR:</strong> You can view any user's profile by changing the ID in the URL</li>
            <li><strong>No Authorization:</strong> No check to verify you should have access to this data</li>
            <li><strong>Sensitive Data Exposure:</strong> SSN, salary, and personal info visible to all</li>
            <li><strong>Missing Function Level Access Control:</strong> Admin operations available to all users</li>
            <li><strong>Horizontal Escalation:</strong> Users can modify other users' data</li>
            <li><strong>Vertical Escalation:</strong> Users can promote themselves to admin</li>
          </ul>
        </div>
      </div>
    </div>
  );
}

export default UserProfile;

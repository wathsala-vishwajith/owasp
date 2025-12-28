import React, { useState, useEffect } from 'react';
import { userAPI } from './services/api';
import UserList from './components/UserList';
import UserProfile from './components/UserProfile';
import './App.css';

function App() {
  const [currentUser, setCurrentUser] = useState(null);
  const [selectedUserId, setSelectedUserId] = useState(null);
  const [exploitLog, setExploitLog] = useState([]);

  useEffect(() => {
    // Simulate logged-in user (user ID 1 by default)
    loadCurrentUser(1);
  }, []);

  const loadCurrentUser = async (userId) => {
    try {
      const response = await userAPI.getCurrentUser(userId);
      setCurrentUser(response.data);
      addLog(`Logged in as: ${response.data.username} (${response.data.role})`);
    } catch (error) {
      console.error('Error loading current user:', error);
    }
  };

  const addLog = (message) => {
    const timestamp = new Date().toLocaleTimeString();
    setExploitLog(prev => [...prev, `[${timestamp}] ${message}`]);
  };

  const handleViewUser = (userId) => {
    setSelectedUserId(userId);
    if (currentUser && userId !== currentUser.id) {
      addLog(`EXPLOIT: Viewing user ${userId}'s profile (IDOR vulnerability)`);
    }
  };

  const handleExploitSalary = async (userId, newSalary) => {
    try {
      await userAPI.updateSalary(userId, newSalary);
      addLog(`EXPLOIT: Updated user ${userId}'s salary to $${newSalary} (No authorization check!)`);
      alert(`Successfully changed user ${userId}'s salary to $${newSalary}!`);
    } catch (error) {
      console.error('Error updating salary:', error);
    }
  };

  const handleExploitRole = async (userId, newRole) => {
    try {
      await userAPI.updateRole(userId, newRole);
      addLog(`EXPLOIT: Changed user ${userId}'s role to ${newRole} (Privilege escalation!)`);
      alert(`Successfully promoted user ${userId} to ${newRole}!`);
      // Reload current user if it's the current user's role
      if (currentUser && userId === currentUser.id) {
        loadCurrentUser(userId);
      }
    } catch (error) {
      console.error('Error updating role:', error);
    }
  };

  const handleDeleteUser = async (userId) => {
    if (window.confirm(`Delete user ${userId}? This demonstrates missing admin checks.`)) {
      try {
        await userAPI.deleteUser(userId);
        addLog(`EXPLOIT: Deleted user ${userId} via admin endpoint (No admin check!)`);
        alert(`User ${userId} deleted successfully!`);
      } catch (error) {
        console.error('Error deleting user:', error);
      }
    }
  };

  const handleViewAllUsers = async () => {
    try {
      const response = await userAPI.getAllUsers();
      addLog(`EXPLOIT: Accessed all users list (Should be admin-only!)`);
      console.log('All users:', response.data);
    } catch (error) {
      console.error('Error fetching all users:', error);
    }
  };

  const switchUser = (userId) => {
    loadCurrentUser(userId);
    setSelectedUserId(null);
  };

  return (
    <div className="App">
      <header className="app-header">
        <h1>🔓 OWASP A01: Broken Access Control Demo</h1>
        <div className="warning-banner">
          ⚠️ WARNING: This application is intentionally vulnerable for educational purposes!
        </div>
      </header>

      <div className="container">
        <div className="sidebar">
          <div className="current-user-panel">
            <h3>Current User</h3>
            {currentUser && (
              <div className="user-badge">
                <div className="user-name">{currentUser.username}</div>
                <div className="user-role">{currentUser.role}</div>
                <div className="user-id">ID: {currentUser.id}</div>
              </div>
            )}

            <div className="switch-user">
              <h4>Switch User (Simulation)</h4>
              <button onClick={() => switchUser(1)}>User 1 (john_doe)</button>
              <button onClick={() => switchUser(2)}>User 2 (jane_smith)</button>
              <button onClick={() => switchUser(3)}>User 3 (bob_admin)</button>
            </div>
          </div>

          <div className="exploit-panel">
            <h3>Exploit Actions</h3>
            <button onClick={handleViewAllUsers} className="exploit-btn">
              View All Users (No Auth!)
            </button>
            <button
              onClick={() => handleExploitRole(currentUser?.id, 'ADMIN')}
              className="exploit-btn danger"
              disabled={!currentUser}
            >
              Promote Self to Admin
            </button>
          </div>

          <div className="exploit-log">
            <h3>Exploit Log</h3>
            <div className="log-content">
              {exploitLog.map((log, index) => (
                <div key={index} className="log-entry">{log}</div>
              ))}
            </div>
          </div>
        </div>

        <div className="main-content">
          <UserList
            currentUserId={currentUser?.id}
            onSelectUser={handleViewUser}
          />

          {selectedUserId && (
            <UserProfile
              userId={selectedUserId}
              currentUser={currentUser}
              onExploitSalary={handleExploitSalary}
              onExploitRole={handleExploitRole}
              onDeleteUser={handleDeleteUser}
            />
          )}
        </div>
      </div>

      <footer className="app-footer">
        <p>This application demonstrates how broken access control can be exploited.</p>
        <p>Learn more about secure coding practices in the README.</p>
      </footer>
    </div>
  );
}

export default App;

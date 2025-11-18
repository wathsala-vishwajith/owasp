# Broken Access Control - Frontend

React application demonstrating OWASP A01: Broken Access Control vulnerabilities.

## Installation

```bash
npm install
```

## Running the Application

```bash
npm start
```

The application will open at `http://localhost:3000`

## Prerequisites

Make sure the backend is running at `http://localhost:8080`

## Features

This demo application demonstrates:

- **IDOR (Insecure Direct Object Reference)**: View any user's profile by selecting them
- **Missing Authorization**: All users can access the user list
- **Horizontal Privilege Escalation**: Modify other users' salaries
- **Vertical Privilege Escalation**: Promote yourself to admin
- **Missing Function Level Access Control**: Access admin operations without admin role

## How to Use

1. Start as User 1 (john_doe)
2. Browse the user list (notice you can see all users)
3. Click on different users to view their profiles
4. Try the exploit actions:
   - Update another user's salary
   - Change your role to ADMIN
   - Delete other users

## Exploit Log

The application includes an exploit log in the sidebar that tracks all security violations as you perform them.

## Learning Points

This UI clearly demonstrates:

- How easy it is to exploit broken access control
- The impact of missing authorization checks
- Why client-side security is insufficient
- The importance of server-side validation

## Note

This is intentionally vulnerable code for educational purposes. Never build production applications with these patterns!

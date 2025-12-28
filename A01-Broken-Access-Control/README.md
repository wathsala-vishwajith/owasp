# A01:2025 - Broken Access Control

## Overview

Broken Access Control is the #1 vulnerability in the OWASP Top 10 2025. It occurs when an application doesn't properly enforce authorization checks, allowing users to access resources or perform actions they shouldn't be able to.

## What is Broken Access Control?

Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of data, or performing business functions outside the user's limits.

### Common Vulnerabilities:

- Bypassing access control checks by modifying URLs, internal application states, or HTML pages
- Allowing the primary key to be changed to another user's record (IDOR - Insecure Direct Object Reference)
- Elevation of privilege (acting as a user without being logged in, or acting as an admin when logged in as a user)
- Missing access controls for POST, PUT, DELETE methods
- Accessing API with missing access controls for CRUD operations

## This Example

This demo shows a simple user management system where:

**VULNERABLE CODE** demonstrates:
- Users can view other users' profiles by manipulating the user ID in the URL
- Regular users can access admin-only endpoints
- No proper authorization checks before returning sensitive data
- Horizontal privilege escalation (viewing other users' data)
- Vertical privilege escalation (regular user accessing admin functions)

## Project Structure

```
A01-Broken-Access-Control/
├── backend/          # SpringBoot REST API (vulnerable)
└── frontend/         # React UI demonstrating the exploit
```

## Running the Example

### Backend (SpringBoot)

```bash
cd backend
./mvnw spring-boot:run
```

The API will run on `http://localhost:8080`

### Frontend (React)

```bash
cd frontend
npm install
npm start
```

The UI will run on `http://localhost:3000`

## How to Exploit

### 1. Horizontal Privilege Escalation (IDOR)

**Scenario**: View another user's private profile

1. Log in as a regular user (userId: 1)
2. Navigate to your profile: `/api/users/1`
3. Change the URL to `/api/users/2` to view another user's profile
4. **VULNERABILITY**: You can now see sensitive information (email, address, salary) of another user

```bash
# As user 1
curl http://localhost:8080/api/users/1

# Exploit: Access user 2's data
curl http://localhost:8080/api/users/2
# Returns sensitive data without checking if you're authorized!
```

### 2. Vertical Privilege Escalation

**Scenario**: Regular user accessing admin functions

1. Log in as a regular user
2. Try to access admin endpoint: `/api/admin/users`
3. **VULNERABILITY**: Regular users can access admin-only functions

```bash
# Regular user accessing admin endpoint
curl http://localhost:8080/api/admin/users
# Returns all users including sensitive admin data!

# Regular user deleting another user
curl -X DELETE http://localhost:8080/api/admin/users/2
# User deleted without proper authorization check!
```

### 3. Missing Function Level Access Control

**Scenario**: Accessing sensitive operations via API

```bash
# Change another user's salary (should be admin-only)
curl -X PUT http://localhost:8080/api/users/2/salary -H "Content-Type: application/json" -d '{"salary": 999999}'
# Salary updated without authorization!
```

## The Vulnerable Code

### Backend: UserController.java

```java
@RestController
@RequestMapping("/api")
public class UserController {

    // VULNERABLE: No authorization check - any logged-in user can view any profile
    @GetMapping("/users/{id}")
    public User getUserById(@PathVariable Long id) {
        return userService.findById(id); // Returns sensitive data!
    }

    // VULNERABLE: No admin role check - anyone can access
    @GetMapping("/admin/users")
    public List<User> getAllUsers() {
        return userService.findAll(); // Should require ADMIN role!
    }

    // VULNERABLE: No ownership check - users can update others' data
    @PutMapping("/users/{id}/salary")
    public User updateSalary(@PathVariable Long id, @RequestBody SalaryUpdate salary) {
        return userService.updateSalary(id, salary.getSalary());
    }
}
```

## How to Fix It

### 1. Implement Proper Authorization Checks

```java
@RestController
@RequestMapping("/api")
public class SecureUserController {

    @Autowired
    private AuthenticationFacade authenticationFacade;

    // SECURE: Check if user is accessing their own data or is admin
    @GetMapping("/users/{id}")
    public User getUserById(@PathVariable Long id) {
        User currentUser = authenticationFacade.getCurrentUser();

        // Only allow if accessing own data OR user is admin
        if (!currentUser.getId().equals(id) && !currentUser.isAdmin()) {
            throw new AccessDeniedException("Cannot access other users' data");
        }

        return userService.findById(id);
    }

    // SECURE: Require ADMIN role
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/users")
    public List<User> getAllUsers() {
        return userService.findAll();
    }

    // SECURE: Check ownership or admin role
    @PreAuthorize("hasRole('ADMIN') or @userSecurity.isOwner(#id)")
    @PutMapping("/users/{id}/salary")
    public User updateSalary(@PathVariable Long id, @RequestBody SalaryUpdate salary) {
        return userService.updateSalary(id, salary.getSalary());
    }
}
```

### 2. Use Spring Security Annotations

Enable method security in your configuration:

```java
@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {
    // Configuration
}
```

### 3. Implement Access Control Checks

```java
@Component("userSecurity")
public class UserSecurity {

    public boolean isOwner(Long userId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        UserDetails userDetails = (UserDetails) auth.getPrincipal();
        return userDetails.getUserId().equals(userId);
    }
}
```

## Best Practices

1. **Deny by Default**: Start with denying all access, then explicitly grant permissions
2. **Enforce on Server**: Never rely on client-side access control checks
3. **Use Consistent Mechanisms**: Apply access control using a centralized mechanism
4. **Principle of Least Privilege**: Give users minimum necessary permissions
5. **Log Access Control Failures**: Monitor and alert on repeated failures
6. **Disable Directory Listing**: Prevent unauthorized file access
7. **Test Authorization**: Include authorization tests in your test suite
8. **Use Framework Features**: Leverage Spring Security's built-in authorization

## Impact

- **Confidentiality**: Unauthorized access to sensitive data
- **Integrity**: Unauthorized modification of data
- **Availability**: Unauthorized deletion of resources
- **Compliance**: Violations of regulations (GDPR, HIPAA, etc.)

## Testing for This Vulnerability

1. Test with different user roles
2. Try to access resources by manipulating IDs
3. Attempt to access admin functions as regular user
4. Check if API enforces authorization on all CRUD operations
5. Verify that access control can't be bypassed by changing request methods

## References

- [OWASP A01:2025 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
- [Spring Security Authorization](https://docs.spring.io/spring-security/reference/servlet/authorization/index.html)

---

**Remember**: This is vulnerable code for educational purposes. Never use these patterns in production!

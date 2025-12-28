package com.owasp.bac.controller;

import com.owasp.bac.model.User;
import com.owasp.bac.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * VULNERABLE USER CONTROLLER
 *
 * This controller demonstrates BROKEN ACCESS CONTROL vulnerabilities:
 * 1. No authorization checks for viewing user profiles
 * 2. No role-based access control for admin operations
 * 3. Insecure Direct Object Reference (IDOR) vulnerabilities
 * 4. Missing function-level access control
 *
 * WARNING: This is intentionally vulnerable code for educational purposes!
 */
@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "http://localhost:3000") // Allow React app to connect
public class UserController {

    @Autowired
    private UserService userService;

    /**
     * VULNERABILITY 1: Insecure Direct Object Reference (IDOR)
     *
     * Any user can view any other user's profile by simply knowing their ID.
     * No check to verify if the requesting user should have access to this data.
     *
     * Exploit: GET /api/users/1, GET /api/users/2, etc.
     */
    @GetMapping("/users/{id}")
    public ResponseEntity<?> getUserById(@PathVariable Long id) {
        // VULNERABLE: No authorization check!
        // Should check if current user is accessing their own profile or is an admin
        return userService.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * VULNERABILITY 2: Missing Function Level Access Control
     *
     * Any user can list ALL users in the system.
     * This should be restricted to admins only.
     *
     * Exploit: GET /api/users
     */
    @GetMapping("/users")
    public List<User> getAllUsers() {
        // VULNERABLE: No admin role check!
        // Should require ADMIN role to list all users
        return userService.findAll();
    }

    /**
     * VULNERABILITY 3: Horizontal Privilege Escalation
     *
     * Any user can update any other user's salary.
     * No ownership or admin check.
     *
     * Exploit: PUT /api/users/2/salary with body {"salary": 999999}
     */
    @PutMapping("/users/{id}/salary")
    public ResponseEntity<User> updateSalary(
            @PathVariable Long id,
            @RequestBody Map<String, Double> body) {
        // VULNERABLE: No authorization check!
        // Should verify user is updating their own salary or is an admin
        Double newSalary = body.get("salary");
        User updated = userService.updateSalary(id, newSalary);
        return ResponseEntity.ok(updated);
    }

    /**
     * VULNERABILITY 4: Vertical Privilege Escalation
     *
     * Any user can promote themselves or others to admin.
     * No admin role verification.
     *
     * Exploit: PUT /api/users/1/role with body {"role": "ADMIN"}
     */
    @PutMapping("/users/{id}/role")
    public ResponseEntity<User> updateRole(
            @PathVariable Long id,
            @RequestBody Map<String, String> body) {
        // VULNERABLE: No authorization check!
        // Should require ADMIN role to change user roles
        String newRole = body.get("role");
        User updated = userService.updateRole(id, newRole);
        return ResponseEntity.ok(updated);
    }

    /**
     * VULNERABILITY 5: Admin Operations Without Authorization
     *
     * Delete user endpoint accessible to anyone.
     * Should require admin privileges.
     *
     * Exploit: DELETE /api/admin/users/2
     */
    @DeleteMapping("/admin/users/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        // VULNERABLE: No admin role check!
        // Should verify user has ADMIN role
        userService.deleteById(id);
        return ResponseEntity.ok().body(Map.of("message", "User deleted successfully"));
    }

    /**
     * VULNERABILITY 6: Admin Dashboard Without Authorization
     *
     * Admin dashboard accessible to all users.
     *
     * Exploit: GET /api/admin/users
     */
    @GetMapping("/admin/users")
    public ResponseEntity<List<User>> adminGetAllUsers() {
        // VULNERABLE: No admin role check!
        // This endpoint should require ADMIN role
        return ResponseEntity.ok(userService.findAll());
    }

    /**
     * Endpoint to simulate "current user" - for demo purposes
     * In real app, this would come from authentication context
     */
    @GetMapping("/current-user")
    public ResponseEntity<User> getCurrentUser(@RequestParam(required = false) Long userId) {
        // For demo: allow specifying which user is "logged in"
        if (userId != null) {
            return userService.findById(userId)
                    .map(ResponseEntity::ok)
                    .orElse(ResponseEntity.notFound().build());
        }
        // Default to user 1
        return userService.findById(1L)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Create a new user - also vulnerable (no validation)
     */
    @PostMapping("/users")
    public ResponseEntity<User> createUser(@RequestBody User user) {
        // VULNERABLE: Anyone can create users with any role
        // Should validate role assignment
        User created = userService.save(user);
        return ResponseEntity.ok(created);
    }
}

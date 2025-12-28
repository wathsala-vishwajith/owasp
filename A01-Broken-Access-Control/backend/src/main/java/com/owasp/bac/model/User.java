package com.owasp.bac.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * User entity with sensitive information
 */
@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;

    private String email;

    private String password; // Storing plain text for simplicity (another vulnerability!)

    private String role; // "USER" or "ADMIN"

    // Sensitive information that should be protected
    private String phoneNumber;

    private String address;

    private Double salary;

    private String ssn; // Social Security Number - highly sensitive!

    // Constructor without sensitive data
    public User(String username, String email, String role) {
        this.username = username;
        this.email = email;
        this.role = role;
    }

    public boolean isAdmin() {
        return "ADMIN".equalsIgnoreCase(this.role);
    }
}

package com.owasp.secconfig.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * VULNERABLE CONTROLLER demonstrating Security Misconfiguration issues
 */
@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*") // VULNERABLE: Allows all origins
public class VulnerableController {

    // VULNERABLE: Secrets in code/configuration
    @Value("${api.key}")
    private String apiKey;

    @Value("${api.password}")
    private String apiPassword;

    @Value("${jwt.secret}")
    private String jwtSecret;

    /**
     * VULNERABILITY: Exposes sensitive configuration
     */
    @GetMapping("/config")
    public ResponseEntity<Map<String, String>> getConfig() {
        Map<String, String> config = new HashMap<>();
        config.put("apiKey", apiKey);  // NEVER expose secrets!
        config.put("apiPassword", apiPassword);
        config.put("jwtSecret", jwtSecret);
        config.put("environment", "production"); // Lying about environment
        return ResponseEntity.ok(config);
    }

    /**
     * VULNERABILITY: Throws detailed exceptions with stack traces
     */
    @GetMapping("/trigger-error")
    public ResponseEntity<?> triggerError() {
        try {
            // Simulate an error
            int result = 10 / 0;
        } catch (Exception e) {
            // VULNERABLE: Exposing full stack trace and system details
            Map<String, Object> errorDetails = new HashMap<>();
            errorDetails.put("error", e.getClass().getName());
            errorDetails.put("message", e.getMessage());
            errorDetails.put("stackTrace", e.getStackTrace());
            errorDetails.put("javaVersion", System.getProperty("java.version"));
            errorDetails.put("osName", System.getProperty("os.name"));
            errorDetails.put("osVersion", System.getProperty("os.version"));
            errorDetails.put("userDir", System.getProperty("user.dir"));

            return ResponseEntity.status(500).body(errorDetails);
        }
        return ResponseEntity.ok("OK");
    }

    /**
     * VULNERABILITY: SQL error with detailed message
     */
    @GetMapping("/sql-error")
    public ResponseEntity<?> sqlError() {
        Map<String, Object> error = new HashMap<>();
        error.put("error", "SQL Exception");
        error.put("message", "Table 'database.users' doesn't exist");
        error.put("sqlState", "42S02");
        error.put("query", "SELECT * FROM users WHERE id = 1");  // Exposing query
        error.put("database", "misconfigdb");
        error.put("driver", "H2 JDBC Driver");
        return ResponseEntity.status(500).body(error);
    }

    /**
     * VULNERABILITY: Debug endpoint that should not be in production
     */
    @GetMapping("/debug/system-info")
    public ResponseEntity<Map<String, String>> getSystemInfo() {
        Map<String, String> info = new HashMap<>();
        info.put("javaVersion", System.getProperty("java.version"));
        info.put("javaHome", System.getProperty("java.home"));
        info.put("osName", System.getProperty("os.name"));
        info.put("osArch", System.getProperty("os.arch"));
        info.put("osVersion", System.getProperty("os.version"));
        info.put("userName", System.getProperty("user.name"));
        info.put("userHome", System.getProperty("user.home"));
        info.put("userDir", System.getProperty("user.dir"));
        info.put("tmpDir", System.getProperty("java.io.tmpdir"));

        // VULNERABLE: Exposing system information
        return ResponseEntity.ok(info);
    }

    /**
     * VULNERABILITY: Login with default credentials
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> credentials) {
        String username = credentials.get("username");
        String password = credentials.get("password");

        // VULNERABLE: Default credentials hardcoded
        if ("admin".equals(username) && "admin123".equals(password)) {
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "Login successful");
            response.put("token", jwtSecret); // VULNERABLE: Exposing JWT secret
            response.put("role", "ADMIN");
            return ResponseEntity.ok(response);
        }

        // VULNERABLE: Detailed error message helps attackers
        Map<String, Object> response = new HashMap<>();
        response.put("success", false);
        if (!"admin".equals(username)) {
            response.put("error", "Username 'admin' not found");  // User enumeration!
        } else {
            response.put("error", "Invalid password for user 'admin'");  // Password hint!
        }
        return ResponseEntity.status(401).body(response);
    }

    /**
     * Test endpoint
     */
    @GetMapping("/test")
    public ResponseEntity<Map<String, String>> test() {
        // Missing security headers - check with curl -I
        return ResponseEntity.ok(Map.of(
            "status", "OK",
            "message", "Check the response headers - security headers are missing!"
        ));
    }
}

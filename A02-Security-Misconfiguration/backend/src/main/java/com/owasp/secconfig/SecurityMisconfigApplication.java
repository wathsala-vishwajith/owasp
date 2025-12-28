package com.owasp.secconfig;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * WARNING: This application contains intentionally VULNERABLE code
 * demonstrating OWASP A02: Security Misconfiguration
 *
 * DO NOT use this code in production!
 */
@SpringBootApplication
public class SecurityMisconfigApplication {

    public static void main(String[] args) {
        System.out.println("=".repeat(80));
        System.out.println("WARNING: Starting VULNERABLE application for educational purposes");
        System.out.println("OWASP A02:2025 - Security Misconfiguration Demo");
        System.out.println("Features exposed:");
        System.out.println("  - All Actuator endpoints at /actuator");
        System.out.println("  - H2 Console at /h2-console");
        System.out.println("  - Verbose error messages with stack traces");
        System.out.println("  - Debug mode enabled");
        System.out.println("  - Default credentials (admin/admin123)");
        System.out.println("DO NOT use this code in production!");
        System.out.println("=".repeat(80));

        SpringApplication.run(SecurityMisconfigApplication.class, args);
    }
}

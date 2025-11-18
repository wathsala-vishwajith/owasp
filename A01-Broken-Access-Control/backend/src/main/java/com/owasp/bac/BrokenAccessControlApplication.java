package com.owasp.bac;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * WARNING: This application contains intentionally VULNERABLE code
 * for educational purposes demonstrating OWASP A01: Broken Access Control
 *
 * DO NOT use this code in production!
 */
@SpringBootApplication
public class BrokenAccessControlApplication {

    public static void main(String[] args) {
        System.out.println("=".repeat(80));
        System.out.println("WARNING: Starting VULNERABLE application for educational purposes");
        System.out.println("OWASP A01:2025 - Broken Access Control Demo");
        System.out.println("DO NOT use this code in production!");
        System.out.println("=".repeat(80));

        SpringApplication.run(BrokenAccessControlApplication.class, args);
    }
}

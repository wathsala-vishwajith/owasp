# A02:2025 - Security Misconfiguration

## Overview

Security Misconfiguration vulnerabilities occur when security settings are defined, implemented, and maintained incorrectly. This can happen at any level of an application stack.

## What is Security Misconfiguration?

Security misconfiguration is the most commonly seen issue. This is commonly a result of:

- Insecure default configurations
- Incomplete or ad hoc configurations
- Open cloud storage
- Misconfigured HTTP headers
- Verbose error messages containing sensitive information
- Missing security patches
- Unnecessary features enabled (debug, admin interfaces, etc.)

### Common Vulnerabilities:

- Default accounts with unchanged passwords
- Stack traces exposed to users
- Directory listing enabled
- Unnecessary services running
- Debug mode enabled in production
- Verbose error messages revealing system details
- Missing security headers (CSP, HSTS, X-Frame-Options, etc.)
- Default sample applications left installed

## This Example

This demo demonstrates a web application with multiple security misconfigurations:

**VULNERABLE CODE** shows:
- Debug endpoints exposed in production
- Default admin credentials (admin/admin123)
- Detailed error messages with stack traces
- Missing security headers
- Actuator endpoints exposed without authentication
- H2 console accessible in production
- CORS misconfigured (wildcard allowed)
- Unnecessary features enabled

## Running the Example

### Backend (SpringBoot)

```bash
cd backend
./mvnw spring-boot:run
```

API runs on `http://localhost:8081`

### Frontend (React)

```bash
cd frontend
npm install
npm start
```

UI runs on `http://localhost:3000`

## How to Exploit

### 1. Access Debug Endpoints

```bash
# Access actuator endpoints without authentication
curl http://localhost:8081/actuator
curl http://localhost:8081/actuator/env
curl http://localhost:8081/actuator/health
curl http://localhost:8081/actuator/metrics

# View application configuration
curl http://localhost:8081/actuator/configprops
```

### 2. Use Default Credentials

Try logging in with common default credentials:
- Username: `admin`
- Password: `admin123`

### 3. Trigger Verbose Error Messages

```bash
# Cause an error to see stack trace
curl http://localhost:8081/api/trigger-error

# SQL error with details
curl http://localhost:8081/api/users/invalid
```

### 4. Access H2 Console

Visit `http://localhost:8081/h2-console` - No authentication required!

### 5. View Environment Variables

```bash
# Exposed environment details
curl http://localhost:8081/actuator/env
```

### 6. Check Missing Security Headers

```bash
# View response headers
curl -I http://localhost:8081/api/test

# Missing headers:
# - X-Content-Type-Options
# - X-Frame-Options
# - Content-Security-Policy
# - Strict-Transport-Security
```

## The Vulnerable Code

### application.properties

```properties
# VULNERABLE: Debug mode enabled
debug=true
spring.devtools.restart.enabled=true

# VULNERABLE: Actuator endpoints exposed without security
management.endpoints.web.exposure.include=*
management.endpoint.health.show-details=always

# VULNERABLE: H2 Console accessible
spring.h2.console.enabled=true

# VULNERABLE: Detailed error messages
server.error.include-message=always
server.error.include-binding-errors=always
server.error.include-stacktrace=always
server.error.include-exception=true

# VULNERABLE: CORS allows all origins
cors.allowed-origins=*
```

### ErrorController (Verbose Errors)

```java
@RestController
public class ErrorController {

    // VULNERABLE: Exposes full stack trace to client
    @GetMapping("/api/trigger-error")
    public ResponseEntity<?> triggerError() {
        try {
            throw new RuntimeException("Something went wrong!");
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of(
                "error", e.getMessage(),
                "stackTrace", e.getStackTrace(),  // NEVER expose this!
                "cause", e.getCause()
            ));
        }
    }
}
```

## How to Fix It

### 1. Secure application.properties

```properties
# SECURE: Disable debug in production
debug=false
spring.devtools.restart.enabled=false

# SECURE: Limit actuator exposure and add security
management.endpoints.web.exposure.include=health,info
management.endpoint.health.show-details=when-authorized

# SECURE: Disable H2 console in production
spring.h2.console.enabled=false

# SECURE: Minimal error details
server.error.include-message=never
server.error.include-binding-errors=never
server.error.include-stacktrace=never
server.error.include-exception=false

# SECURE: Specific CORS origins
cors.allowed-origins=https://yourdomain.com
```

### 2. Add Security Headers

```java
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .headers(headers -> headers
                .contentSecurityPolicy(csp ->
                    csp.policyDirectives("default-src 'self'"))
                .frameOptions(frame -> frame.deny())
                .xssProtection(xss -> xss.block(true))
                .contentTypeOptions(Customizer.withDefaults())
                .httpStrictTransportSecurity(hsts -> hsts
                    .maxAgeInSeconds(31536000)
                    .includeSubDomains(true))
            );
        return http.build();
    }
}
```

### 3. Secure Actuator Endpoints

```properties
management.endpoints.web.exposure.include=health,info
management.endpoint.health.show-details=when-authorized
management.security.enabled=true
```

```java
@Configuration
public class ActuatorSecurity {
    @Bean
    public SecurityFilterChain actuatorSecurity(HttpSecurity http) throws Exception {
        http
            .requestMatcher(EndpointRequest.toAnyEndpoint())
            .authorizeHttpRequests(auth -> auth
                .anyRequest().hasRole("ADMIN")
            );
        return http.build();
    }
}
```

### 4. Handle Errors Securely

```java
@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleException(Exception e) {
        // Log the full error server-side
        log.error("Error occurred", e);

        // Return generic message to client
        return ResponseEntity.status(500).body(Map.of(
            "error", "An internal error occurred",
            "timestamp", Instant.now()
            // NO stack trace, NO detailed message!
        ));
    }
}
```

### 5. Remove Default Credentials

- Use strong, unique passwords
- Implement password policies
- Use environment variables for credentials
- Never commit credentials to version control

## Best Practices

1. **Use Security Hardening Guides**: Follow CIS benchmarks
2. **Remove Unnecessary Features**: Disable unused services
3. **Update Regularly**: Keep all components patched
4. **Automate Configuration**: Use infrastructure as code
5. **Review Default Settings**: Never use defaults in production
6. **Implement Security Headers**: Use all recommended headers
7. **Minimize Error Information**: Generic errors for users, detailed logs server-side
8. **Secure Admin Interfaces**: Separate network, strong authentication
9. **Regular Security Audits**: Automated scanning and manual review
10. **Environment Separation**: Different configs for dev/staging/prod

## Impact

- Information disclosure leading to targeted attacks
- Unauthorized access through default credentials
- Full system compromise through exposed debug interfaces
- Data theft through misconfigured cloud storage
- Cross-site scripting through missing headers
- Clickjacking attacks

## Testing

1. Run security scanners (OWASP ZAP, Nessus)
2. Check for default credentials
3. Review HTTP headers
4. Test error handling
5. Verify actuator endpoints are secured
6. Check for unnecessary services
7. Review CORS configuration

## References

- [OWASP A02:2025 - Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [Spring Boot Security Best Practices](https://spring.io/guides/topicals/spring-security-architecture/)
- [Security Headers](https://securityheaders.com/)

---

**Remember**: Every misconfiguration is a potential entry point for attackers!

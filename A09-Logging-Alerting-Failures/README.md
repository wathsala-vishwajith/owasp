# A09:2025 - Logging & Alerting Failures

## Overview

Security logging and monitoring failures can allow attackers to persist in systems, pivot to more systems, and tamper, extract, or destroy data. Without logging and alerting, breaches cannot be detected.

## Common Failures

- Auditable events not logged (logins, failed logins, high-value transactions)
- Warnings and errors generate inadequate or unclear log messages
- Logs not monitored for suspicious activity
- Logs only stored locally
- No alerting thresholds or response escalation
- Logs exposed to users or attackers
- Application unable to detect, escalate, or alert for active attacks
- Insufficient log retention

## Vulnerable Examples

### 1. Missing Security Event Logging

```java
@RestController
public class VulnerableAuthController {

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        User user = userService.authenticate(
            request.getUsername(),
            request.getPassword()
        );

        if (user != null) {
            // VULNERABLE: No logging of successful login
            return ResponseEntity.ok(generateToken(user));
        }

        // VULNERABLE: No logging of failed login attempt
        return ResponseEntity.status(401).body("Invalid credentials");
    }

    @DeleteMapping("/user/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        // VULNERABLE: No audit of sensitive operation
        userService.delete(id);
        return ResponseEntity.ok("Deleted");
    }
}
```

### 2. Insufficient Log Detail

```java
@Service
public class VulnerableTransactionService {

    @Transactional
    public void transfer(Long fromAccount, Long toAccount, BigDecimal amount) {
        // VULNERABLE: Minimal logging
        log.info("Transfer initiated");

        // Missing: who initiated, source account, destination, amount, timestamp
        accountService.debit(fromAccount, amount);
        accountService.credit(toAccount, amount);

        // Missing: success/failure logging
    }
}
```

### 3. Logging Sensitive Data

```java
@Service
public class InsecureLoggingService {

    public void processPayment(PaymentRequest payment) {
        // VULNERABLE: Logging sensitive data!
        log.info("Processing payment: " + payment);
        // Logs credit card number, CVV, passwords in plain text!

        // VULNERABLE: Stack traces with sensitive data
        try {
            paymentGateway.charge(payment);
        } catch (Exception e) {
            log.error("Payment failed", e);  // May contain sensitive data
        }
    }
}
```

### 4. No Log Monitoring

```java
// VULNERABLE: Logs written but never monitored
@Scheduled(fixedRate = 60000)
public void checkLogs() {
    // No implementation!
    // Logs just accumulate, nobody reviews them
}
```

## Secure Implementation

### 1. Comprehensive Security Logging

```java
@Service
public class SecureAuditService {

    @Autowired
    private AuditRepository auditRepository;

    public void logAuthenticationSuccess(User user, HttpServletRequest request) {
        AuditEvent event = AuditEvent.builder()
            .eventType("AUTHENTICATION_SUCCESS")
            .userId(user.getId())
            .username(user.getUsername())
            .ipAddress(getClientIP(request))
            .userAgent(request.getHeader("User-Agent"))
            .timestamp(Instant.now())
            .severity(Severity.INFO)
            .build();

        auditRepository.save(event);
        log.info("User {} logged in successfully from {}", user.getUsername(), getClientIP(request));
    }

    public void logAuthenticationFailure(String username, HttpServletRequest request) {
        AuditEvent event = AuditEvent.builder()
            .eventType("AUTHENTICATION_FAILURE")
            .username(username)
            .ipAddress(getClientIP(request))
            .userAgent(request.getHeader("User-Agent"))
            .timestamp(Instant.now())
            .severity(Severity.WARNING)
            .build();

        auditRepository.save(event);
        log.warn("Failed login attempt for user {} from {}", username, getClientIP(request));

        // Check for brute force attack
        checkForBruteForce(username, getClientIP(request));
    }

    public void logSensitiveOperation(String operation, User user, Map<String, Object> details) {
        // Sanitize details - remove sensitive data
        Map<String, Object> sanitized = sanitizeLogData(details);

        AuditEvent event = AuditEvent.builder()
            .eventType(operation)
            .userId(user.getId())
            .username(user.getUsername())
            .details(sanitized)
            .timestamp(Instant.now())
            .severity(Severity.HIGH)
            .build();

        auditRepository.save(event);
        log.warn("Sensitive operation {} performed by user {}", operation, user.getUsername());

        // Alert on sensitive operations
        if (isHighRiskOperation(operation)) {
            alertService.sendSecurityAlert(event);
        }
    }

    private Map<String, Object> sanitizeLogData(Map<String, Object> data) {
        Map<String, Object> sanitized = new HashMap<>(data);

        // Remove sensitive fields
        List<String> sensitiveFields = Arrays.asList(
            "password", "creditCard", "ssn", "cvv", "pin"
        );

        for (String field : sensitiveFields) {
            if (sanitized.containsKey(field)) {
                sanitized.put(field, "***REDACTED***");
            }
        }

        return sanitized;
    }
}
```

### 2. Structured Logging

```java
@Configuration
public class LoggingConfig {

    @Bean
    public Logger.Factory structuredLoggingFactory() {
        return new StructuredLoggingFactory();
    }
}

@Service
public class TransactionService {

    @Autowired
    private StructuredLogger logger;

    @Transactional
    public TransferResult transfer(TransferRequest request, User user) {
        // Structured logging with context
        Map<String, Object> context = Map.of(
            "fromAccount", request.getFromAccount(),
            "toAccount", request.getToAccount(),
            "amount", request.getAmount(),
            "currency", request.getCurrency(),
            "userId", user.getId(),
            "username", user.getUsername()
        );

        logger.info("Transfer initiated", context);

        try {
            validateTransfer(request);
            TransferResult result = executeTransfer(request);

            logger.info("Transfer completed successfully", Map.of(
                "transactionId", result.getTransactionId(),
                "status", "SUCCESS"
            ));

            return result;

        } catch (InsufficientFundsException e) {
            logger.warn("Transfer failed - insufficient funds", context);
            throw e;

        } catch (Exception e) {
            logger.error("Transfer failed with error", context, e);
            throw e;
        }
    }
}
```

### 3. Log Monitoring and Alerting

```java
@Service
public class SecurityMonitoringService {

    @Scheduled(fixedRate = 60000) // Every minute
    public void monitorSecurityEvents() {
        Instant since = Instant.now().minus(Duration.ofMinutes(5));

        // Check for multiple failed logins
        checkFailedLogins(since);

        // Check for unusual access patterns
        checkAccessPatterns(since);

        // Check for privilege escalation attempts
        checkPrivilegeEscalation(since);

        // Check for suspicious API usage
        checkAPIAbuse(since);
    }

    private void checkFailedLogins(Instant since) {
        // Group by username and IP
        Map<String, Long> failedAttempts = auditRepository
            .countFailedLoginsByUsername(since);

        failedAttempts.forEach((username, count) -> {
            if (count >= 5) {
                SecurityAlert alert = SecurityAlert.builder()
                    .type("BRUTE_FORCE_ATTEMPT")
                    .severity(Severity.HIGH)
                    .message("Multiple failed login attempts for user: " + username)
                    .count(count)
                    .build();

                alertService.sendAlert(alert);

                // Auto-block if threshold exceeded
                if (count >= 10) {
                    securityService.blockUser(username);
                }
            }
        });
    }

    private void checkAccessPatterns(Instant since) {
        // Detect unusual access patterns
        List<AuditEvent> events = auditRepository.findByTimestampAfter(since);

        // Check for rapid account enumeration
        Map<String, Set<Long>> userAccess = new HashMap<>();
        for (AuditEvent event : events) {
            if (event.getEventType().equals("USER_PROFILE_ACCESS")) {
                userAccess
                    .computeIfAbsent(event.getUsername(), k -> new HashSet<>())
                    .add(event.getTargetUserId());
            }
        }

        userAccess.forEach((username, accessedUsers) -> {
            if (accessedUsers.size() > 50) {
                SecurityAlert alert = SecurityAlert.builder()
                    .type("SUSPICIOUS_ACCESS_PATTERN")
                    .severity(Severity.HIGH)
                    .message("User " + username + " accessed " + accessedUsers.size() + " profiles in 5 minutes")
                    .build();

                alertService.sendAlert(alert);
            }
        });
    }
}
```

### 4. Centralized Log Management

```java
@Configuration
public class CentralizedLoggingConfig {

    @Bean
    public LogstashTcpSocketAppender logstashAppender() {
        // Send logs to centralized system (ELK, Splunk, etc.)
        LogstashTcpSocketAppender appender = new LogstashTcpSocketAppender();
        appender.setHost("logstash.example.com");
        appender.setPort(5000);
        appender.setEncoder(logstashEncoder());
        return appender;
    }

    @Bean
    public CloudWatchAppender cloudWatchAppender() {
        // Send to AWS CloudWatch
        CloudWatchAppender appender = new CloudWatchAppender();
        appender.setLogGroupName("/aws/app/security");
        appender.setLogStreamName("security-events");
        return appender;
    }
}
```

### 5. Secure Log Storage

```java
@Service
public class SecureLogService {

    // Logs stored with integrity protection
    public void writeAuditLog(AuditEvent event) {
        // Calculate checksum
        String checksum = calculateChecksum(event);
        event.setChecksum(checksum);

        // Sign log entry
        String signature = signatureService.sign(event.toString());
        event.setSignature(signature);

        // Encrypt sensitive details
        if (event.containsSensitiveData()) {
            event.setDetails(encryptionService.encrypt(event.getDetails()));
        }

        auditRepository.save(event);

        // Also send to immutable storage (WORM)
        archiveService.archiveLog(event);
    }

    // Verify log integrity
    public boolean verifyLogIntegrity(AuditEvent event) {
        // Verify checksum
        String expectedChecksum = calculateChecksum(event);
        if (!expectedChecksum.equals(event.getChecksum())) {
            alertService.sendAlert("Log tampering detected!");
            return false;
        }

        // Verify signature
        return signatureService.verify(event.toString(), event.getSignature());
    }
}
```

## What to Log

### Security Events
- Authentication (success/failure)
- Authorization failures
- Session management events
- Input validation failures
- Sensitive operations (delete, role change, etc.)
- Security configuration changes

### User Activity
- Login/logout
- Account changes
- Permission changes
- Access to sensitive data
- Failed access attempts

### Application Events
- Startup/shutdown
- Configuration changes
- Critical errors
- Resource exhaustion
- Service degradation

## Log Format Best Practices

```java
// Good structured log
{
  "timestamp": "2025-01-15T10:30:45.123Z",
  "level": "WARN",
  "event": "AUTHENTICATION_FAILURE",
  "userId": null,
  "username": "admin",
  "ipAddress": "192.168.1.100",
  "userAgent": "Mozilla/5.0...",
  "message": "Failed login attempt",
  "context": {
    "attemptNumber": 3,
    "reason": "invalid_password"
  }
}
```

## Alerting Rules

```java
@Configuration
public class AlertingRules {

    // Immediate alerts
    - 5+ failed logins in 5 minutes
    - Admin privilege escalation
    - Access to admin panel from new IP
    - Sensitive data access outside business hours
    - SQL injection attempt detected
    - Unusual data exfiltration patterns

    // Aggregated alerts (daily/weekly)
    - Summary of security events
    - Trend analysis
    - Anomaly detection results
}
```

## Log Retention

- **Security logs**: 1-2 years (compliance requirements)
- **Audit logs**: 7 years (regulatory requirements)
- **Application logs**: 90 days
- **Debug logs**: 7-30 days

## Tools

- **Log Management**: ELK Stack, Splunk, Graylog
- **SIEM**: Splunk, IBM QRadar, Azure Sentinel
- **Cloud Logging**: AWS CloudWatch, Google Cloud Logging
- **Alerting**: PagerDuty, Opsgenie, Slack

## Best Practices

1. **Log All Security Events**: Authentication, authorization, sensitive operations
2. **Use Structured Logging**: JSON format for easy parsing
3. **Sanitize Log Data**: Never log passwords, credit cards, PII
4. **Centralize Logs**: Send to centralized system
5. **Monitor Actively**: Real-time alerting on suspicious activity
6. **Protect Logs**: Encrypt, sign, immutable storage
7. **Retain Appropriately**: Meet compliance requirements
8. **Test Monitoring**: Regularly verify alerts work
9. **Include Context**: Who, what, when, where, why
10. **Correlate Events**: Connect related security events

## Testing

```bash
# Generate security events
# Verify they're logged correctly
# Verify alerts trigger
# Test log integrity
# Test log retention
```

## References

- [OWASP A09:2025 - Logging & Monitoring Failures](https://owasp.org/Top10/)
- [Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [Application Logging Vocabulary Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html)

---

**To Implement**: Build examples with proper security logging, monitoring, and alerting using SpringBoot and React.

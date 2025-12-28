# A07:2025 - Authentication Failures

## Overview

Authentication failures occur when applications fail to properly verify user identity, manage sessions, or protect credentials. This was previously known as "Broken Authentication".

## Common Vulnerabilities

- Weak password policies
- Credential stuffing attacks possible
- No brute force protection
- Session fixation
- Exposing session IDs in URLs
- Not invalidating sessions after logout
- Weak session IDs
- Missing or improper MFA
- Default credentials
- Insecure password recovery

## Vulnerable Examples

### 1. Weak Password Validation

```java
@Service
public class WeakPasswordService {
    // VULNERABLE: Weak password requirements
    public boolean isValidPassword(String password) {
        return password.length() >= 6;  // Too weak!
    }
}
```

### 2. No Brute Force Protection

```java
@RestController
public class VulnerableLoginController {

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        // VULNERABLE: No rate limiting, no account lockout
        User user = userService.findByUsername(request.getUsername());

        if (user != null && user.getPassword().equals(request.getPassword())) {
            String sessionId = UUID.randomUUID().toString();
            return ResponseEntity.ok(Map.of("sessionId", sessionId));
        }

        return ResponseEntity.status(401).body("Invalid credentials");
    }
}
```

### 3. Session Fixation

```java
@PostMapping("/login")
public ResponseEntity<?> login(HttpServletRequest request, @RequestBody LoginRequest loginRequest) {
    // VULNERABLE: Reusing existing session ID after authentication
    HttpSession session = request.getSession();  // Reuses session!

    User user = authenticate(loginRequest);
    session.setAttribute("user", user);

    return ResponseEntity.ok("Logged in");
}
```

### 4. Insecure Password Recovery

```java
@PostMapping("/reset-password")
public ResponseEntity<?> resetPassword(@RequestParam String username) {
    User user = userService.findByUsername(username);

    if (user != null) {
        // VULNERABLE: Predictable reset token
        String token = String.valueOf(System.currentTimeMillis());

        // VULNERABLE: Token never expires
        user.setResetToken(token);

        // VULNERABLE: Reveals if user exists
        return ResponseEntity.ok("Reset email sent to " + user.getEmail());
    }

    return ResponseEntity.badRequest().body("User not found");
}
```

## Secure Implementation

### 1. Strong Password Policy

```java
@Service
public class SecurePasswordService {

    private static final int MIN_LENGTH = 12;
    private static final Pattern UPPERCASE = Pattern.compile("[A-Z]");
    private static final Pattern LOWERCASE = Pattern.compile("[a-z]");
    private static final Pattern DIGIT = Pattern.compile("[0-9]");
    private static final Pattern SPECIAL = Pattern.compile("[!@#$%^&*(),.?\":{}|<>]");

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(12);

    public ValidationResult validatePassword(String password) {
        List<String> errors = new ArrayList<>();

        if (password.length() < MIN_LENGTH) {
            errors.add("Password must be at least " + MIN_LENGTH + " characters");
        }

        if (!UPPERCASE.matcher(password).find()) {
            errors.add("Password must contain uppercase letter");
        }

        if (!LOWERCASE.matcher(password).find()) {
            errors.add("Password must contain lowercase letter");
        }

        if (!DIGIT.matcher(password).find()) {
            errors.add("Password must contain digit");
        }

        if (!SPECIAL.matcher(password).find()) {
            errors.add("Password must contain special character");
        }

        // Check against common passwords
        if (commonPasswordService.isCommon(password)) {
            errors.add("Password is too common");
        }

        // Check against breached passwords (Have I Been Pwned API)
        if (breachedPasswordService.isBreached(password)) {
            errors.add("Password found in data breach");
        }

        return errors.isEmpty() ? ValidationResult.valid() : ValidationResult.invalid(errors);
    }

    public String hashPassword(String password) {
        return passwordEncoder.encode(password);
    }

    public boolean verifyPassword(String rawPassword, String hashedPassword) {
        return passwordEncoder.matches(rawPassword, hashedPassword);
    }
}
```

### 2. Brute Force Protection

```java
@Service
public class SecureAuthenticationService {

    private static final int MAX_ATTEMPTS = 5;
    private static final Duration LOCKOUT_DURATION = Duration.ofMinutes(30);

    @Transactional
    public AuthResult authenticate(String username, String password, String ipAddress) {

        // Check if IP is rate limited
        if (rateLimiterService.isBlocked(ipAddress)) {
            auditService.logBlockedAttempt(username, ipAddress);
            return AuthResult.rateLimited();
        }

        // Check if account is locked
        User user = userRepository.findByUsername(username);
        if (user != null && user.isLocked()) {
            if (user.getLockoutExpiry().isAfter(Instant.now())) {
                return AuthResult.accountLocked();
            } else {
                // Unlock account
                user.setLocked(false);
                user.setFailedAttempts(0);
            }
        }

        // Verify credentials
        if (user == null || !passwordEncoder.matches(password, user.getPasswordHash())) {
            handleFailedAttempt(user, username, ipAddress);
            return AuthResult.invalidCredentials();
        }

        // Reset failed attempts on successful login
        user.setFailedAttempts(0);
        user.setLastLogin(Instant.now());
        userRepository.save(user);

        auditService.logSuccessfulLogin(user, ipAddress);

        return AuthResult.success(user);
    }

    private void handleFailedAttempt(User user, String username, String ipAddress) {
        if (user != null) {
            user.setFailedAttempts(user.getFailedAttempts() + 1);

            if (user.getFailedAttempts() >= MAX_ATTEMPTS) {
                user.setLocked(true);
                user.setLockoutExpiry(Instant.now().plus(LOCKOUT_DURATION));
                alertService.sendAccountLockoutNotification(user);
            }

            userRepository.save(user);
        }

        rateLimiterService.recordFailedAttempt(ipAddress);
        auditService.logFailedLogin(username, ipAddress);
    }
}
```

### 3. Secure Session Management

```java
@Configuration
public class SessionConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .invalidSessionUrl("/login?expired")
                .maximumSessions(1)
                .maxSessionsPreventsLogin(false)
                .expiredUrl("/login?expired")
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
                .clearAuthentication(true)
            );

        return http.build();
    }
}

@PostMapping("/login")
public ResponseEntity<?> login(
        HttpServletRequest request,
        @RequestBody LoginRequest loginRequest) {

    AuthResult result = authService.authenticate(
        loginRequest.getUsername(),
        loginRequest.getPassword(),
        request.getRemoteAddr()
    );

    if (result.isSuccessful()) {
        // Prevent session fixation: create new session
        HttpSession oldSession = request.getSession(false);
        if (oldSession != null) {
            oldSession.invalidate();
        }

        // Create new session
        HttpSession newSession = request.getSession(true);
        newSession.setAttribute("user", result.getUser());

        // Set secure session cookie properties
        newSession.setMaxInactiveInterval(30 * 60); // 30 minutes

        return ResponseEntity.ok(Map.of("success", true));
    }

    return ResponseEntity.status(401).body(result.getError());
}
```

### 4. Multi-Factor Authentication

```java
@Service
public class MFAService {

    @Autowired
    private TOTPService totpService;

    @Autowired
    private SMSService smsService;

    public MFASetupResult setupTOTP(User user) {
        String secret = totpService.generateSecret();
        String qrCode = totpService.generateQRCode(user.getUsername(), secret);

        user.setMfaSecret(secret);
        user.setMfaEnabled(false); // Enable after verification

        return new MFASetupResult(secret, qrCode);
    }

    public boolean verifyTOTP(User user, String code) {
        if (!user.isMfaEnabled()) {
            return false;
        }

        return totpService.verifyCode(user.getMfaSecret(), code);
    }

    public void sendSMSCode(User user) {
        String code = String.format("%06d", secureRandom.nextInt(1000000));

        // Store code with expiry
        mfaCodeRepository.save(new MFACode(
            user.getId(),
            code,
            Instant.now().plus(Duration.ofMinutes(5))
        ));

        smsService.send(user.getPhoneNumber(), "Your code: " + code);
    }

    public boolean verifySMSCode(User user, String code) {
        Optional<MFACode> mfaCode = mfaCodeRepository
            .findByUserIdAndCode(user.getId(), code);

        if (mfaCode.isEmpty()) {
            return false;
        }

        MFACode storedCode = mfaCode.get();

        // Check expiry
        if (storedCode.getExpiry().isBefore(Instant.now())) {
            mfaCodeRepository.delete(storedCode);
            return false;
        }

        // Delete code after use
        mfaCodeRepository.delete(storedCode);

        return true;
    }
}
```

### 5. Secure Password Recovery

```java
@Service
public class SecurePasswordRecoveryService {

    @Transactional
    public void initiatePasswordReset(String email) {
        User user = userRepository.findByEmail(email);

        // Always return same message (prevent user enumeration)
        if (user == null) {
            // Simulate delay to prevent timing attacks
            Thread.sleep(200);
            return;
        }

        // Generate cryptographically secure token
        String token = secureRandomService.generateToken(32);

        PasswordResetToken resetToken = new PasswordResetToken();
        resetToken.setUser(user);
        resetToken.setToken(passwordEncoder.encode(token)); // Hash the token!
        resetToken.setExpiry(Instant.now().plus(Duration.ofHours(1)));

        resetTokenRepository.save(resetToken);

        // Send email with token
        emailService.sendPasswordResetEmail(user.getEmail(), token);

        // Log the request
        auditService.logPasswordResetRequest(user);
    }

    @Transactional
    public ResetResult resetPassword(String token, String newPassword) {
        // Find token
        Optional<PasswordResetToken> resetTokenOpt =
            resetTokenRepository.findValidToken(token);

        if (resetTokenOpt.isEmpty()) {
            return ResetResult.invalidToken();
        }

        PasswordResetToken resetToken = resetTokenOpt.get();

        // Verify token hasn't expired
        if (resetToken.getExpiry().isBefore(Instant.now())) {
            resetTokenRepository.delete(resetToken);
            return ResetResult.expiredToken();
        }

        // Validate new password
        ValidationResult validation = passwordService.validatePassword(newPassword);
        if (!validation.isValid()) {
            return ResetResult.invalidPassword(validation.getErrors());
        }

        // Update password
        User user = resetToken.getUser();
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        user.setPasswordChangedAt(Instant.now());
        userRepository.save(user);

        // Invalidate token
        resetTokenRepository.delete(resetToken);

        // Invalidate all sessions
        sessionRegistry.removeAllSessions(user.getUsername());

        // Notify user
        emailService.sendPasswordChangedNotification(user.getEmail());

        auditService.logPasswordReset(user);

        return ResetResult.success();
    }
}
```

## Best Practices

1. **Strong Password Policy**: Min 12 chars, complexity, check breaches
2. **Account Lockout**: 5 failed attempts, 30-minute lockout
3. **Rate Limiting**: Per IP and per username
4. **Multi-Factor Authentication**: TOTP or SMS
5. **Secure Session Management**: HTTPOnly, Secure, SameSite cookies
6. **Session Regeneration**: New session ID after authentication
7. **Password Hashing**: Argon2id or BCrypt (work factor 12+)
8. **Secure Password Recovery**: Time-limited tokens, no user enumeration
9. **Audit Logging**: Log all authentication events
10. **Monitor Anomalies**: Detect unusual login patterns

## Testing

```bash
# Test brute force protection
for i in {1..10}; do
  curl -X POST http://localhost:8080/login \
    -d '{"username":"admin","password":"wrong'$i'"}'
done

# Test session fixation
# 1. Get session ID before login
# 2. Login
# 3. Verify session ID changed
```

## References

- [OWASP A07:2025 - Authentication Failures](https://owasp.org/Top10/)
- [Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

---

**To Implement**: Create full example with SpringBoot backend and React frontend following A01/A02 patterns.

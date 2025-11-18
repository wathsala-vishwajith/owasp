# A06:2025 - Insecure Design

## Overview

Insecure Design represents missing or ineffective control design. It's different from insecure implementation - you can't fix insecure design with a perfect implementation. It requires threat modeling, secure design patterns, and reference architectures.

## What is Insecure Design?

Fundamental flaws in the application's architecture and design that can't be fixed by implementation alone. These are risks related to design and architectural flaws.

### Common Issues:

- Missing security controls
- Insufficient threat modeling
- Failure to segregate tenants in multi-tenant architecture
- Missing rate limiting on critical functions
- No defense in depth
- Trust boundaries not defined
- Business logic flaws
- Missing input validation framework

## Examples of Insecure Design

### 1. No Rate Limiting on Password Reset

```java
@RestController
public class InsecurePasswordReset {

    @PostMapping("/password-reset")
    public ResponseEntity<?> requestReset(@RequestParam String email) {
        // INSECURE DESIGN: No rate limiting
        // Attacker can enumerate users and flood emails

        User user = userService.findByEmail(email);
        if (user != null) {
            String token = UUID.randomUUID().toString();
            emailService.sendResetLink(email, token);
        }

        return ResponseEntity.ok("If account exists, email sent");
    }
}
```

### 2. No Multi-Factor Authentication

```java
@Service
public class InsecureAuthService {

    public boolean authenticate(String username, String password) {
        // INSECURE DESIGN: Only username/password
        // No MFA, no account lockout, no suspicious activity detection

        User user = userRepository.findByUsername(username);
        return user != null &&
               passwordEncoder.matches(password, user.getPasswordHash());
    }
}
```

### 3. Insufficient Workflow Validation

```java
@RestController
public class InsecureCheckout {

    @PostMapping("/checkout")
    public ResponseEntity<?> checkout(@RequestBody Order order) {
        // INSECURE DESIGN: Missing workflow validation
        // User can manipulate order after approval

        // No check if items still in cart
        // No check if prices haven't changed
        // No check if order was already processed

        paymentService.charge(order);
        return ResponseEntity.ok("Order placed");
    }
}
```

### 4. No Tenant Isolation

```java
@RestController
public class InsecureMultiTenantAPI {

    @GetMapping("/api/documents/{id}")
    public Document getDocument(@PathVariable Long id) {
        // INSECURE DESIGN: No tenant isolation
        // User from Company A can access Company B's documents

        return documentRepository.findById(id).orElse(null);

        // Missing: Check if document belongs to user's tenant
    }
}
```

### 5. Unlimited Resource Consumption

```java
@RestController
public class InsecureFileUpload {

    @PostMapping("/upload")
    public ResponseEntity<?> upload(@RequestParam("file") MultipartFile file) {
        // INSECURE DESIGN: No limits on file size or number of uploads
        // No virus scanning
        // No file type validation
        // Can cause DoS

        fileStorage.save(file);
        return ResponseEntity.ok("Uploaded");
    }
}
```

### 6. No Transaction Atomicity

```java
@Service
public class InsecureTransferService {

    public void transfer(Long fromAccount, Long toAccount, BigDecimal amount) {
        // INSECURE DESIGN: Race condition possible
        // Not atomic - can fail midway

        Account from = accountRepo.findById(fromAccount).get();
        Account to = accountRepo.findById(toAccount).get();

        from.setBalance(from.getBalance().subtract(amount));
        accountRepo.save(from);

        // PROBLEM: If crash happens here, money disappears

        to.setBalance(to.getBalance().add(amount));
        accountRepo.save(to);
    }
}
```

## How to Fix It

### 1. Implement Rate Limiting

```java
@Service
public class SecurePasswordReset {

    private final RateLimiter rateLimiter = RateLimiter.create(5.0); // 5 requests/second

    @PostMapping("/password-reset")
    public ResponseEntity<?> requestReset(
            @RequestParam String email,
            HttpServletRequest request) {

        String clientIp = request.getRemoteAddr();

        // Check rate limit per IP
        if (!rateLimiterService.allowRequest(clientIp, "password-reset", 3, Duration.ofMinutes(15))) {
            return ResponseEntity.status(429).body("Too many requests");
        }

        // Check rate limit per email
        if (!rateLimiterService.allowRequest(email, "password-reset", 5, Duration.ofHours(1))) {
            return ResponseEntity.status(429).body("Too many requests for this email");
        }

        User user = userService.findByEmail(email);
        if (user != null) {
            String token = secureRandomService.generateToken();
            tokenService.saveResetToken(user, token, Duration.ofMinutes(30));
            emailService.sendResetLink(email, token);
        }

        return ResponseEntity.ok("If account exists, email sent");
    }
}
```

### 2. Implement MFA and Account Protection

```java
@Service
public class SecureAuthService {

    public AuthResult authenticate(String username, String password, String mfaCode) {
        // Check if account is locked
        if (lockoutService.isLocked(username)) {
            return AuthResult.locked();
        }

        User user = userRepository.findByUsername(username);

        // Verify password
        if (user == null || !passwordEncoder.matches(password, user.getPasswordHash())) {
            failedAttemptService.recordFailure(username);
            return AuthResult.failed();
        }

        // Verify MFA
        if (!mfaService.verifyCode(user, mfaCode)) {
            return AuthResult.failed();
        }

        // Check for suspicious activity
        if (anomalyDetectionService.isSuspicious(user, request)) {
            mfaService.sendAdditionalChallenge(user);
            return AuthResult.additionalVerificationRequired();
        }

        // Reset failed attempts on success
        failedAttemptService.reset(username);

        return AuthResult.success(user);
    }
}
```

### 3. Implement Proper Workflow Validation

```java
@RestController
public class SecureCheckout {

    @PostMapping("/checkout")
    @Transactional
    public ResponseEntity<?> checkout(@RequestBody OrderRequest orderRequest) {
        User user = authService.getCurrentUser();

        // 1. Validate cart exists and belongs to user
        Cart cart = cartService.getCart(user);
        if (cart == null || cart.getItems().isEmpty()) {
            return ResponseEntity.badRequest().body("Cart is empty");
        }

        // 2. Validate all items still available
        for (CartItem item : cart.getItems()) {
            if (!inventoryService.isAvailable(item.getProductId(), item.getQuantity())) {
                return ResponseEntity.badRequest().body("Item no longer available: " + item.getProductName());
            }
        }

        // 3. Verify prices haven't changed
        BigDecimal currentTotal = cartService.calculateTotal(cart);
        if (!currentTotal.equals(orderRequest.getExpectedTotal())) {
            return ResponseEntity.badRequest().body("Prices have changed");
        }

        // 4. Check for duplicate submission (idempotency)
        if (orderService.exists(orderRequest.getIdempotencyKey())) {
            return ResponseEntity.ok(orderService.getByIdempotencyKey(orderRequest.getIdempotencyKey()));
        }

        // 5. Create order atomically
        Order order = orderService.createOrder(cart, orderRequest.getIdempotencyKey());

        // 6. Process payment
        PaymentResult paymentResult = paymentService.charge(order);
        if (!paymentResult.isSuccessful()) {
            orderService.cancel(order);
            return ResponseEntity.badRequest().body("Payment failed");
        }

        // 7. Update inventory
        inventoryService.reserve(order);

        return ResponseEntity.ok(order);
    }
}
```

### 4. Implement Tenant Isolation

```java
@Aspect
@Component
public class TenantIsolationAspect {

    @Around("@annotation(TenantScoped)")
    public Object enforceTenantIsolation(ProceedingJoinPoint pjp) throws Throwable {
        Long currentTenantId = tenantContext.getCurrentTenantId();

        Object result = pjp.proceed();

        // Ensure result belongs to current tenant
        if (result instanceof TenantAware) {
            TenantAware entity = (TenantAware) result;
            if (!entity.getTenantId().equals(currentTenantId)) {
                throw new AccessDeniedException("Cross-tenant access denied");
            }
        }

        return result;
    }
}

@Repository
public interface DocumentRepository extends JpaRepository<Document, Long> {

    // Always include tenant filter
    @Query("SELECT d FROM Document d WHERE d.id = :id AND d.tenantId = :tenantId")
    Optional<Document> findByIdAndTenant(@Param("id") Long id, @Param("tenantId") Long tenantId);
}
```

### 5. Implement Resource Limits

```java
@Configuration
public class FileUploadConfig {

    @Bean
    public MultipartConfigElement multipartConfigElement() {
        MultipartConfigFactory factory = new MultipartConfigFactory();
        // Limit file size to 10MB
        factory.setMaxFileSize(DataSize.ofMegabytes(10));
        // Limit request size to 15MB
        factory.setMaxRequestSize(DataSize.ofMegabytes(15));
        return factory.createMultipartConfig();
    }
}

@Service
public class SecureFileUploadService {

    private static final Set<String> ALLOWED_TYPES = Set.of(
        "image/jpeg", "image/png", "application/pdf"
    );

    private static final int MAX_FILES_PER_USER_PER_DAY = 100;

    public UploadResult upload(MultipartFile file, User user) {
        // Check daily upload limit
        int uploadCount = uploadRepository.countByUserAndDate(user, LocalDate.now());
        if (uploadCount >= MAX_FILES_PER_USER_PER_DAY) {
            throw new LimitExceededException("Daily upload limit exceeded");
        }

        // Validate file type
        if (!ALLOWED_TYPES.contains(file.getContentType())) {
            throw new InvalidFileTypeException("File type not allowed");
        }

        // Scan for malware
        if (!antivirusService.scan(file)) {
            throw new MalwareDetectedException("File contains malware");
        }

        // Save with unique name
        String filename = UUID.randomUUID().toString() + getExtension(file);
        fileStorage.save(filename, file);

        return new UploadResult(filename);
    }
}
```

### 6. Use Transactions and Locks

```java
@Service
public class SecureTransferService {

    @Transactional(isolation = Isolation.SERIALIZABLE)
    public TransferResult transfer(Long fromAccountId, Long toAccountId, BigDecimal amount) {

        // Use pessimistic locking to prevent race conditions
        Account fromAccount = accountRepo.findByIdWithLock(fromAccountId);
        Account toAccount = accountRepo.findByIdWithLock(toAccountId);

        // Validate accounts
        if (fromAccount == null || toAccount == null) {
            throw new AccountNotFoundException();
        }

        // Validate balance
        if (fromAccount.getBalance().compareTo(amount) < 0) {
            throw new InsufficientFundsException();
        }

        // Perform atomic transfer
        fromAccount.setBalance(fromAccount.getBalance().subtract(amount));
        toAccount.setBalance(toAccount.getBalance().add(amount));

        accountRepo.save(fromAccount);
        accountRepo.save(toAccount);

        // Create audit record
        auditService.recordTransfer(fromAccount, toAccount, amount);

        return TransferResult.success();
    }
}
```

## Secure Design Principles

1. **Defense in Depth**: Multiple layers of security
2. **Principle of Least Privilege**: Minimal necessary access
3. **Fail Secure**: System fails to secure state
4. **Separation of Duties**: Critical operations require multiple parties
5. **Zero Trust**: Never trust, always verify
6. **Secure by Default**: Secure configuration out of the box
7. **Minimize Attack Surface**: Disable unnecessary features
8. **Complete Mediation**: Check every access
9. **Open Design**: Security through design, not obscurity
10. **Psychological Acceptability**: Security should be usable

## Secure Design Checklist

- [ ] Threat modeling performed
- [ ] Rate limiting on sensitive endpoints
- [ ] MFA for privileged accounts
- [ ] Input validation at boundaries
- [ ] Workflow validation for business logic
- [ ] Proper error handling (fail secure)
- [ ] Transaction atomicity for critical operations
- [ ] Tenant isolation in multi-tenant apps
- [ ] Resource limits defined and enforced
- [ ] Audit logging for sensitive operations
- [ ] Secure session management
- [ ] Account lockout mechanisms
- [ ] Anomaly detection
- [ ] Circuit breakers for dependencies

## Tools and Practices

- Threat Modeling: STRIDE, PASTA
- Design Reviews: Peer review security architecture
- Reference Architectures: Use proven patterns
- Security Requirements: Define early in SDLC
- Abuse Cases: Think like an attacker

## References

- [OWASP A06:2025 - Insecure Design](https://owasp.org/Top10/)
- [Threat Modeling](https://owasp.org/www-community/Threat_Modeling)
- [Security Design Principles](https://owasp.org/www-project-security-design-principles/)

---

**To Implement**: Build examples showing insecure vs secure design patterns with SpringBoot and React.

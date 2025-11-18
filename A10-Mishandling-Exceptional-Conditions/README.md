# A10:2025 - Mishandling of Exceptional Conditions ⭐ NEW

## Overview

Mishandling of Exceptional Conditions is a NEW category in OWASP Top 10 2025. It encompasses improper error handling, logical errors, and systems "failing open" instead of "failing closed" when encountering abnormal conditions.

## What is Mishandling of Exceptional Conditions?

This vulnerability occurs when applications don't properly handle errors, edge cases, or unexpected conditions, leading to security breaches. It includes:

- Failing open (allowing access when error occurs)
- Verbose error messages exposing system details
- Unhandled exceptions causing crashes
- Race conditions
- Time-of-check to time-of-use (TOCTOU) bugs
- Improper null handling
- Integer overflow/underflow
- Division by zero without handling

## Vulnerable Examples

### 1. Failing Open (Security Bypasses)

```java
@Service
public class VulnerableAuthorizationService {

    public boolean isAuthorized(User user, Resource resource) {
        try {
            // Check permission
            Permission permission = permissionService.getPermission(user, resource);
            return permission != null && permission.isAllowed();

        } catch (Exception e) {
            // VULNERABLE: Exception = access granted!
            log.error("Error checking permission", e);
            return true;  // FAILING OPEN - should be false!
        }
    }
}

// Exploit: Attacker triggers exception to bypass authorization
```

### 2. Verbose Error Messages

```java
@RestController
public class VulnerableAPIController {

    @GetMapping("/user/{id}")
    public ResponseEntity<?> getUser(@PathVariable String id) {
        try {
            Long userId = Long.parseLong(id);
            User user = userService.findById(userId);
            return ResponseEntity.ok(user);

        } catch (NumberFormatException e) {
            // VULNERABLE: Exposing implementation details
            return ResponseEntity.badRequest().body(
                "Error parsing user ID: " + e.getMessage() +
                "\nStack trace: " + Arrays.toString(e.getStackTrace()) +
                "\nJava version: " + System.getProperty("java.version")
            );

        } catch (Exception e) {
            // VULNERABLE: Exposing internal errors
            return ResponseEntity.status(500).body(
                "Database error: " + e.getMessage() +
                "\nQuery: " + e.getCause()
            );
        }
    }
}
```

### 3. Race Conditions (TOCTOU)

```java
@Service
public class VulnerableFileService {

    public void processFile(String filename) {
        File file = new File(filename);

        // VULNERABLE: Time-of-check to time-of-use bug
        // File could be changed/deleted between check and use

        if (file.exists()) {  // Check
            // ... time passes ...
            // Attacker could delete or replace file here!

            FileInputStream fis = new FileInputStream(file);  // Use
            // Could throw exception or read malicious file
        }
    }
}
```

### 4. Unhandled Null Pointers

```java
@Service
public class VulnerableUserService {

    public void updateUserProfile(Long userId, ProfileUpdate update) {
        User user = userRepository.findById(userId).orElse(null);

        // VULNERABLE: No null check!
        // NullPointerException if user not found
        user.setEmail(update.getEmail());  // Crashes!
        user.setPhone(update.getPhone());

        userRepository.save(user);
    }
}
```

### 5. Integer Overflow

```java
@RestController
public class VulnerableShoppingCart {

    @PostMapping("/add-item")
    public ResponseEntity<?> addItem(@RequestParam int quantity) {
        // VULNERABLE: No overflow check
        // quantity could be Integer.MAX_VALUE

        int currentQuantity = cartService.getTotalItems();

        // Overflow! Result could be negative
        int newQuantity = currentQuantity + quantity;

        if (newQuantity < 0) {
            // After overflow, quantity appears low, bypassing limit!
        }

        cartService.setTotalItems(newQuantity);
        return ResponseEntity.ok("Added");
    }
}
```

## Secure Implementation

### 1. Fail Securely (Fail Closed)

```java
@Service
public class SecureAuthorizationService {

    public boolean isAuthorized(User user, Resource resource) {
        try {
            // Validate inputs
            if (user == null || resource == null) {
                log.warn("Null user or resource in authorization check");
                return false;  // FAIL CLOSED
            }

            // Check permission
            Permission permission = permissionService.getPermission(user, resource);
            return permission != null && permission.isAllowed();

        } catch (Exception e) {
            // SECURE: Exception = access denied
            log.error("Error checking permission - denying access", e);
            alertService.sendSecurityAlert("Authorization check failed", e);
            return false;  // FAIL CLOSED - default to deny
        }
    }
}
```

### 2. Generic Error Messages

```java
@RestController
@ControllerAdvice
public class SecureExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleException(Exception e, HttpServletRequest request) {

        // Log detailed error server-side
        log.error("Error processing request: {} {}",
            request.getMethod(),
            request.getRequestURI(),
            e);

        // SECURE: Generic message to client
        ErrorResponse response = ErrorResponse.builder()
            .timestamp(Instant.now())
            .error("An error occurred processing your request")
            .requestId(UUID.randomUUID().toString())
            .build();

        // NO stack traces, NO implementation details!
        return ResponseEntity.status(500).body(response);
    }

    @ExceptionHandler(ValidationException.class)
    public ResponseEntity<?> handleValidation(ValidationException e) {
        // Can provide more detail for validation errors
        ErrorResponse response = ErrorResponse.builder()
            .timestamp(Instant.now())
            .error("Validation failed")
            .details(e.getValidationErrors())  // Safe to expose
            .build();

        return ResponseEntity.badRequest().body(response);
    }
}
```

### 3. Prevent Race Conditions

```java
@Service
public class SecureFileService {

    public void processFile(String filename) {
        Path path = Paths.get(filename);

        try {
            // SECURE: Atomic operation - no TOCTOU
            // Open file directly, handle FileNotFoundException
            try (InputStream is = Files.newInputStream(path,
                    StandardOpenOption.READ)) {

                // Verify file properties
                BasicFileAttributes attrs = Files.readAttributes(
                    path,
                    BasicFileAttributes.class
                );

                // Check file size to prevent DoS
                if (attrs.size() > MAX_FILE_SIZE) {
                    throw new FileTooLargeException();
                }

                // Process file
                processFileContent(is);
            }

        } catch (NoSuchFileException e) {
            throw new FileNotFoundException("File not found: " + filename);

        } catch (IOException e) {
            log.error("Error processing file", e);
            throw new FileProcessingException("Unable to process file");
        }
    }
}

// For concurrent access, use locks
@Service
public class SecureAccountService {

    @Transactional(isolation = Isolation.SERIALIZABLE)
    public void withdraw(Long accountId, BigDecimal amount) {
        // Use pessimistic locking to prevent race conditions
        Account account = accountRepository.findByIdWithLock(accountId);

        if (account == null) {
            throw new AccountNotFoundException();
        }

        // Check balance
        if (account.getBalance().compareTo(amount) < 0) {
            throw new InsufficientFundsException();
        }

        // Atomic operation - no race condition
        account.setBalance(account.getBalance().subtract(amount));
        accountRepository.save(account);
    }
}
```

### 4. Proper Null Handling

```java
@Service
public class SecureUserService {

    public void updateUserProfile(Long userId, ProfileUpdate update) {
        // Validate inputs
        Objects.requireNonNull(userId, "User ID cannot be null");
        Objects.requireNonNull(update, "Profile update cannot be null");

        // Handle optional properly
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException("User not found: " + userId));

        // Validate update data
        if (update.getEmail() != null) {
            validateEmail(update.getEmail());
            user.setEmail(update.getEmail());
        }

        if (update.getPhone() != null) {
            validatePhone(update.getPhone());
            user.setPhone(update.getPhone());
        }

        userRepository.save(user);
    }
}

// Use Optional effectively
@Service
public class SecureOrderService {

    public OrderSummary getOrderSummary(Long orderId) {
        return orderRepository.findById(orderId)
            .map(this::createSummary)
            .orElseThrow(() -> new OrderNotFoundException(orderId));
    }

    private OrderSummary createSummary(Order order) {
        return OrderSummary.builder()
            .orderId(order.getId())
            .total(order.getTotal())
            .items(order.getItems())
            .build();
    }
}
```

### 5. Prevent Integer Overflow

```java
@RestController
public class SecureShoppingCart {

    private static final int MAX_QUANTITY = 1000;

    @PostMapping("/add-item")
    public ResponseEntity<?> addItem(@RequestParam int quantity) {
        // Validate input range
        if (quantity < 1 || quantity > MAX_QUANTITY) {
            return ResponseEntity.badRequest()
                .body("Quantity must be between 1 and " + MAX_QUANTITY);
        }

        int currentQuantity = cartService.getTotalItems();

        // SECURE: Check for overflow before addition
        if (currentQuantity > Integer.MAX_VALUE - quantity) {
            return ResponseEntity.badRequest()
                .body("Cart quantity would exceed maximum");
        }

        // Use Math.addExact for overflow detection
        try {
            int newQuantity = Math.addExact(currentQuantity, quantity);

            if (newQuantity > MAX_QUANTITY) {
                return ResponseEntity.badRequest()
                    .body("Cart quantity exceeds maximum allowed");
            }

            cartService.setTotalItems(newQuantity);
            return ResponseEntity.ok("Added to cart");

        } catch (ArithmeticException e) {
            return ResponseEntity.badRequest()
                .body("Quantity calculation error");
        }
    }
}

// For financial calculations, use BigDecimal
@Service
public class SecurePaymentService {

    public BigDecimal calculateTotal(List<LineItem> items) {
        return items.stream()
            .map(item -> item.getPrice().multiply(
                BigDecimal.valueOf(item.getQuantity())
            ))
            .reduce(BigDecimal.ZERO, BigDecimal::add);

        // BigDecimal prevents overflow and precision loss
    }
}
```

### 6. Timeout and Circuit Breaker

```java
@Service
public class SecureExternalService {

    private final CircuitBreaker circuitBreaker;

    @Autowired
    public SecureExternalService(CircuitBreakerFactory factory) {
        this.circuitBreaker = factory.create("external-service");
    }

    public Response callExternalAPI(Request request) {
        return circuitBreaker.run(
            () -> {
                // Call with timeout
                return restTemplate.exchange(
                    url,
                    HttpMethod.POST,
                    new HttpEntity<>(request),
                    Response.class
                ).getBody();
            },
            throwable -> {
                // Fallback - fail gracefully
                log.error("External service call failed", throwable);
                return Response.unavailable();
            }
        );
    }
}
```

## Best Practices

1. **Fail Securely**: Default to deny/reject on errors
2. **Generic Errors**: Don't expose implementation details
3. **Validate Inputs**: Check all inputs thoroughly
4. **Handle Null Safely**: Use Optional, Objects.requireNonNull()
5. **Prevent Overflows**: Validate ranges, use Math.*Exact()
6. **Atomic Operations**: Prevent race conditions
7. **Timeouts**: Set timeouts on all external calls
8. **Circuit Breakers**: Handle cascading failures
9. **Graceful Degradation**: System remains functional when components fail
10. **Comprehensive Testing**: Test edge cases and error paths

## Error Handling Checklist

- [ ] All exceptions caught and handled appropriately
- [ ] Default behavior is secure (fail closed)
- [ ] Error messages are generic (no sensitive info)
- [ ] Null checks on all nullable values
- [ ] Integer overflow prevention
- [ ] Race condition prevention (locks, transactions)
- [ ] Timeout on all external calls
- [ ] Circuit breakers for external services
- [ ] Input validation (range, format, type)
- [ ] Proper resource cleanup (try-with-resources)
- [ ] Dead letter queues for failed messages
- [ ] Retry logic with exponential backoff

## Testing

```java
@Test
public void testAuthorizationFailsClosed() {
    // Simulate error condition
    when(permissionService.getPermission(any(), any()))
        .thenThrow(new RuntimeException());

    // Verify access is denied on error
    assertFalse(authService.isAuthorized(user, resource));
}

@Test
public void testIntegerOverflow() {
    // Test with values that would cause overflow
    assertThrows(ValidationException.class, () ->
        cartService.addItem(Integer.MAX_VALUE)
    );
}

@Test
public void testRaceCondition() {
    // Run concurrent operations
    // Verify data consistency
}
```

## Impact

- Authentication/authorization bypass
- Information disclosure
- Data corruption
- Denial of service
- System crashes
- Security control bypass

## References

- [OWASP A10:2025 - Mishandling of Exceptional Conditions](https://owasp.org/Top10/)
- [Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)
- [Transaction Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html)

---

**To Implement**: Create SpringBoot backend and React frontend demonstrating error handling vulnerabilities and secure implementations.

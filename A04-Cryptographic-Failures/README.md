# A04:2025 - Cryptographic Failures

## Overview

Cryptographic Failures (previously Sensitive Data Exposure) relates to failures in cryptography which often lead to exposure of sensitive data. This includes weak encryption, insecure protocols, and poor key management.

## What are Cryptographic Failures?

Failures that compromise the confidentiality of sensitive data at rest or in transit through:

- Weak or outdated cryptographic algorithms
- Insufficient key lengths
- Improper key management
- Storing passwords in plaintext or with weak hashing
- Not enforcing encryption for sensitive data
- Missing or improper use of TLS/SSL
- Using deprecated protocols (SSL, TLS 1.0/1.1)
- Predictable initialization vectors (IVs)
- Reusing keys or IVs

### Common Vulnerabilities:

- Passwords stored in plaintext
- Using MD5 or SHA1 for passwords
- Weak encryption algorithms (DES, RC4)
- Hardcoded encryption keys
- Transmitting sensitive data over HTTP
- Insufficient randomness in key generation
- Missing certificate validation
- Sensitive data in logs or error messages

## This Example

This demo demonstrates cryptographic failures in:

1. **Weak Password Hashing**
2. **Insecure Encryption**
3. **Hardcoded Secrets**
4. **Data Transmitted Unencrypted**
5. **Weak Random Number Generation**

## Demonstration

### Vulnerable Code Examples

#### 1. Plaintext Password Storage

```java
@Entity
public class User {
    private String username;

    // VULNERABLE: Password stored in plaintext!
    private String password;

    // Other sensitive data
    private String creditCard;  // Unencrypted!
    private String ssn;  // Unencrypted!
}

@Service
public class AuthService {
    public boolean authenticate(String username, String password) {
        User user = userRepository.findByUsername(username);
        // VULNERABLE: Comparing plaintext passwords
        return user != null && user.getPassword().equals(password);
    }
}
```

#### 2. Weak Password Hashing (MD5)

```java
@Service
public class WeakCryptoService {
    // VULNERABLE: MD5 is cryptographically broken
    public String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(password.getBytes());
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            return null;
        }
    }
}
```

#### 3. Insecure Encryption (DES with hardcoded key)

```java
public class InsecureEncryption {
    // VULNERABLE: Hardcoded key
    private static final String SECRET_KEY = "12345678";

    // VULNERABLE: Using DES (weak algorithm)
    public String encrypt(String data) throws Exception {
        Cipher cipher = Cipher.getInstance("DES");
        SecretKeySpec key = new SecretKeySpec(
            SECRET_KEY.getBytes(), "DES"
        );
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }
}
```

#### 4. Predictable Random Numbers

```java
public class WeakRandom {
    // VULNERABLE: Using java.util.Random (not cryptographically secure)
    private Random random = new Random();

    public String generateToken() {
        return String.valueOf(random.nextInt(1000000));
    }

    public String generateSessionId() {
        // VULNERABLE: Predictable!
        return String.valueOf(System.currentTimeMillis());
    }
}
```

#### 5. Sensitive Data Over HTTP

```javascript
// Frontend sending sensitive data
// VULNERABLE: Using HTTP instead of HTTPS
axios.post('http://api.example.com/login', {
    username: username,
    password: password,  // Sent in cleartext!
    creditCard: '4532-1234-5678-9010'  // Sent in cleartext!
});
```

## How to Fix It

### 1. Secure Password Hashing

```java
@Service
public class SecurePasswordService {

    // SECURE: Using BCrypt with proper work factor
    public String hashPassword(String password) {
        return BCrypt.hashpw(password, BCrypt.gensalt(12));
    }

    public boolean verifyPassword(String password, String hash) {
        return BCrypt.checkpw(password, hash);
    }
}

// Alternative: Argon2
@Service
public class Argon2PasswordService {
    private Argon2 argon2 = Argon2Factory.create(
        Argon2Factory.Argon2Types.ARGON2id
    );

    public String hashPassword(String password) {
        return argon2.hash(2, 65536, 1, password.toCharArray());
    }

    public boolean verify(String hash, String password) {
        return argon2.verify(hash, password.toCharArray());
    }
}
```

### 2. Secure Encryption (AES-256-GCM)

```java
@Service
public class SecureEncryptionService {

    // SECURE: Generate strong key
    private SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);  // 256-bit key
        return keyGen.generateKey();
    }

    // SECURE: AES-GCM with proper IV
    public EncryptedData encrypt(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        // Generate random IV for each encryption
        byte[] iv = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);

        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] encrypted = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));

        return new EncryptedData(encrypted, iv);
    }

    public String decrypt(EncryptedData encryptedData, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, encryptedData.getIv());

        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] decrypted = cipher.doFinal(encryptedData.getData());

        return new String(decrypted, StandardCharsets.UTF_8);
    }
}
```

### 3. Secure Key Management

```java
@Configuration
public class KeyManagementConfig {

    // SECURE: Load keys from secure key store
    @Bean
    public SecretKey encryptionKey() throws Exception {
        // Use environment variable or key vault
        String keyBase64 = System.getenv("ENCRYPTION_KEY");
        byte[] decodedKey = Base64.getDecoder().decode(keyBase64);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }
}

// application.properties
// DON'T: encryption.key=hardcodedkey123
// DO: Use environment variables or Azure Key Vault/AWS KMS
```

### 4. Secure Random Generation

```java
public class SecureRandomGenerator {
    // SECURE: Use SecureRandom for cryptographic operations
    private SecureRandom secureRandom = new SecureRandom();

    public String generateToken() {
        byte[] token = new byte[32];
        secureRandom.nextBytes(token);
        return Base64.getUrlEncoder().withoutPadding()
            .encodeToString(token);
    }

    public String generateSessionId() {
        byte[] sessionId = new byte[64];
        secureRandom.nextBytes(sessionId);
        return Hex.encodeHexString(sessionId);
    }
}
```

### 5. Enforce HTTPS

```java
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // SECURE: Require HTTPS
            .requiresChannel(channel -> channel
                .anyRequest().requiresSecure()
            )
            // SECURE: Enable HSTS
            .headers(headers -> headers
                .httpStrictTransportSecurity(hsts -> hsts
                    .includeSubDomains(true)
                    .maxAgeInSeconds(31536000)
                )
            );
        return http.build();
    }
}
```

### 6. Encrypt Sensitive Database Fields

```java
@Entity
public class SecureUser {
    private String username;

    // SECURE: Password hashed with BCrypt
    @Column(length = 60)
    private String passwordHash;

    // SECURE: Sensitive fields encrypted at rest
    @Convert(converter = CreditCardEncryptor.class)
    private String creditCard;

    @Convert(converter = SSNEncryptor.class)
    private String ssn;
}

@Converter
public class CreditCardEncryptor implements AttributeConverter<String, String> {

    @Autowired
    private EncryptionService encryptionService;

    @Override
    public String convertToDatabaseColumn(String attribute) {
        return encryptionService.encrypt(attribute);
    }

    @Override
    public String convertToEntityAttribute(String dbData) {
        return encryptionService.decrypt(dbData);
    }
}
```

## Best Practices

1. **Use Strong Algorithms**:
   - Encryption: AES-256-GCM or ChaCha20-Poly1305
   - Hashing: Argon2id, scrypt, or bcrypt
   - TLS: 1.3 only

2. **Proper Key Management**:
   - Generate keys with SecureRandom
   - Store keys securely (HSM, Key Vault)
   - Rotate keys regularly
   - Never hardcode keys

3. **Password Storage**:
   - Use Argon2id (recommended)
   - Alternative: bcrypt with work factor ≥ 12
   - Add salt automatically
   - Never store plaintext passwords

4. **Data in Transit**:
   - Always use HTTPS/TLS
   - Implement certificate pinning
   - Use HSTS headers
   - Disable older TLS versions

5. **Data at Rest**:
   - Encrypt sensitive fields
   - Use database-level encryption
   - Encrypt backups
   - Secure key storage

## Common Mistakes

- Using `java.util.Random` for security
- Reusing IVs/nonces
- ECB mode for block ciphers
- Implementing custom crypto
- Storing keys with data
- Not validating certificates
- Weak key derivation

## Testing

```bash
# Check TLS configuration
nmap --script ssl-enum-ciphers -p 443 example.com

# Test password hashing
# Should NOT be reversible
# Should take reasonable time (100-500ms)

# Verify encryption
# Different encryptions of same data should differ
# Should use proper IV/nonce
```

## Impact

- Theft of sensitive personal data
- Financial fraud
- Identity theft
- Privacy violations
- Regulatory penalties (GDPR, PCI-DSS)
- Reputation damage

## References

- [OWASP A04:2025 - Cryptographic Failures](https://owasp.org/Top10/)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

---

**To Implement**: Follow patterns from A01 and A02 to create full demonstration with SpringBoot backend and React frontend.

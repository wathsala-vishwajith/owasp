# A08:2025 - Software and Data Integrity Failures

## Overview

Software and Data Integrity Failures relate to code and infrastructure that doesn't protect against integrity violations. This includes insecure CI/CD pipelines, auto-updates without verification, and insecure deserialization.

## Common Vulnerabilities

- Unsigned or unverified software updates
- Insecure deserialization
- Untrusted CI/CD pipelines
- Auto-update without integrity checks
- Using CDNs without SRI (Subresource Integrity)
- Insufficient backup integrity verification
- Missing digital signatures
- Unprotected critical data

## Examples

### 1. Insecure Deserialization

```java
@RestController
public class VulnerableDeserializationController {

    @PostMapping("/import")
    public ResponseEntity<?> importData(@RequestBody String base64Data) {
        try {
            // VULNERABLE: Deserializing untrusted data
            byte[] data = Base64.getDecoder().decode(base64Data);
            ObjectInputStream ois = new ObjectInputStream(
                new ByteArrayInputStream(data)
            );
            Object obj = ois.readObject();  // RCE possible!

            return ResponseEntity.ok("Imported");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error");
        }
    }
}

// Exploit: Attacker sends malicious serialized object
// Can achieve Remote Code Execution (RCE)
```

### 2. Auto-Update Without Verification

```java
@Service
public class VulnerableUpdateService {

    @Scheduled(cron = "0 0 * * * *")
    public void checkForUpdates() {
        // VULNERABLE: Downloading updates over HTTP
        // No signature verification
        String updateUrl = "http://updates.example.com/latest.jar";

        try {
            byte[] update = restTemplate.getForObject(updateUrl, byte[].class);

            // VULNERABLE: No integrity check!
            Files.write(Paths.get("app.jar"), update);

            // Restart application with new code
            restartApplication();
        } catch (Exception e) {
            log.error("Update failed", e);
        }
    }
}
```

### 3. Using External Resources Without SRI

```html
<!-- VULNERABLE: No Subresource Integrity -->
<script src="https://cdn.example.com/library.js"></script>

<!-- Attacker compromises CDN = your app compromised -->
```

### 4. Insecure CI/CD Pipeline

```yaml
# VULNERABLE: .github/workflows/deploy.yml
name: Deploy
on: [push]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      # VULNERABLE: No verification of dependencies
      - uses: actions/checkout@v2
      - run: npm install  # Could install malicious packages

      # VULNERABLE: Secrets in logs
      - run: echo "API_KEY=${{ secrets.API_KEY }}"

      # VULNERABLE: Deploying without tests
      - run: npm run build
      - run: ./deploy.sh
```

## Secure Implementation

### 1. Safe Deserialization

```java
@RestController
public class SecureDeserializationController {

    // SECURE: Use JSON instead of Java serialization
    @PostMapping("/import")
    public ResponseEntity<?> importData(@RequestBody ImportRequest request) {
        // JSON deserialization is much safer
        // Limited to data, not code execution

        // Validate structure
        if (!isValidImport(request)) {
            return ResponseEntity.badRequest().body("Invalid data");
        }

        // Process with validation
        ImportResult result = importService.process(request);

        return ResponseEntity.ok(result);
    }
}

// If you MUST use Java serialization:
@Service
public class SecureSerializationService {

    public Object deserialize(byte[] data) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(
            new ByteArrayInputStream(data)
        ) {
            @Override
            protected Class<?> resolveClass(ObjectStreamClass desc)
                    throws IOException, ClassNotFoundException {

                // Whitelist allowed classes only
                if (!isAllowedClass(desc.getName())) {
                    throw new InvalidClassException(
                        "Unauthorized deserialization attempt",
                        desc.getName()
                    );
                }

                return super.resolveClass(desc);
            }
        };

        return ois.readObject();
    }

    private boolean isAllowedClass(String className) {
        // Whitelist specific classes only
        return Set.of(
            "com.example.SafeClass1",
            "com.example.SafeClass2"
        ).contains(className);
    }
}
```

### 2. Secure Auto-Update

```java
@Service
public class SecureUpdateService {

    @Scheduled(cron = "0 0 * * * *")
    public void checkForUpdates() {
        try {
            // SECURE: Use HTTPS
            String updateUrl = "https://updates.example.com/latest.jar";
            String signatureUrl = "https://updates.example.com/latest.jar.sig";

            // Download update and signature
            byte[] update = restTemplate.getForObject(updateUrl, byte[].class);
            byte[] signature = restTemplate.getForObject(signatureUrl, byte[].class);

            // Verify signature
            if (!signatureService.verify(update, signature, PUBLIC_KEY)) {
                log.error("Update signature verification failed!");
                alertService.sendSecurityAlert("Invalid update signature");
                return;
            }

            // Verify checksum matches published checksum
            String expectedChecksum = getPublishedChecksum();
            String actualChecksum = calculateSHA256(update);

            if (!expectedChecksum.equals(actualChecksum)) {
                log.error("Update checksum mismatch!");
                return;
            }

            // Backup current version
            backupService.backupCurrentVersion();

            // Apply update
            Files.write(Paths.get("app.jar"), update);

            // Verify update was applied correctly
            if (verifyUpdate()) {
                restartApplication();
            } else {
                rollbackUpdate();
            }

        } catch (Exception e) {
            log.error("Update failed", e);
            rollbackUpdate();
        }
    }
}

@Service
public class SignatureService {

    public boolean verify(byte[] data, byte[] signature, PublicKey publicKey) {
        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(publicKey);
            sig.update(data);
            return sig.verify(signature);
        } catch (Exception e) {
            log.error("Signature verification failed", e);
            return false;
        }
    }
}
```

### 3. Use Subresource Integrity

```html
<!-- SECURE: With Subresource Integrity -->
<script
  src="https://cdn.example.com/library@1.2.3.js"
  integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
  crossorigin="anonymous">
</script>

<!-- Browser verifies hash before executing -->
```

### 4. Secure CI/CD Pipeline

```yaml
# SECURE: .github/workflows/deploy.yml
name: Deploy
on:
  push:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      # Verify dependencies
      - name: Dependency Check
        run: |
          npm audit --audit-level=high
          npm run license-check

      # SAST scanning
      - name: CodeQL Analysis
        uses: github/codeql-action/analyze@v2

  test:
    needs: security-scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      # Lock file ensures consistent dependencies
      - name: Install Dependencies
        run: npm ci  # Not npm install!

      - name: Run Tests
        run: npm test

      - name: Integration Tests
        run: npm run test:integration

  deploy:
    needs: test
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v3

      - name: Build
        run: npm run build

      # Sign the build
      - name: Sign Artifacts
        run: |
          gpg --detach-sign --armor dist/app.js
          sha256sum dist/app.js > dist/app.js.sha256

      # Deploy with verification
      - name: Deploy
        run: ./deploy.sh
        env:
          API_KEY: ${{ secrets.API_KEY }}

      # Verify deployment
      - name: Verify Deployment
        run: ./verify-deployment.sh
```

### 5. Data Integrity Checks

```java
@Service
public class DataIntegrityService {

    // Store checksums with data
    @Transactional
    public void saveDocument(Document document) {
        // Calculate checksum
        String checksum = calculateChecksum(document.getContent());
        document.setChecksum(checksum);

        // Sign document
        String signature = signatureService.sign(document.getContent());
        document.setSignature(signature);

        documentRepository.save(document);

        // Audit trail
        auditService.logDocumentCreation(document);
    }

    // Verify integrity when reading
    public Document getDocument(Long id) {
        Document document = documentRepository.findById(id)
            .orElseThrow(() -> new NotFoundException("Document not found"));

        // Verify checksum
        String actualChecksum = calculateChecksum(document.getContent());
        if (!actualChecksum.equals(document.getChecksum())) {
            log.error("Document integrity check failed for id: " + id);
            alertService.sendIntegrityAlert(document);
            throw new IntegrityException("Document has been tampered with");
        }

        // Verify signature
        if (!signatureService.verify(
                document.getContent(),
                document.getSignature())) {
            throw new IntegrityException("Document signature invalid");
        }

        return document;
    }

    private String calculateChecksum(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            return Hex.encodeHexString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
```

## Best Practices

1. **Digital Signatures**: Sign all software releases
2. **Subresource Integrity**: For CDN resources
3. **Secure Deserialization**: Prefer JSON, whitelist classes
4. **Update Verification**: Check signatures and checksums
5. **Secure CI/CD**: Scan dependencies, run tests, verify deployment
6. **Data Checksums**: Store and verify data integrity
7. **Audit Trails**: Log all integrity-sensitive operations
8. **Dependency Pinning**: Lock file for reproducible builds
9. **Security Scanning**: SAST/DAST in pipeline
10. **Backup Verification**: Test backup integrity regularly

## Tools

- **Dependency Scanning**: OWASP Dependency-Check, Snyk
- **SAST**: SonarQube, Checkmarx, Semgrep
- **DAST**: OWASP ZAP, Burp Suite
- **Container Scanning**: Trivy, Clair
- **SBOM**: CycloneDX, SPDX

## References

- [OWASP A08:2025 - Software and Data Integrity Failures](https://owasp.org/Top10/)
- [Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [Subresource Integrity](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity)

---

**To Implement**: Create examples demonstrating insecure deserialization and secure alternatives with SpringBoot and React.

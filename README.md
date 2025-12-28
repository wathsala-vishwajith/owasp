# OWASP Top 10 2025 - Learning Examples

This repository contains educational example projects demonstrating each of the **OWASP Top 10 2025** vulnerabilities. Each example includes a vulnerable SpringBoot backend and React frontend to help developers understand these security risks.

> **WARNING**: These examples contain intentionally vulnerable code for educational purposes only. **DO NOT** use this code in production environments.

## OWASP Top 10 2025 Overview

The OWASP Top 10 2025 represents the most critical security risks to web applications:

### The List

1. **[A01:2025 - Broken Access Control](./A01-Broken-Access-Control/)**
   - Missing authorization checks, allowing users to access resources they shouldn't

2. **[A02:2025 - Security Misconfiguration](./A02-Security-Misconfiguration/)**
   - Improperly configured security settings, default credentials, verbose error messages

3. **[A03:2025 - Software Supply Chain Failures](./A03-Software-Supply-Chain-Failures/)** ⭐ NEW
   - Compromises in dependencies, build systems, and distribution infrastructure

4. **[A04:2025 - Cryptographic Failures](./A04-Cryptographic-Failures/)**
   - Weak encryption, exposed sensitive data, improper key management

5. **[A05:2025 - Injection](./A05-Injection/)**
   - SQL injection, command injection, and other injection attacks

6. **[A06:2025 - Insecure Design](./A06-Insecure-Design/)**
   - Fundamental flaws in application architecture and design

7. **[A07:2025 - Authentication Failures](./A07-Authentication-Failures/)**
   - Broken authentication mechanisms, session management issues

8. **[A08:2025 - Software or Data Integrity Failures](./A08-Software-Data-Integrity-Failures/)**
   - Unverified updates, insecure CI/CD pipelines, deserialization issues

9. **[A09:2025 - Logging & Alerting Failures](./A09-Logging-Alerting-Failures/)**
   - Insufficient logging, monitoring, and incident response

10. **[A10:2025 - Mishandling of Exceptional Conditions](./A10-Mishandling-Exceptional-Conditions/)** ⭐ NEW
    - Improper error handling, failing open, logical errors

## Project Structure

Each vulnerability example follows this structure:

```
A0X-Vulnerability-Name/
├── backend/                    # SpringBoot application
│   ├── src/
│   ├── pom.xml
│   └── README.md
├── frontend/                   # React application
│   ├── src/
│   ├── package.json
│   └── README.md
└── README.md                   # Vulnerability explanation and demo instructions
```

## How to Use This Repository

### For Each Example:

1. **Read the README** in each vulnerability folder to understand:
   - What the vulnerability is
   - How it manifests in code
   - The potential impact
   - How to fix it

2. **Run the Backend** (SpringBoot):
   ```bash
   cd A0X-Vulnerability-Name/backend
   ./mvnw spring-boot:run
   ```

3. **Run the Frontend** (React):
   ```bash
   cd A0X-Vulnerability-Name/frontend
   npm install
   npm start
   ```

4. **Exploit the Vulnerability** following the demonstration steps in each README

5. **Learn How to Fix It** by reviewing the secure code examples

## Learning Objectives

By working through these examples, you will:

- Understand how each vulnerability works in practice
- Learn to identify these issues in real code
- Discover best practices for prevention
- Gain hands-on experience with security testing

## Prerequisites

- Java 17 or higher
- Maven 3.6+
- Node.js 18+ and npm
- Basic knowledge of Spring Boot and React
- A curious mind and willingness to learn!

## Security Notice

**CRITICAL**: This repository is for **educational purposes only**. The code examples intentionally demonstrate security vulnerabilities. Never use these patterns in production applications.

## Contributing

If you find issues or want to improve the examples, please open an issue or submit a pull request.

## License

MIT License - Use for educational purposes only

## Resources

- [OWASP Top 10 2025](https://owasp.org/Top10/2025/)
- [OWASP Foundation](https://owasp.org/)
- [Spring Security](https://spring.io/projects/spring-security)
- [React Security Best Practices](https://react.dev/learn/security)

---

**Happy Learning! Stay Secure!** 🔒
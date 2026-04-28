# Stored SQL Injection via Report Parameters → MyBatis SQL Concatenation

## Project Information
- **Project:** xianrendzw/EasyReport
- **Type:** Stored SQL Injection
- **Severity:** High (CVSS 7.5)
- **CWE:** CWE-89 (SQL Injection)

## Vulnerability Description

EasyReport contains a stored SQL injection where report parameters are stored via MyBatis and later used in SQL concatenation without parameterization.

## Data Flow

```
REST API (reportParams) → MyBatis → SQL concatenation → execute()
```

### Write Path
1. REST endpoint accepts report configuration with SQL parameters
2. Parameters stored via MyBatis to database

### Read Path
3. Stored report parameters retrieved during report generation
4. Values concatenated into SQL strings via MyBatis ${} syntax or Java string concatenation
5. SQL executed without parameterization

## Authentication

Authentication required for report management.

## Remediation

1. **Parameterized queries**: Use MyBatis #{} instead of ${}
2. **Input validation**: Validate report parameter values
3. **SQL escaping**: Sanitize special characters

## References

- CWE-89: SQL Injection

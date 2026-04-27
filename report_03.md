# Stored Injection RCE via Backup Script Configuration → Runtime.exec()

## Project Information
- **Project:** gocd/gocd
- **Type:** Stored Injection RCE (Command Injection via Backup Script)
- **Severity:** Critical (CVSS 9.1)
- **CWE:** CWE-78 (OS Command Injection)

## Vulnerability Description

GoCD contains a stored injection RCE where backup script configuration is stored in the database and later executed via `Runtime.exec()` or ProcessBuilder during backup operations.

## Data Flow

```
REST API (backup script config) → DB → Backup trigger → Runtime.exec(script)
```

### Write Path
1. REST endpoint accepts backup configuration including script path/command
2. Configuration stored to database via GoCD's configuration persistence layer

### Read Path
3. On backup trigger, stored script configuration is read from database
4. Script executed via `Runtime.exec()` or ProcessBuilder without sanitization

## Authentication

**Required**: Admin-level access needed for backup configuration. However, backup scheduling may allow automated triggers.

## Remediation

1. **Validate script paths**: Restrict to known-safe directories
2. **Input sanitization**: Reject shell metacharacters in script configuration
3. **Sandboxing**: Execute backup scripts in isolated environment
4. **Least privilege**: Run backup operations with minimal OS privileges

## References

- CWE-78: OS Command Injection

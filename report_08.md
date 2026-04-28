# Stored Injection RCE via Job Configuration → ClassLoader/Shell Execution

## Project Information
- **Project:** vipshop/Saturn
- **Type:** Stored Injection RCE (Reflection + Command Injection)
- **Severity:** Critical (CVSS 9.8)
- **CWE:** CWE-470 (Use of Externally-Controlled Input to Select Classes or Code), CWE-78 (OS Command Injection)

## Vulnerability Description

vipshop Saturn contains two stored injection RCE vulnerabilities:

1. **JAVA_JOB vector**: Attacker-controlled `jobClass` value is stored via REST API and later loaded via `ClassLoader.loadClass()` + `Class.newInstance()` on executor nodes
2. **SHELL_JOB vector**: Attacker-controlled `jobParameter` is stored and later executed via `/bin/sh -c` on executor nodes

Both vectors require NO authentication — the REST API at `/rest/v1/*` is unauthenticated by default.

## Data Flow

### Vector 1: JAVA_JOB Class Loading RCE

```
POST /rest/v1/{namespace}/jobs → MySQL+ZK → ClassLoader.loadClass(jobClass) → Class.newInstance()
```

**Write Path:**
1. `JobOperationRestApiController.java:59-71,227-239` — REST endpoint `POST /rest/v1/{namespace}/jobs` accepts arbitrary `jobClass`
2. `constructJobConfigOfCreate()` (line 292): no sanitization
3. `JobServiceImpl.validateJobConfig()` (lines 528-555): only checks `jobClass` is non-empty — no whitelist
4. `JobServiceImpl.addOrCopyJob()` (lines 903-956): stores to MySQL via `CurrentJobConfigMapper.xml:7,197-227`

**Read/Exec Path:**
5. `JobScheduler.java:176`: `JobTypeManager.get(jobType).getHandlerClass().newInstance()` → `SaturnJavaJob`
6. `SaturnJavaJob.createJobBusinessInstanceIfNecessary()` (lines 72-116):
   - Line 84: `jobClassLoader.loadClass(jobClassStr)` — loads arbitrary class
   - Line 101: `jobClass.newInstance()` — instantiates arbitrary class

### Vector 2: SHELL_JOB Command Injection

```
POST /rest/v1/{namespace}/jobs → MySQL+ZK → /bin/sh -c <jobParameter>
```

**Write Path:** Same as Vector 1, using `SHELL_JOB` type with malicious `jobParameter`

**Read/Exec Path:**
1. `SaturnScriptJob.java:55-107` — handles `SHELL_JOB` type
2. `ScriptJobRunner.createCommandLine()` (lines 99-112):
   ```java
   CommandLine cmdLine = new CommandLine("/bin/sh");
   cmdLine.addArguments(new String[]{"-c", execParameter}, false);
   ```
3. `ScriptJobRunner.execute()` (line 188): `executor.execute(commandLine, env)`

## Key Evidence

**No authentication on REST API** (`SaturnFilterRegister.java:26,34`):
```java
@Value("${authentication.enabled:false}")   // default: disabled
private boolean authenticationEnabled;
registration.addUrlPatterns("/console/*");   // REST API /rest/v1/* NOT covered
```

**Dangerous class loading** (`SaturnJavaJob.java:84,101`):
```java
Class<?> jobClass = jobClassLoader.loadClass(jobClassStr);  // line 84
jobBusinessInstance = jobClass.newInstance();                // line 101
```

**Shell command execution** (`ScriptJobRunner.java:107-111`):
```java
final CommandLine cmdLine = new CommandLine("/bin/sh");
cmdLine.addArguments(new String[]{"-c", execParameter}, false);
```

## Authentication

**NOT REQUIRED.** The REST API at `/rest/v1/*` is never covered by `AuthenticationFilter`. `authentication.enabled` defaults to `false`.

## Remediation

1. **Authenticate REST API:** Extend authentication to `/rest/v1/*` endpoints
2. **JobClass Whitelist:** Restrict loadable classes to a predefined package/annotation whitelist
3. **Input Sanitization:** Validate `jobParameter` against shell metacharacter patterns
4. **Disable Shell Jobs:** Remove or heavily restrict `SHELL_JOB` type functionality
5. **Security Manager:** Implement JVM SecurityManager to restrict class loading

## References

- CWE-470: Use of Externally-Controlled Input to Select Classes or Code
- CWE-78: OS Command Injection
- CWE-306: Missing Authentication for Critical Function

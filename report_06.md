# Stored Injection RCE via Script API → Groovy Evaluation (Default Disabled)

## Project Information
- **Project:** sonatype/nexus-public
- **Type:** Stored Injection RCE via Groovy Script Execution (Mitigated)
- **Severity:** High (CVSS 7.2) — lowered due to default-disabled mitigation
- **CWE:** CWE-94 (Code Injection), CWE-693 (Protection Mechanism Failure)

## Vulnerability Description

Sonatype Nexus Repository Manager contains a stored injection RCE via its Script API. Scripts (Groovy code) can be stored via REST API and executed in the server JVM. Script creation is **disabled by default** since v3.22 (`nexus.scripts.allowCreation=false`), but the execution path remains fully functional. If an admin re-enables script creation, the vulnerability is exploitable.

## Data Flow

```
POST /v1/script → ScriptManager.create() → MySQL → POST /v1/script/{name}/run → Groovy eval in JVM
```

### Write Path (Requires `nexus.scripts.allowCreation=true`)
1. `ScriptResource.add()` (ScriptResource.java:157): Accepts `ScriptXO` with `name`, `content`, `type`
2. `ScriptManagerImpl.create()`: Checks feature flag → `ScriptData` → `ScriptStoreImpl` → MySQL
3. No content validation — only `@NotEmpty` on `content` field

### Read/Exec Path
4. `POST /v1/script/{name}/run` (`ScriptResource.run()`, line 191-216)
5. `ScriptServiceImpl.eval()` (line 132-133):
   ```java
   return engineForLanguage(language).eval(script, context);
   ```
6. Groovy code executes in server JVM with full privileges

## Key Evidence

**Weak sandbox** (`GroovyScriptEngineFactory.java:89-94`):
```java
secureASTCustomizer.setImportsBlacklist(Collections.singletonList("java.lang.System"));
secureASTCustomizer.setReceiversBlackList(Collections.singletonList(System.class.getName()));
```
Only blocks `java.lang.System`. Bypass via `Runtime.exec()`, `ProcessBuilder`, `"cmd".execute()`.

**Default disabled** (`NexusPropertiesVerifier.java:128-129`):
```java
if (nexusProperties.getProperty("nexus.scripts.allowCreation") == null) {
    nexusProperties.put("nexus.scripts.allowCreation", FALSE);
}
```

**No content validation** (`ScriptResource.java:157-167`):
```java
public void add(@NotNull @Valid final ScriptXO scriptXO) {
    scriptManager.create(scriptXO.getName(), scriptXO.getContent(), scriptXO.getType());
}
```

## Authentication

**Required**: All operations require Shiro permissions (`nexus:script:*:add`, `nexus:script:{name}:run`). Admin-level access needed.

## Status

- **Default config**: Script creation DISABLED — not exploitable
- **With `nexus.scripts.allowCreation=true`**: Fully exploitable with admin credentials
- **Sandbox**: Trivially bypassable

## Remediation

1. **Keep script creation disabled**: Do not set `nexus.scripts.allowCreation=true`
2. **Strengthen sandbox**: Block all dangerous classes and methods, not just `System`
3. **Remove execution API**: Consider removing the script run endpoint entirely
4. **Audit logging**: Log all script content at creation and execution time
5. **Network restriction**: Restrict Script API access to localhost only

## References

- CWE-94: Code Injection
- CWE-693: Protection Mechanism Failure

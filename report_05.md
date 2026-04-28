# Stored Deserialization via SQLite BLOB — Android Binder IPC (Not REST)

## Project Information
- **Project:** re-zero001/LSPosed-Irena
- **Type:** Stored Deserialization (Android-specific)
- **Severity:** High (CVSS 7.0) — system-level impact but limited attack surface
- **CWE:** CWE-502 (Deserialization of Untrusted Data)

## Verdict: CONFIRMED — SerializationUtils.deserialize() with no class filtering at system level

## Data Flow

```
Xposed module → Binder IPC → LSPModuleService.updateRemotePreferences() → SerializationUtils.serialize() → SQLite BLOB
Daemon restart → ConfigManager.fetchModuleConfig() → SerializationUtils.deserialize() → ObjectInputStream.readObject() (root level)
```

## Key Findings

1. **Not REST-based**: Uses Android Binder IPC, not HTTP REST
2. **Not SharedPreferences**: Uses SQLite database, not SharedPreferences XML
3. **No class filtering**: `org.apache.commons.lang3.SerializationUtils.deserialize()` uses raw `ObjectInputStream` with no `resolveClass` override
4. **System-level execution**: Runs in zygote (root) process
5. **UID check enforced**: `ensureModule()` verifies calling module's UID matches loaded module

## Attack Surface

- Any installed Xposed module can write arbitrary serialized objects via `updateRemotePreferences()`
- Objects deserialized at root/system level on daemon restart
- Requires user to install malicious Xposed module (social engineering)

## KB Addition

- `SharedPreferencesImpl` → file read pattern (original description was inaccurate)

## References

- CWE-502: Deserialization of Untrusted Data

# Stored Deserialization RCE via ZK Task Store → SerializationUtils.deserialize()

## Project Information
- **Project:** pravega/pravega
- **Type:** Stored Deserialization RCE (Java Serialization via ZooKeeper task store)
- **Severity:** High (CVSS 8.1) — Conditional on auth configuration
- **CWE:** CWE-502 (Deserialization of Untrusted Data)
- **Verdict:** CONFIRMED (conditional auth)

## Vulnerability Description

Pravega's controller stores task metadata (including `Serializable[] parameters`) in ZooKeeper using Apache Commons Lang `SerializationUtils.serialize/deserialize`. The deserialization path uses raw `ObjectInputStream.readObject()` with no class filtering. `TaskData.parameters` is a `Serializable[]` that can carry arbitrary gadget chains.

## Data Flow

```
REST API → ControllerService → TaskBase.lock() → ZKTaskMetadataStore → ZK node → SerializationUtils.deserialize() → readObject() → RCE
```

### Write Path
1. REST endpoints (`POST /v1/scopes`, `POST /v1/scopes/{scopeName}/streams`) handled by `StreamMetadataResourceImpl`
2. Calls `ControllerService.createScope()`/`createStream()` → delegates to `StreamMetadataTasks`
3. `StreamMetadataTasks` extends `TaskBase`, uses `taskMetadataStore.lock()` storing `TaskData` in ZK
4. `ZKTaskMetadataStore.acquireLock()` (lines 46-65) serializes `TaskData`, wraps in `LockData`, both via `SerializationUtils.serialize()`

### Read Path
5. `getTask()` (lines 143-170): `LockData.deserialize(data)` → `SerializationUtils.deserialize(bytes)` (`LockData` line 46)
6. Then `TaskData.deserialize(lockData.getTaskData())` → `SerializationUtils.deserialize(bytes)` (`TaskData` line 45)
7. `SerializationUtils.deserialize()` internally calls `ObjectInputStream.readObject()` — **no class filtering**
8. `ZookeeperBucketStore` (lines 158, 170) also does raw `SerializationUtils.deserialize(data.getObject())`

## Key Evidence

- **`LockData.java` lines 45-46**: `return (LockData) SerializationUtils.deserialize(bytes)` — raw Java deserialization
- **`TaskData.java` lines 44-45**: `return (TaskData) SerializationUtils.deserialize(bytes)` — same issue
- **`TaskData` line 32**: `Serializable[] parameters` — array elements can be any Serializable type
- **`ZKTaskMetadataStore` lines 82, 103, 159-160**: all call `LockData.deserialize(data)` from ZK reads
- **`ZookeeperBucketStore` lines 158, 170**: raw `SerializationUtils.deserialize()` for bucket ownership data

## Authentication

Conditional — `RESTAuthHelper.isAuthEnabled()` returns true only if `pravegaAuthManager != null`. If no auth manager is configured (possible default), REST endpoints are unauthenticated. Even with auth, the threat model includes authenticated attackers or compromised credentials.

## Remediation

1. **Replace Java serialization**: Use Protocol Buffers or JSON for task state (note: `ControllerEventSerializer` already uses safe custom serialization for events)
2. **Add ObjectInputFilter**: Implement JEP 290 deserialization filtering for all `SerializationUtils.deserialize()` calls
3. **Type restriction**: Replace `Serializable[] parameters` with a typed, validated container
4. **Auth by default**: Enable authentication by default in Pravega controller

## References

- CWE-502: Deserialization of Untrusted Data

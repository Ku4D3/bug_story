# Stored Deserialization RCE via Hessian2 Untrusted Deserialization

## Project Information
- **Project:** vivo/MoonBox
- **Type:** Stored Deserialization RCE
- **Severity:** Critical (CVSS 9.8)
- **CWE:** CWE-502 (Deserialization of Untrusted Data)

## Vulnerability Description

vivo MoonBox contains a stored deserialization RCE via Hessian2. Unauthenticated REST endpoints accept raw HTTP request bodies, deserialize them using Hessian2 with `setAllowNonSerializable(true)`, store them in Elasticsearch, and later deserialize them again during replay on target JVMs. The Hessian `SerializerFactory` has no class whitelist/blacklist, and `UnsafeDeserializer` uses `sun.misc.Unsafe` to instantiate arbitrary classes.

## Data Flow

```
POST /api/agent/record/save → Hessian2 deserialize → ES storage → Replay → Hessian2 deserialize → RCE
POST /api/agent/replay/save → Hessian2 deserialize → ES storage → Replay → Hessian2 deserialize → RCE
```

### Write Path
1. Unauthenticated endpoint `/api/agent/record/save` and `/api/agent/replay/save` accept raw request body
2. `HessianSerializer` deserializes with `setAllowNonSerializable(true)` and `Object.class`/`Object[].class`
3. Raw Hessian2 serialized data stored in Elasticsearch as `wrapperRecord` field

### Read Path
4. During replay, stored data retrieved from ES without integrity checks
5. Hessian2 deserialization on target JVM using same unsafe configuration
6. `UnsafeDeserializer` uses `sun.misc.Unsafe` to instantiate arbitrary classes

## Key Evidence

**No authentication**: `/api/agent/*` endpoints have zero authentication. `SignUtils.getHeaders()` returns empty `HashMap`. No Spring Security or servlet filter.

**Unsafe Hessian2 configuration**: `setAllowNonSerializable(true)` with no `ClassFactory` filter. Deserialization uses `Object.class` and `Object[].class` accepting arbitrary types.

**Stored payload**: Raw Hessian2 serialized body stored as-is in ES, retrieved and deserialized during replay without integrity checks.

**Fastjson bypass**: AutoType is blocked by `safeMode` (default on), but Hessian2 path completely bypasses Fastjson protections.

## Authentication

**NOT REQUIRED.** `/api/agent/*` endpoints have no authentication whatsoever.

## Remediation

1. **Authenticate agent endpoints**: Require authentication for all `/api/agent/*` endpoints
2. **Hessian2 hardening**: Configure `ClassFactory` with strict class whitelist; disable `setAllowNonSerializable`
3. **Input validation**: Validate serialized data integrity before storage
4. **Replace UnsafeDeserializer**: Use safe deserialization with explicit type mapping
5. **Network segmentation**: Restrict agent endpoint access to trusted networks only

## References

- CWE-502: Deserialization of Untrusted Data
- CWE-306: Missing Authentication for Critical Function

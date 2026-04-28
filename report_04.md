# Stored Deserialization RCE via File/HTTP Storage — Mitigated by Class Filtering

## Project Information
- **Project:** javamelody/javamelody
- **Type:** Stored Deserialization (Mitigated)
- **Severity:** Medium (CVSS 5.5) — class filtering applied
- **CWE:** CWE-502 (Deserialization of Untrusted Data)

## Verdict: CONFIRMED but MITIGATED — Class whitelist prevents gadget chain exploitation

## Data Flow

```
MonitoringFilter → CounterStorage.writeToFile() → .ser.gz file → CounterStorage.readFromFile() → MyObjectInputStream.readObject()
LabradorRetriever (HTTP collector) → TransportFormat.SERIALIZED → MyObjectInputStream.readObject()
```

## Key Findings

1. **MyObjectInputStream has whitelist**: `resolveClass()` only allows `java.lang.*`, `java.util.*`, `java.io.*`, `net.bull.javamelody.*` — effectively blocks gadget chains
2. **Storage uses Java serialization**: `Counter` objects serialized to `.ser.gz` files via `ObjectOutputStream`
3. **HTTP collector flow**: `LabradorRetriever` fetches serialized data from remote apps over HTTP
4. **Auth defaults to open**: `HttpAuth` allows all access if `authorized-users` parameter not set

## Authentication

**Optional**: HTTP auth supported but defaults to fully open if not configured.

## References

- CWE-502: Deserialization of Untrusted Data

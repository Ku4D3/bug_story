# Stored Deserialization RCE via Redis → Fastjson AutoType Parse

## Project Information
- **Project:** changmingxie/tcc-transaction
- **Type:** Stored Deserialization RCE (Fastjson AutoType)
- **Severity:** Critical (CVSS 9.8)
- **CWE:** CWE-502 (Deserialization of Untrusted Data)

## Vulnerability Description

tcc-transaction stores transaction data in Redis which is later deserialized using Fastjson with AutoType enabled. An attacker who can write to Redis (via REST API or direct access) can inject a crafted JSON payload that triggers arbitrary class instantiation during deserialization.

## Data Flow

```
REST API → Redis (transaction state) → Fastjson.parseObject() with AutoType → RCE
```

### Write Path
1. TCC transaction participants write transaction state to Redis
2. Transaction data serialized using Fastjson and stored in Redis keys

### Read Path
3. Transaction recovery process reads data from Redis
4. `JSON.parseObject()` or `JSON.parse()` with AutoType support enabled
5. Attacker-controlled @type field causes arbitrary class instantiation

## Authentication

Redis access may be unauthenticated in default deployments.

## Remediation

1. **Disable AutoType**: Set `ParserConfig.getGlobalInstance().setAutoTypeSupport(false)` and use `safeMode`
2. **Type whitelist**: Use explicit type mapping instead of AutoType
3. **Redis authentication**: Require authentication for Redis connections
4. **Network segmentation**: Restrict Redis access to application servers

## References

- CWE-502: Deserialization of Untrusted Data

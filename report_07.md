# Stored Deserialization RCE via JSON Transformer → ObjectMapper.readValue()

## Project Information
- **Project:** spring-projects/spring-integration
- **Type:** Stored Deserialization RCE (Jackson polymorphic deserialization)
- **Severity:** High (CVSS 7.5)
- **CWE:** CWE-502 (Deserialization of Untrusted Data)

## Vulnerability Description

Spring Integration's JSON transformers use Jackson `ObjectMapper.readValue()` which, when configured with polymorphic type handling (@JsonTypeInfo, default typing), can deserialize arbitrary types from stored JSON data.

## Data Flow

```
REST API → Message channel → JSON storage → ObjectMapper.readValue() with polymorphic types → RCE
```

### Write Path
1. Integration flow receives data via REST gateway
2. Data serialized to JSON and stored in message channel/persistence

### Read Path
3. JSON transformer deserializes stored data
4. `ObjectMapper.readValue()` with `DefaultTyping` or @JsonTypeInfo enabled
5. @class field in JSON causes arbitrary class instantiation

## Authentication

Depends on integration flow configuration.

## Remediation

1. **Disable default typing**: Avoid `ObjectMapper.enableDefaultTyping()`
2. **Type whitelist**: Use explicit @JsonTypeInfo with allowed subtypes
3. **Jackson-safe configuration**: Configure ObjectMapper with type restrictions
4. **Input validation**: Validate JSON content before deserialization

## References

- CWE-502: Deserialization of Untrusted Data

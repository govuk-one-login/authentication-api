# StructuredAuditService for typed audit events

## Decision

We will implement a `StructuredAuditService` that provides type-safe audit event submission using strongly-typed event classes that implement a `StructuredAuditEvent` interface. This service will serialize events to JSON using snake_case field naming and submit them to the TxMA audit queue via SQS.

## Context

The authentication service needs to emit audit events for security monitoring and compliance purposes. Previously, audit events were created using unstructured approaches that could lead to inconsistencies in event format and missing required fields.

We identified the need for a more robust audit system that:

- Ensures consistent event structure across all audit events
- Provides compile-time safety for event creation
- Standardizes field naming conventions
- Maintains compatibility with existing TxMA infrastructure
- Reduces the likelihood of malformed audit events

## Detail

This approach introduces:

**StructuredAuditEvent Interface**: A common interface that all audit events must implement, defining required fields:

- `eventName()`: The name of the audit event
- `timestamp()`: Unix timestamp in seconds
- `eventTimestampMs()`: Unix timestamp in milliseconds
- `clientId()`: The client identifier (nullable)
- `componentId()`: The component generating the event

**Concrete Event Classes**: Strongly-typed record classes for each audit event type (e.g., `AuthEmailFraudCheckBypassed`) that:

- Implement the `StructuredAuditEvent` interface
- Use Java records for immutability and reduced boilerplate
- Include nested record classes for complex data structures (User, Extensions)
- Provide static factory methods for easy creation
- Enforce non-null constraints on required fields

**StructuredAuditService**: A service class that:

- Accepts any `StructuredAuditEvent` implementation
- Serializes events to JSON
- Submits serialized events to the TxMA audit queue

**Integration Pattern**: Services inject `StructuredAuditService` and create specific event instances:

```java
var auditEvent = AuthEmailFraudCheckBypassed.create(
    clientId,
    new AuthEmailFraudCheckBypassed.User(userId, email, ipAddress, sessionId, journeyId),
    new AuthEmailFraudCheckBypassed.Extensions(journeyType, timestamp)
);
auditService.submitAuditEvent(auditEvent);
```

## Consequences

### Positive

- **Type Safety**: Compile-time verification of event structure prevents runtime errors from malformed events
- **Consistency**: All audit events follow the same interface contract, ensuring consistent field presence
- **Maintainability**: Adding new audit events requires implementing the interface, making the contract explicit
- **Documentation**: Event structure is self-documenting through the type system
- **Testability**: Strongly-typed events are easier to test and mock
- **Field Naming**: Automatic snake_case conversion ensures consistent naming convention for downstream systems, which can be overridden on a case-by-case basis
- **Immutability**: Using records ensures audit events cannot be modified after creation

### Negative

- **Code Volume**: Each audit event type requires a dedicated class, increasing the codebase size
- **Migration Effort**: Existing unstructured audit events need to be migrated to the new system
- **Dependency**: Services now depend on specific audit event classes in addition to the service

### Neutral

- **Performance**: Minimal impact as JSON serialization overhead is similar to previous approaches
- **Compatibility**: Events are still submitted to the same TxMA infrastructure via SQS
- **Configuration**: Service configuration remains the same (queue URL, region, etc.)

## Implementation Notes

- The `StructuredAuditService.UNKNOWN` constant provides a standard placeholder for unavailable field values
- Event timestamps are automatically generated using `Instant.now()` in factory methods
- The service supports both direct `AwsSqsClient` injection for testing and `ConfigurationService`-based initialization
- Component IDs are standardized using a `ComponentId` enum (e.g., `ComponentId.AUTH.getValue()`)

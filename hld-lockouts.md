## Proposed Design: Domain-Driven Lockout Management

### 1. Core Domain Model

```java
// Central domain entity that encapsulates all lockout logic
public class LockoutPolicy {
private final JourneyType journeyType;
private final CountType countType;
private final int maxAttempts;
private final Duration lockoutDuration;
private final Duration countTtl;

    public LockoutResult evaluateAttempt(int currentCount, Instant lastAttemptTime) {
        // Single place for all lockout logic
    }

    public boolean isLocked(int currentCount, Instant lastAttemptTime) {
        // Centralized lockout evaluation
    }
}

// Immutable result object
public sealed interface LockoutResult
permits AllowAttempt, BlockAttempt, ApplyLockout {

    record AllowAttempt() implements LockoutResult {}
    record BlockAttempt(Duration remainingLockout) implements LockoutResult {}
    record ApplyLockout(Duration lockoutDuration) implements LockoutResult {}
}
```

### 2. Policy Configuration Registry

```java
@Component
public class LockoutPolicyRegistry {
private final Map<PolicyKey, LockoutPolicy> policies;

    public LockoutPolicyRegistry(ConfigurationService config) {
        this.policies = buildPolicies(config);
    }

    public LockoutPolicy getPolicy(JourneyType journey, CountType countType) {
        return policies.get(new PolicyKey(journey, countType));
    }

    private Map<PolicyKey, LockoutPolicy> buildPolicies(ConfigurationService config) {
        return Map.of(
            // All business rules defined in one place
            new PolicyKey(SIGN_IN, ENTER_PASSWORD),
                new LockoutPolicy(SIGN_IN, ENTER_PASSWORD, 6,
                    Duration.ofHours(2), Duration.ofHours(2)),

            new PolicyKey(SIGN_IN, ENTER_MFA_CODE),
                new LockoutPolicy(SIGN_IN, ENTER_MFA_CODE, 6,
                    Duration.ofHours(2), Duration.ofMinutes(15)),
            // ... other policies
        );
    }
}
```

### 3. Unified Lockout Service

```java
@Service
public class LockoutService {
private final LockoutAttemptRepository repository;
private final LockoutPolicyRegistry policyRegistry;
private final AuditService auditService;

    public Result<LockoutError, LockoutResult> processAttempt(
            String subjectId,
            JourneyType journey,
            CountType countType,
            boolean attemptSuccessful) {

        var policy = policyRegistry.getPolicy(journey, countType);
        var currentState = repository.getCurrentState(subjectId, journey, countType);

        if (attemptSuccessful) {
            return handleSuccessfulAttempt(subjectId, journey, countType, currentState);
        }

        return handleFailedAttempt(subjectId, journey, countType, policy, currentState);
    }

    public boolean isLocked(String subjectId, JourneyType journey, CountType countType) {
        var policy = policyRegistry.getPolicy(journey, countType);
        var currentState = repository.getCurrentState(subjectId, journey, countType);
        return policy.isLocked(currentState.getCount(), currentState.getLastAttemptTime());
    }
}
```

### 4. Simplified DynamoDB Schema

```java
@DynamoDbBean
public class LockoutAttempt {
@DynamoDbPartitionKey
private String subjectId;

    @DynamoDbSortKey
    private String lockoutKey; // "SIGN_IN#ENTER_PASSWORD"

    private int attemptCount;
    private Instant lastAttemptTime;
    private Instant lockoutExpiresAt;
    private long ttl; // DynamoDB TTL for automatic cleanup

    // Computed properties
    public boolean isLocked() {
        return lockoutExpiresAt != null &&
               Instant.now().isBefore(lockoutExpiresAt);
    }

    public boolean isCountExpired() {
        return ttl > 0 && Instant.now().getEpochSecond() > ttl;
    }
}
```

### 5. Repository with Resilience

```java
@Repository
public class LockoutAttemptRepository {
private final DynamoDbEnhancedClient dynamoClient;
private final DynamoDbTable<LockoutAttempt> table;

    public Result<RepositoryError, LockoutAttemptState> getCurrentState(
            String subjectId, JourneyType journey, CountType countType) {

        try {
            var key = buildLockoutKey(journey, countType);
            var item = table.getItem(Key.builder()
                .partitionValue(subjectId)
                .sortValue(key)
                .build());

            return Result.success(
                item != null && !item.isCountExpired()
                    ? LockoutAttemptState.fromDynamoItem(item)
                    : LockoutAttemptState.empty()
            );
        } catch (Exception e) {
            LOG.error("Failed to retrieve lockout state", e);
            // Fail-safe: assume no lockout to avoid blocking legitimate users
            return Result.success(LockoutAttemptState.empty());
        }
    }

    public Result<RepositoryError, Void> updateAttemptCount(
            String subjectId,
            JourneyType journey,
            CountType countType,
            LockoutAttemptState newState) {

        try {
            var item = LockoutAttempt.builder()
                .subjectId(subjectId)
                .lockoutKey(buildLockoutKey(journey, countType))
                .attemptCount(newState.getCount())
                .lastAttemptTime(newState.getLastAttemptTime())
                .lockoutExpiresAt(newState.getLockoutExpiresAt())
                .ttl(newState.getTtl())
                .build();

            table.putItem(item);
            return Result.success(null);
        } catch (Exception e) {
            LOG.error("Failed to update lockout state", e);
            return Result.failure(new RepositoryError("Update failed", e));
        }
    }
}
```

### 6. Handler Integration

```java
// Clean integration in handlers
public class VerifyCodeHandler extends BaseFrontendHandler<VerifyCodeRequest> {
private final LockoutService lockoutService;

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(...) {
        var subjectId = userContext.getUserProfile().getSubjectID();
        var journey = determineJourney(codeRequest);
        var countType = determineCountType(codeRequest);

        // Simple lockout check
        if (lockoutService.isLocked(subjectId, journey, countType)) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1027);
        }

        var codeValid = validateCode(codeRequest);

        // Process attempt result
        var lockoutResult = lockoutService.processAttempt(
            subjectId, journey, countType, codeValid);

        return lockoutResult.fold(
            error -> generateApiGatewayProxyErrorResponse(500, ErrorResponse.ERROR_1064),
            result -> handleLockoutResult(result, codeValid)
        );
    }
}
```

## Key Design Benefits

### **Locality & Understanding**
• All lockout rules centralized in LockoutPolicyRegistry
• Business logic encapsulated in domain objects
• Clear separation between policy and persistence

### **Extensibility**
• New journey/count type combinations require only policy configuration
• Easy to add new lockout behaviors (e.g., progressive delays)
• Plugin architecture for different lockout strategies

### **Resilience**
• Fail-safe defaults (no lockout on errors)
• Result types force explicit error handling
• DynamoDB TTL for automatic cleanup
• Graceful degradation on persistence failures

### **Testability**
• Pure domain logic easily unit tested
• Repository abstraction enables integration testing
• Policy registry can be mocked for handler tests

### **Migration Path**
• Can run alongside existing system
• Gradual migration journey by journey
• Feature flags for rollback capability

### **Observability**
```java
// Built-in metrics and audit trails
public class LockoutService {
    private void auditLockoutEvent(String subjectId, JourneyType journey,
            CountType countType, LockoutResult result) {
        auditService.submitAuditEvent(
            FrontendAuditableEvent.AUTH_LOCKOUT_APPLIED,
            auditContext,
            pair("journey", journey.getValue()),
            pair("countType", countType.getValue()),
            pair("result", result.getClass().getSimpleName())
        );
    }
}
```

This design transforms the current scattered lockout logic into a cohesive, domain-driven approach that makes business rules explicit, improves maintainability, and provides a solid foundation for future enhancements.

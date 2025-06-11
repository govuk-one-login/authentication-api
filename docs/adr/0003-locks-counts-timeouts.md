# Migrating Error Counts to DynamoDB -- DRAFT

# !! CURRENTLY PARKED FOR LATER USE !!

Check the git history to see the changes made so far.

## Context

We are changing our architecture to use DynamoDB in preference to Elasticache (redis). This ADR addresses the migration of error counts, failed code entries, and other temporary state data from Redis to DynamoDB. The current system uses Redis to store various types of error counts and temporary locks, including:

### Count Types
1. **Authentication Attempts**
    - MFA code attempt counts (SMS and Auth App)
    - Password attempt counts
    - Email attempt counts
    - Code request counts for different notification types
    - Account creation attempt counts
    - Reauthentication attempt counts

2. **Journey-Specific Counts**
    - Sign-in journey counts
    - Reauthentication journey counts
    - Account creation journey counts
    - Password reset journey counts
    - Account recovery journey counts
    - Password reset MFA journey counts

3. **Lock Types**
    - Code request blocks
    - Password blocks
    - MFA blocks
    - Email blocks
    - Account recovery blocks
    - Password reset blocks
    - Reduced lockout blocks (for SMS registration and account recovery)

4. **Session Data**
    - Retry counts
    - Password reset counts
    - Code request counts by type
    - Account intervention states
    - Email fraud block states

The data access patterns show several key requirements:
1. Fast reads and writes for error count increments
2. TTL-based expiration of counts and locks
3. Atomic increment operations
4. Ability to check multiple count types in a single operation
5. Support for different journey types (SIGN_IN, REAUTHENTICATION, etc.)
6. Support for different notification types (SMS, EMAIL, AUTH_APP)
7. Support for different code request types (VERIFY_EMAIL, MFA_SMS, etc.)
8. Support for different lockout durations (standard and reduced)
9. Support for account intervention states
10. Support for email fraud block states

## Decision

We will migrate all error counts and temporary state data to a single DynamoDB table using the design pattern established in ADR-0002. This table will use:

- Partition Key (PK): subject_id
- Sort Key (SK): JOURNEY_TYPE#COUNT_TYPE#CLASSIFIER
- Attributes:
    - count: number
    - ttl: number (Unix timestamp)
    - last_updated: number (Unix timestamp)
    - notification_type: string (optional)
    - mfa_method_type: string (optional)
    - block_type: string (optional)
    - block_duration: number (optional)
    - intervention_state: string (optional)


# Expected Access Paths for SK LOGIN#MFA#ERROR

## Assume a User is trying to log in:
```
LOGIN#MFA#ERROR#EF444945-A8A9-4CBD-8E71-552C735E78A0
LOGIN#MFA#ERROR#72CB4E28-CD8D-48A0-9899-02601480CE10
```

## Is user locked out?

We can do a Query with Count parameter for SK=LOGIN#MFA#ERROR which will return 5 in a single call.  Then check its less than 11?

## Has User tried this MFA method too many times?
Query:  SK=LOGIN#MFA#ERROR#EF444945-A8A9-4CBD-8E71-552C735E78A0 will return 3 which can be checked against max allowed for an individual MFA device.

## Increment login mfa error count for MFA.
Update SK=LOGIN#MFA#ERROR#EF444945-A8A9-4CBD-8E71-552C735E78A0 increment count.

Example Items:

| PK                | SK                                               | count | ttl        | last_updated | notification_type | mfa_method_type | block_type | block_duration | intervention_state |
| ----------------- | ------------------------------------------------ | ----- | ---------- | ------------ | ---------------- | --------------- | ---------- | -------------- | ----------------- |
| subject-id-user-a | SIGN_IN#ERROR_COUNT#MFA_CODE_ENTRY              | 2     | 1234567890 | 1234567800   | MFA_SMS         | SMS            | null       | null           | null              |
| subject-id-user-a | REAUTHENTICATION#ERROR_COUNT#PASSWORD_ENTRY     | 1     | 1234567890 | 1234567800   | null            | null           | null       | null           | null              |
| subject-id-user-a | SIGN_IN#LOCK#PASSWORD_RESET                     | 1     | 1234567890 | 1234567800   | null            | null           | STANDARD   | 900            | null              |
| subject-id-user-a | ACCOUNT_CREATION#ERROR_COUNT#MFA_CODE_ENTRY     | 3     | 1234567890 | 1234567800   | MFA_SMS         | SMS            | null       | null           | null              |
| subject-id-user-a | PASSWORD_RESET#ERROR_COUNT#CODE_ENTRY           | 2     | 1234567890 | 1234567800   | RESET_PASSWORD  | EMAIL          | null       | null           | null              |
| subject-id-user-a | ACCOUNT_RECOVERY#ERROR_COUNT#MFA_CODE_ENTRY     | 4     | 1234567890 | 1234567800   | VERIFY_CHANGE_HOW_GET_SECURITY_CODES | AUTH_APP | null | null | null |
| subject-id-user-a | SIGN_IN#ERROR_COUNT#MFA_CODE_ENTRY              | 1     | 1234567890 | 1234567800   | MFA_SMS         | AUTH_APP       | null       | null           | null              |
| subject-id-user-a | PASSWORD_RESET_MFA#ERROR_COUNT#MFA_CODE_ENTRY   | 2     | 1234567890 | 1234567800   | MFA_SMS         | SMS            | null       | null           | null              |
| subject-id-user-a | REAUTHENTICATION#ERROR_COUNT#MFA_CODE_ENTRY     | 3     | 1234567890 | 1234567800   | MFA_SMS         | SMS            | null       | null           | null              |
| subject-id-user-a | SIGN_IN#LOCK#MFA_CODE_ENTRY                     | 1     | 1234567890 | 1234567800   | MFA_SMS         | SMS            | STANDARD   | 900            | null              |
| subject-id-user-a | ACCOUNT_RECOVERY#LOCK#MFA_CODE_ENTRY            | 1     | 1234567890 | 1234567800   | VERIFY_CHANGE_HOW_GET_SECURITY_CODES | AUTH_APP | REDUCED | 300 | null |
| subject-id-user-a | PASSWORD_RESET#LOCK#MFA_CODE_ENTRY              | 1     | 1234567890 | 1234567800   | RESET_PASSWORD  | SMS            | STANDARD   | 900            | null              |
| subject-id-user-a | ACCOUNT_INTERVENTION#STATE#BLOCKED              | 1     | 1234567890 | 1234567800   | null            | null           | PERMANENT  | null           | BLOCKED           |
| subject-id-user-a | EMAIL_FRAUD#STATE#BLOCKED                       | 1     | 1234567890 | 1234567800   | null            | null           | STANDARD   | 900            | FRAUD_BLOCKED     |

## Consequences

### Positive

1. **Consistency with Existing Pattern**: Aligns with the design pattern established in ADR-0002 for reauthentication error counts, making the codebase more consistent and easier to maintain.

2. **Scalability**: DynamoDB's automatic scaling will handle increased load without manual intervention, unlike Redis which requires manual scaling.

3. **Cost Efficiency**: DynamoDB's pay-per-request model may be more cost-effective than maintaining Redis clusters, especially for lower traffic periods.

4. **Simplified Operations**: Reduces operational complexity by consolidating temporary state storage into a single service.

5. **Built-in TTL**: DynamoDB's native TTL support eliminates the need for manual key expiration management.

6. **Flexible Querying**: The composite sort key structure allows efficient querying of all counts for a user across different journey types and count types.

### Negative

1. **Migration Complexity**: Requires careful coordination to migrate existing data and ensure no counts are lost during the transition.

2. **Latency**: DynamoDB may have slightly higher latency compared to Redis for single-item operations, though this should be mitigated by using strongly consistent reads where necessary.

3. **Cost Structure Change**: While potentially more cost-effective overall, the cost structure changes from Redis's memory-based pricing to DynamoDB's request-based pricing.

4. **Data Model Complexity**: The need to support multiple count types and notification types increases the complexity of the data model.

## Options Considered

### Option 1: Single DynamoDB Table (Selected)

Use a single DynamoDB table with the design pattern from ADR-0002, extending it to handle all error counts and temporary state.

**Pros:**
- Consistent with existing pattern
- Simplified operations and maintenance
- Single source of truth for all temporary state
- Efficient querying of all counts for a user
- Flexible schema that can accommodate new count types

**Cons:**
- Slightly higher latency than Redis for single operations
- Requires careful migration planning
- More complex data model

### Option 2: Multiple DynamoDB Tables

Create separate DynamoDB tables for different types of counts (MFA, password, email) and locks.

**Pros:**
- Clear separation of concerns
- Potentially simpler queries for specific count types
- Simpler data models per table

**Cons:**
- Increased operational complexity
- Higher costs from multiple tables
- Inconsistent with existing pattern
- More complex migration
- Harder to query across different count types

### Option 3: Hybrid Approach

Keep some high-frequency counts in Redis while migrating others to DynamoDB.

**Pros:**
- Minimal impact on high-frequency operations
- Gradual migration possible
- Can optimize for specific use cases

**Cons:**
- Increased system complexity
- Multiple data stores to maintain
- Inconsistent patterns
- Higher operational overhead
- More complex application logic

## Implementation Notes

1. The migration should be done in phases:
    - Phase 1: Create new DynamoDB table and implement new service
    - Phase 2: Dual-write to both Redis and DynamoDB
    - Phase 3: Read from DynamoDB, fallback to Redis
    - Phase 4: Remove Redis writes
    - Phase 5: Remove Redis reads and cleanup

2. Use DynamoDB's atomic increment operations for count updates:
   ```java
   UpdateItemRequest request = new UpdateItemRequest()
       .withTableName(tableName)
       .withKey(key)
       .withUpdateExpression("SET #count = #count + :incr, #last_updated = :now")
       .withExpressionAttributeNames(Map.of("#count", "count", "#last_updated", "last_updated"))
       .withExpressionAttributeValues(Map.of(":incr", 1, ":now", currentTimestamp));
   ```

3. Implement TTL using DynamoDB's native TTL feature:
   ```java
   // Set TTL to current time + lockout duration
   long ttl = System.currentTimeMillis() / 1000 + lockoutDuration;
   ```

4. Use strongly consistent reads where necessary:
   ```java
   GetItemRequest request = new GetItemRequest()
       .withTableName(tableName)
       .withKey(key)
       .withConsistentRead(true);
   ```

5. Handle different count types and notification types:
   ```java
   String sortKey = String.format("%s#%s#%s", 
       journeyType.getValue(),
       countType.getValue(),
       notificationType != null ? notificationType.getValue() : "GENERAL");
   ```

6. Support for MFA method types:
   ```java
   if (mfaMethodType != null) {
       request.withExpressionAttributeNames(Map.of(
           "#count", "count",
           "#last_updated", "last_updated",
           "#mfa_method", "mfa_method_type"
       ));
       request.withExpressionAttributeValues(Map.of(
           ":incr", 1,
           ":now", currentTimestamp,
           ":mfa_method", mfaMethodType.getValue()
       ));
   }
   ``` 
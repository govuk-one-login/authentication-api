# Re-authentication error counts table design

## Context

We are changing our architecture to use DynamoDB in preference to Elasticache (redis). For the re-authentication feature that means designing a new DynamoDB table to hold information about failed attempts to enter a valid credential (email, password, MFA security code).

This ADR simply records the decision we made and does not record alternatives that we considered.

## Decision

The table uses the subject ID for the Partition Key (PK) to uniquely identify the Items for a User. The table has a structured Sort Key (SK) to support efficient and flexible access. The SK consists of three values: a Journey Type, a classifier type and a classifier.

Journey Type identifies what the User was doing when they performed an aciton of interest, for example entering an incorrect password. Initially the Journey Type will always be REAUTHENTICATION until new journeys are introduced.

The classifier type identifies the type of data in the Attributes, for example an error count

The classifier identifies the specific class of the data in the Attributes, for example email entry.

Example Items:

| PK                | SK                                               | Attributes |
| ----------------- | ------------------------------------------------ | ---------- |
| subject-id-user-a | REAUTHENTICATION#ERROR_COUNT#EMAIL_ENTRY         | 1          |
| subject-id-user-a | REAUTHENTICATION#ERROR_COUNT#PASSWORD_ENTRY      | 2          |
| subject-id-user-a | REAUTHENTICATION#ERROR_COUNT#SECURITY_CODE_ENTRY | 3          |

## Consequences

The design aligns with several best practices in DynamoDB, including using composite sort keys for multiple event types, minimal attribute storage, avoiding hotspots, and leveraging TTL for stale data. These practices will help the table scale efficiently while maintaining cost and performance benefits.

The design is flexible to allow expansion of the type of data stored.

## Options Considered

This ADR is a retrospective record of the decision we made so only the approach we selected is detailed.

### Single DynamoDB table with composite Sort Key

There are several best practices and design patterns for storing count-based data in DynamoDB. Following are the principal reasons for this design.

#### 1. Composite Sort Keys for Scalability

Using composite sort keys (like `attempt_type#classifier_type#classifier`) is a well-recognized design pattern in DynamoDB. This can organize multiple types of data (attempts, locks, counts) under the same user (partition key), ensuring that queries are efficient and scalable.

**Reference**: [AWS Best Practices for Designing DynamoDB Tables](https://aws.amazon.com/blogs/database/choosing-the-right-dynamodb-partition-key/) highlights the importance of composite sort keys for efficiently querying structured data.

#### 2. Composite Sort Keys for Flexibility

Using a structured SK provides a flexible solution that allows new Journey types and classifiers to be added. For example to add a new classifier type for lockouts:

| PK                | SK                                 | Attributes |
| ----------------- | ---------------------------------- | ---------- |
| subject-id-user-a | AUTHENTICATION#LOCK#SIGN_IN        | 1          |
| subject-id-user-a | AUTHENTICATION#LOCK#PASSWORD_RESET | 0          |

Here the user is locked out of the sign-in journey but not the password reset journey.

#### 3. Efficient Usage of Attributes

In DynamoDB, having a minimal number of attributes is a good practice for both performance and cost efficiency. Storing only what you need reduces overhead in terms of both read and write throughput, which is essential in high-traffic systems like authentication tracking.

##### Best Practice Example:

**Single Attribute for State**: Storing a single attribute (`value`) for counts based on the context provided by the sort key is efficient, as DynamoDB pricing is based on storage and request units. This pattern is often used in event-based systems like logs and user activity tracking.

**Reference**: [AWS DynamoDB Single Table Design](https://www.alexdebrie.com/posts/dynamodb-single-table/) explains the use of fewer attributes and composite keys to manage different entity types in one table.

#### 4. Using Partition and Sort Keys to Avoid Hotspots

Partition keys like `subject_id` ensure that each user's data is distributed evenly across DynamoDB partitions. Coupling this with a meaningful sort key (like `attempt_type#classifier_type#classifier`) allows us to store multiple related items for each User without creating a "hotspot" on a single partition, which is crucial for performance in large-scale systems.

##### Best Practice Example:

**Avoiding Hotspots**: By distributing data with a combination of partition and sort keys, DynamoDB can scale horizontally. This is especially important when storing many types of authentication attempts, and helps in avoiding hotspots during high traffic events like mass re-authentications.

**Reference**: [AWS Best Practices for DynamoDB](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/bp-partition-key-design.html) explains how to avoid partition key hotspots.

#### 5. Time-to-Live (TTL) for Expiring Data

For tables that track temporary states (like failed authentication attempts), enabling TTL (Time-to-Live) is a recommended best practice. TTL automatically deletes items after a set period, ensuring that your table doesn’t grow indefinitely with old authentication attempts, which are no longer relevant.

##### Best Practice Example:

**TTL for Expiring Events**: For temporary locks or failed attempts, using TTL ensures that your table remains clean and efficient. This is ideal for managing data that becomes irrelevant after a set time (e.g., unlock a user after 24 hours).

**Reference**: [Using DynamoDB TTL for Automatic Expiry](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/TTL.html) is a best practice for expiring stale data, improving cost-efficiency.

#### 6. Single Table Design

Storing multiple types of events or activities (e.g., sign-ins, credential changes) in a single table by leveraging partition keys and sort keys is a recommended approach. This simplifies the data model and ensures scalability while avoiding multiple tables for each event type.

##### Best Practice Example:

**Single Table Design for Different Event Types**: Instead of creating separate tables for each event type (sign-in, reauthentication, etc.), we can use a single table with a composite sort key to differentiate between event types. This is a best practice for keeping your DynamoDB architecture simple and scalable.

**Reference**: [Single Table Design in DynamoDB](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/bp-modeling-nosql-B.html) shows how to use a single table to store multiple types of related data.

# Method Management Point In Time (PIT) Migration

## Context

In order to store multiple MFA methods with different related data it is necessary to migrate away from storing information in user-profile and move all data to dedicated fields in user-credentials.

This change in data storage means that users will be subject to a point-in-time (PIT) migration when they add a new MFA method.

There has been analysis performed on users with incomplete/invalid MFA profiles [1] and this ADR describes the action that will be taken when these profiles are to be migrated when a user adds a new MFA method.

An incomplete/invalid profile is one that requires the user to complete an MFA set up before being able to log in with One Login. None of the data present in the data stores is presented to the user in this circumstance.

[1]: https://docs.google.com/spreadsheets/d/1XQrEHsEeYeX0qxtrQkTTgEaHByYQWCc5cck7yhcnxXY/edit?gid=0#gid=0

## Decision

Delete invalid / orphaned data when migrating users (option 3)

## Options

### Option 1 - do nothing (discounted)

Create a new MFA method in the updated format but leave the existing method in place.

#### Pros

- Provides a functional account

#### Cons

- Leaves old orphaned data in place

### Option 2 - retain orphaned MFA method (discounted)

Both the user's new MFA method and the orphaned method will be added to the user-credentials store as MFA methods in the updated format.

#### Pros

- No data loss

#### Cons

- Migrated MFA method is not valid
- May no longer be in possession of the user

### Option 3 - delete orphaned MFA method (chosen)

When adding the new MFA method, clean up the orphaned data to remove all information associated with it.

#### Pros

- Cleans the data store
- Removes data that may no longer relate to the user

#### Cons

- More complex to implement safely

### Consequences

Invalid data will be removed from the user-profile and user-credential stores when a user adds a new MFA method.
This approach will also be taken for the post-go-live operation to bulk-migrate users who have not modified their MFA methods since launch.

# Prefer Result Return Type Over Exceptions

When implementing domain business logic, prefer returning a `Result<F, S>` type instead of throwing exceptions.

```java
// BAD
public User findUserById(String id) throws UserNotFoundException {
    User user = repository.findById(id);
    if (user == null) {
        throw new UserNotFoundException("User not found with id: " + id);
    }
    return user;
}

// GOOD
public Result<String, User> findUserById(String id) {
    User user = repository.findById(id);
    if (user == null) {
        return Result.failure("User not found with id: " + id);
    }
    return Result.success(user);
}
```

Using the `Result` type provides several benefits:

- Makes error handling explicit in the method signature
- Forces callers to handle both success and failure cases
- Enables functional composition with `map`, `flatMap`, and `mapFailure`
- Improves testability by avoiding exception-based control flow
- Separates domain errors from unexpected technical exceptions

Reserve exceptions for truly exceptional conditions that indicate bugs or system failures, not for expected domain outcomes like "user not found" or "validation failed".
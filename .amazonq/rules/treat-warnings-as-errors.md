# Treat Compiler Warnings as Errors

All code must compile without warnings. The project is configured with `-Werror` which treats all compiler warnings as errors.

```java
// BAD - Using deprecated API
@Deprecated
public void oldMethod() {
    // implementation
}

public void caller() {
    oldMethod(); // This will fail the build
}

// GOOD - Using current API or suppressing with justification
public void caller() {
    newMethod();
}

// Only when absolutely necessary
@SuppressWarnings("deprecation")
public void legacySupport() {
    // Clear comment explaining why this can't be updated
    oldMethod();
}
```

Pay special attention to:
- Deprecation warnings
- Unchecked type conversions
- Unused imports, variables, or methods
- Resource leaks
# Use Google Java Format (AOSP Style)

All Java code must follow the Google Java Format with AOSP style. The project uses Spotless to enforce this.

```java
// BAD - Incorrect formatting
public class BadlyFormattedClass {
    public void badMethod(){
        if(condition) {
            doSomething();
        }
        else{
            doSomethingElse();
        }
    }
}

// GOOD - Correct AOSP style formatting
public class WellFormattedClass {
    public void goodMethod() {
        if (condition) {
            doSomething();
        } else {
            doSomethingElse();
        }
    }
}
```

Key formatting rules:
- Use 4 spaces for indentation (not tabs)
- No line breaks before opening braces
- Line breaks after opening braces and before closing braces
- Spaces around operators and after commas
# No Wildcard Imports

Always use explicit imports instead of wildcard imports.

```java
// BAD
import java.util.*;

// GOOD
import java.util.List;
import java.util.Map;
import java.util.Optional;
```

Wildcard imports should be avoided because they:

- Make it unclear which classes are actually being used
- Can lead to naming conflicts
- Present security risks by potentially importing vulnerable or untrusted classes without explicit developer awareness
- Can mask issues with shaded dependencies, where the wrong version of a class might be imported silently
- Make refactoring and maintenance more difficult
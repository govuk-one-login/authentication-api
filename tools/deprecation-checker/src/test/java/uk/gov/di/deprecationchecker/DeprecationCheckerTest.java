package uk.gov.di.deprecationchecker;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class DeprecationCheckerTest {

    @TempDir Path tempDir;

    @Test
    void shouldDetectRemovedEnumConstantWithoutDeprecation() throws Exception {
        String oldContent =
                """
            package com.example;
            public enum TestEnum {
                CONSTANT_A,
                CONSTANT_B,
                CONSTANT_C
            }
            """;

        String newContent =
                """
            package com.example;
            public enum TestEnum {
                CONSTANT_A,
                CONSTANT_C
            }
            """;

        List<String> violations =
                DeprecationChecker.checkEnumRemovals(
                        "TestEnum.java", oldContent, newContent, Set.of("com.example.TestEnum"));

        assertEquals(1, violations.size());
        assertTrue(violations.get(0).contains("CONSTANT_B"));
        assertTrue(violations.get(0).contains("was removed without being @Deprecated first"));
    }

    @Test
    void shouldAllowRemovedEnumConstantWithDeprecation() throws Exception {
        String oldContent =
                """
            package com.example;
            public enum TestEnum {
                CONSTANT_A,
                @Deprecated
                CONSTANT_B,
                CONSTANT_C
            }
            """;

        String newContent =
                """
            package com.example;
            public enum TestEnum {
                CONSTANT_A,
                CONSTANT_C
            }
            """;

        List<String> violations =
                DeprecationChecker.checkEnumRemovals(
                        "TestEnum.java", oldContent, newContent, Set.of("com.example.TestEnum"));

        assertEquals(0, violations.size());
    }

    @Test
    void shouldIgnoreEnumsNotInTargetList() throws Exception {
        String oldContent =
                """
            package com.example;
            public enum TestEnum {
                CONSTANT_A,
                CONSTANT_B
            }
            """;

        String newContent =
                """
            package com.example;
            public enum TestEnum {
                CONSTANT_A
            }
            """;

        List<String> violations =
                DeprecationChecker.checkEnumRemovals(
                        "TestEnum.java", oldContent, newContent, Set.of("com.other.DifferentEnum"));

        assertEquals(0, violations.size());
    }

    @Test
    void shouldCheckAllEnumsWhenTargetListEmpty() throws Exception {
        String oldContent =
                """
            package com.example;
            public enum TestEnum {
                CONSTANT_A,
                CONSTANT_B
            }
            """;

        String newContent =
                """
            package com.example;
            public enum TestEnum {
                CONSTANT_A
            }
            """;

        List<String> violations =
                DeprecationChecker.checkEnumRemovals(
                        "TestEnum.java", oldContent, newContent, Set.of());

        assertEquals(1, violations.size());
        assertTrue(violations.get(0).contains("CONSTANT_B"));
    }

    @Test
    void shouldHandleMultipleRemovedConstants() throws Exception {
        String oldContent =
                """
            package com.example;
            public enum TestEnum {
                CONSTANT_A,
                CONSTANT_B,
                CONSTANT_C,
                CONSTANT_D
            }
            """;

        String newContent =
                """
            package com.example;
            public enum TestEnum {
                CONSTANT_A,
                CONSTANT_D
            }
            """;

        List<String> violations =
                DeprecationChecker.checkEnumRemovals(
                        "TestEnum.java", oldContent, newContent, Set.of("com.example.TestEnum"));

        assertEquals(2, violations.size());
        assertTrue(violations.stream().anyMatch(v -> v.contains("CONSTANT_B")));
        assertTrue(violations.stream().anyMatch(v -> v.contains("CONSTANT_C")));
    }

    @Test
    void shouldHandleMultipleEnumsInSameFile() throws Exception {
        String oldContent =
                """
            package com.example;
            public enum FirstEnum {
                FIRST_A,
                FIRST_B
            }
            enum SecondEnum {
                SECOND_A,
                SECOND_B
            }
            """;

        String newContent =
                """
            package com.example;
            public enum FirstEnum {
                FIRST_A
            }
            enum SecondEnum {
                SECOND_A
            }
            """;

        List<String> violations =
                DeprecationChecker.checkEnumRemovals(
                        "TestEnum.java", oldContent, newContent, Set.of("com.example.FirstEnum"));

        assertEquals(1, violations.size());
        assertTrue(violations.get(0).contains("FIRST_B"));
        assertFalse(violations.get(0).contains("SECOND_B"));
    }

    @Test
    void shouldHandleInvalidJavaCode() throws Exception {
        String oldContent = "invalid java code";
        String newContent = "also invalid";

        List<String> violations =
                DeprecationChecker.checkEnumRemovals(
                        "TestEnum.java", oldContent, newContent, Set.of());

        assertEquals(0, violations.size());
    }

    @Test
    void shouldHandleEmptyPackage() throws Exception {
        String oldContent =
                """
            public enum TestEnum {
                CONSTANT_A,
                CONSTANT_B
            }
            """;

        String newContent =
                """
            public enum TestEnum {
                CONSTANT_A
            }
            """;

        List<String> violations =
                DeprecationChecker.checkEnumRemovals(
                        "TestEnum.java", oldContent, newContent, Set.of(".TestEnum"));

        assertEquals(1, violations.size());
        assertTrue(violations.get(0).contains("CONSTANT_B"));
    }

    @Test
    void shouldIgnoreAddedConstants() throws Exception {
        String oldContent =
                """
            package com.example;
            public enum TestEnum {
                CONSTANT_A
            }
            """;

        String newContent =
                """
            package com.example;
            public enum TestEnum {
                CONSTANT_A,
                CONSTANT_B,
                CONSTANT_C
            }
            """;

        List<String> violations =
                DeprecationChecker.checkEnumRemovals(
                        "TestEnum.java", oldContent, newContent, Set.of("com.example.TestEnum"));

        assertEquals(0, violations.size());
    }
}

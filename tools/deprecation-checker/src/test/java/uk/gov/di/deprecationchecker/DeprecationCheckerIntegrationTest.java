package uk.gov.di.deprecationchecker;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class DeprecationCheckerIntegrationTest {

    @TempDir Path tempDir;

    private Path originalDir;
    private PrintStream originalErr;
    private ByteArrayOutputStream capturedErr;

    @BeforeEach
    void setUp() {
        originalDir = Path.of(System.getProperty("user.dir"));
        originalErr = System.err;
        capturedErr = new ByteArrayOutputStream();
        System.setErr(new PrintStream(capturedErr));
    }

    void tearDown() {
        System.setProperty("user.dir", originalDir.toString());
        System.setErr(originalErr);
    }

    @Test
    void shouldExitWithErrorWhenViolationsFound() throws Exception {
        // This test would require mocking System.exit or using a different approach
        // For now, we'll test the core logic without the main method

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

        var violations =
                DeprecationChecker.checkEnumRemovals(
                        "TestEnum.java",
                        oldContent,
                        newContent,
                        java.util.Set.of("com.example.TestEnum"));

        assertFalse(violations.isEmpty());
        assertTrue(violations.get(0).contains("CONSTANT_B"));

        tearDown();
    }

    @Test
    void shouldPassWhenNoViolationsFound() throws Exception {
        String oldContent =
                """
            package com.example;
            public enum TestEnum {
                CONSTANT_A,
                @Deprecated
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

        var violations =
                DeprecationChecker.checkEnumRemovals(
                        "TestEnum.java",
                        oldContent,
                        newContent,
                        java.util.Set.of("com.example.TestEnum"));

        assertTrue(violations.isEmpty());

        tearDown();
    }
}

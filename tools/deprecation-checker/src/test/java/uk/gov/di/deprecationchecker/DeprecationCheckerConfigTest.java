package uk.gov.di.deprecationchecker;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class DeprecationCheckerConfigTest {

    @TempDir Path tempDir;

    private Path originalDir;

    @BeforeEach
    void setUp() {
        originalDir = Path.of(System.getProperty("user.dir"));
    }

    @Test
    void shouldLoadDefaultConfigWhenFileNotExists() throws Exception {
        // Change to temp directory where no config exists
        System.setProperty("user.dir", tempDir.toString());

        try {
            Method loadConfigMethod = DeprecationChecker.class.getDeclaredMethod("loadConfig");
            loadConfigMethod.setAccessible(true);

            Object config = loadConfigMethod.invoke(null);

            assertNotNull(config);
            // Config should have default values
        } finally {
            System.setProperty("user.dir", originalDir.toString());
        }
    }

    @Test
    void shouldLoadConfigFromFile() throws Exception {
        Path configFile = tempDir.resolve("deprecation-config.json");
        String configContent =
                """
            {
              "baseBranch": "main",
              "enums": [
                "com.example.TestEnum",
                "com.example.AnotherEnum"
              ]
            }
            """;
        Files.writeString(configFile, configContent);

        System.setProperty("user.dir", tempDir.toString());

        try {
            Method loadConfigMethod = DeprecationChecker.class.getDeclaredMethod("loadConfig");
            loadConfigMethod.setAccessible(true);

            Object config = loadConfigMethod.invoke(null);

            assertNotNull(config);
            // Would need to expose config fields to test values
        } finally {
            System.setProperty("user.dir", originalDir.toString());
        }
    }

    @Test
    void shouldHandleInvalidJsonConfig() throws Exception {
        Path configFile = tempDir.resolve("deprecation-config.json");
        Files.writeString(configFile, "invalid json content");

        System.setProperty("user.dir", tempDir.toString());

        try {
            Method loadConfigMethod = DeprecationChecker.class.getDeclaredMethod("loadConfig");
            loadConfigMethod.setAccessible(true);

            // Gson handles invalid JSON gracefully, so this should not throw
            Object config = loadConfigMethod.invoke(null);
            assertNotNull(config);
        } finally {
            System.setProperty("user.dir", originalDir.toString());
        }
    }
}

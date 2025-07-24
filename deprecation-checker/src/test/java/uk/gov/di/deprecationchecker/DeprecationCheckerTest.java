package uk.gov.di.deprecationchecker;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class DeprecationCheckerTest {

    @Nested
    class LoadConfig {
        @Test
        void shouldLoadDefaultConfigWhenFileNotExists(@TempDir Path tempDir) throws IOException {
            String originalDir = System.getProperty("user.dir");
            try {
                System.setProperty("user.dir", tempDir.toString());

                var config = DeprecationChecker.loadConfig();

                assertEquals("origin/main", config.baseBranch);
                assertTrue(config.enums.isEmpty());
            } finally {
                System.setProperty("user.dir", originalDir);
            }
        }

        @Test
        void shouldLoadConfigFromFile(@TempDir Path tempDir) throws IOException {
            String originalDir = System.getProperty("user.dir");
            try {
                Path configFile = tempDir.resolve("deprecation-config.json");
                Files.writeString(
                        configFile,
                        """
                    {
                        "baseBranch": "origin/develop",
                        "enums": ["com.example.TestEnum"]
                    }
                    """);

                System.setProperty("user.dir", tempDir.toString());

                var config = DeprecationChecker.loadConfig();

                assertEquals("origin/develop", config.baseBranch);
                assertEquals(Set.of("com.example.TestEnum"), config.enums);
            } finally {
                System.setProperty("user.dir", originalDir);
            }
        }

        @Test
        void shouldLoadConfigWithNullBaseBranch(@TempDir Path tempDir) throws IOException {
            String originalDir = System.getProperty("user.dir");
            try {
                Path configFile = tempDir.resolve("deprecation-config.json");
                Files.writeString(configFile, "{\"enums\": [\"test\"]}");
                System.setProperty("user.dir", tempDir.toString());

                var config = DeprecationChecker.loadConfig();

                assertEquals("origin/main", config.baseBranch);
            } finally {
                System.setProperty("user.dir", originalDir);
            }
        }

        @Test
        void shouldLoadConfigWithNullEnums(@TempDir Path tempDir) throws IOException {
            String originalDir = System.getProperty("user.dir");
            try {
                Path configFile = tempDir.resolve("deprecation-config.json");
                Files.writeString(configFile, "{\"baseBranch\": \"test\"}");
                System.setProperty("user.dir", tempDir.toString());

                var config = DeprecationChecker.loadConfig();

                assertTrue(config.enums.isEmpty());
            } finally {
                System.setProperty("user.dir", originalDir);
            }
        }
    }
}

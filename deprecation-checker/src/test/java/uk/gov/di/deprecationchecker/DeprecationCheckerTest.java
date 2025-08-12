package uk.gov.di.deprecationchecker;

import org.eclipse.jgit.lib.ObjectId;
import org.eclipse.jgit.lib.ObjectLoader;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.revwalk.RevCommit;
import org.eclipse.jgit.revwalk.RevTree;
import org.eclipse.jgit.revwalk.RevWalk;
import org.eclipse.jgit.storage.file.FileRepositoryBuilder;
import org.eclipse.jgit.treewalk.TreeWalk;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

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
                assertTrue(config.enumFiles.isEmpty());
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
                        "enumFiles": ["src/TestEnum.java"]
                    }
                    """);

                System.setProperty("user.dir", tempDir.toString());

                var config = DeprecationChecker.loadConfig();

                assertEquals("origin/develop", config.baseBranch);
                assertEquals(Set.of("src/TestEnum.java"), config.enumFiles);
            } finally {
                System.setProperty("user.dir", originalDir);
            }
        }

        @Test
        void shouldLoadConfigWithNullBaseBranch(@TempDir Path tempDir) throws IOException {
            String originalDir = System.getProperty("user.dir");
            try {
                Path configFile = tempDir.resolve("deprecation-config.json");
                Files.writeString(configFile, "{\"enumFiles\": [\"test.java\"]}");
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

                assertTrue(config.enumFiles.isEmpty());
            } finally {
                System.setProperty("user.dir", originalDir);
            }
        }
    }

    @Nested
    class PerformCheck {
        @Test
        void shouldReturnEmptyListWhenBaseBranchNotFound() throws Exception {
            var config =
                    new DeprecationChecker.Config("nonexistent-branch", Set.of("TestEnum.java"));

            var violations = DeprecationChecker.performCheck(config);

            assertTrue(violations.isEmpty());
        }

        @Test
        void shouldCallCheckEnumRemovalsAndReturnViolations() throws Exception {
            var config = new DeprecationChecker.Config("origin/main", Set.of("TestEnum.java"));

            try (MockedStatic<DeprecationChecker> mockStatic =
                            mockStatic(DeprecationChecker.class, Mockito.CALLS_REAL_METHODS);
                    MockedConstruction<FileRepositoryBuilder> mockRepoBuilder =
                            mockConstruction(
                                    FileRepositoryBuilder.class,
                                    (mock, context) -> {
                                        Repository mockRepo = mock(Repository.class);
                                        ObjectId mockCommitId =
                                                ObjectId.fromString(
                                                        "1234567890123456789012345678901234567890");
                                        when(mock.setWorkTree(any())).thenReturn(mock);
                                        when(mock.readEnvironment()).thenReturn(mock);
                                        when(mock.findGitDir()).thenReturn(mock);
                                        when(mock.build()).thenReturn(mockRepo);
                                        when(mockRepo.resolve("origin/main"))
                                                .thenReturn(mockCommitId);
                                    })) {

                mockStatic
                        .when(
                                () ->
                                        DeprecationChecker.getCommitedFileContent(
                                                any(), any(), eq("TestEnum.java")))
                        .thenReturn("old content");
                mockStatic
                        .when(() -> DeprecationChecker.getWorkspaceFileContent("TestEnum.java"))
                        .thenReturn("new content");
                mockStatic
                        .when(
                                () ->
                                        DeprecationChecker.checkEnumRemovals(
                                                "TestEnum.java", "old content", "new content"))
                        .thenReturn(java.util.List.of("violation found"));

                var violations = DeprecationChecker.performCheck(config);

                assertEquals(1, violations.size());
                assertEquals("violation found", violations.get(0));
            }
        }
    }

    @Nested
    class GetWorkspaceFileContent {
        @Test
        void shouldReadFileContent(@TempDir Path tempDir) throws IOException {
            Path testFile = tempDir.resolve("test.java");
            Files.writeString(testFile, "public class Test {}");

            String content = DeprecationChecker.getWorkspaceFileContent(testFile.toString());

            assertEquals("public class Test {}", content);
        }
    }

    @Nested
    class GetCommitedFileContent {
        @Test
        void shouldReturnFileContentFromCommit() throws Exception {
            Repository mockRepo = mock(Repository.class);
            ObjectId mockCommitId = ObjectId.fromString("1234567890123456789012345678901234567890");
            RevCommit mockCommit = mock(RevCommit.class);
            RevTree mockTree = mock(RevTree.class);
            ObjectId mockFileId = ObjectId.fromString("fedcba0987654321098765432109876543210987");
            ObjectLoader mockLoader = mock(ObjectLoader.class);

            when(mockCommit.getTree()).thenReturn(mockTree);
            when(mockLoader.getBytes())
                    .thenReturn("class Test {}".getBytes(StandardCharsets.UTF_8));
            when(mockRepo.open(mockFileId)).thenReturn(mockLoader);

            try (MockedConstruction<RevWalk> mockRevWalkConstruction =
                            mockConstruction(
                                    RevWalk.class,
                                    (mock, context) -> {
                                        when(mock.parseCommit(mockCommitId)).thenReturn(mockCommit);
                                    });
                    MockedConstruction<TreeWalk> mockTreeWalkConstruction =
                            mockConstruction(
                                    TreeWalk.class,
                                    (mock, context) -> {
                                        when(mock.next()).thenReturn(true);
                                        when(mock.getObjectId(0)).thenReturn(mockFileId);
                                    })) {

                String content =
                        DeprecationChecker.getCommitedFileContent(
                                mockRepo, mockCommitId, "test.java");

                assertEquals("class Test {}", content);
            }
        }

        @Test
        void shouldReturnEmptyWhenFileNotFound() {
            Repository mockRepo = mock(Repository.class);
            ObjectId mockCommitId = ObjectId.fromString("1234567890123456789012345678901234567890");
            RevCommit mockCommit = mock(RevCommit.class);
            RevTree mockTree = mock(RevTree.class);

            when(mockCommit.getTree()).thenReturn(mockTree);

            try (MockedConstruction<RevWalk> mockRevWalkConstruction =
                            mockConstruction(
                                    RevWalk.class,
                                    (mock, context) -> {
                                        when(mock.parseCommit(mockCommitId)).thenReturn(mockCommit);
                                    });
                    MockedConstruction<TreeWalk> mockTreeWalkConstruction =
                            mockConstruction(
                                    TreeWalk.class,
                                    (mock, context) -> {
                                        when(mock.next()).thenReturn(false);
                                    })) {

                String content =
                        DeprecationChecker.getCommitedFileContent(
                                mockRepo, mockCommitId, "nonexistent.java");

                assertEquals("", content);
            }
        }
    }

    @Nested
    class CheckEnumRemovals {
        @Test
        void shouldAllowRemovalOfDeprecatedEnumConstant() {
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

            List<String> violations =
                    DeprecationChecker.checkEnumRemovals("TestEnum.java", oldContent, newContent);

            assertTrue(violations.isEmpty());
        }

        @Test
        void shouldDetectViolationWhenRemovingNonDeprecatedConstant() {
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
                    DeprecationChecker.checkEnumRemovals("TestEnum.java", oldContent, newContent);

            assertEquals(1, violations.size());
            assertTrue(violations.get(0).contains("CONSTANT_B"));
        }

        @Test
        void shouldReturnEmptyWhenOldContentUnparseable() {
            List<String> violations =
                    DeprecationChecker.checkEnumRemovals(
                            "TestEnum.java", "invalid java", "public enum Test {}");

            assertTrue(violations.isEmpty());
        }

        @Test
        void shouldReturnEmptyWhenNewContentUnparseable() {
            List<String> violations =
                    DeprecationChecker.checkEnumRemovals(
                            "TestEnum.java", "public enum Test {}", "invalid java");

            assertTrue(violations.isEmpty());
        }

        @Test
        void shouldHandleEnumRemovedEntirely() {
            String oldContent =
                    """
                package com.example;
                public enum TestEnum {
                    CONSTANT_A
                }
                """;

            String newContent = "package com.example;";

            List<String> violations =
                    DeprecationChecker.checkEnumRemovals("TestEnum.java", oldContent, newContent);

            assertTrue(violations.isEmpty());
        }
    }

    @Nested
    class IsDeprecated {
        @Test
        void shouldDetectDeprecatedAnnotation() {
            String javaCode =
                    """
                public enum TestEnum {
                    @Deprecated
                    DEPRECATED_CONSTANT
                }
                """;

            com.github.javaparser.JavaParser parser = new com.github.javaparser.JavaParser();
            var unit = parser.parse(javaCode).getResult().orElseThrow();
            var enumDecl =
                    unit.findAll(com.github.javaparser.ast.body.EnumDeclaration.class).get(0);
            var constant = enumDecl.getEntries().get(0);

            assertTrue(DeprecationChecker.isDeprecated(constant));
        }
    }
}

package uk.gov.di.deprecationchecker;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.EnumConstantDeclaration;
import com.github.javaparser.ast.body.EnumDeclaration;
import com.google.gson.Gson;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.lib.ObjectId;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.revwalk.RevCommit;
import org.eclipse.jgit.revwalk.RevWalk;
import org.eclipse.jgit.revwalk.filter.RevFilter;
import org.eclipse.jgit.storage.file.FileRepositoryBuilder;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;

public class DeprecationChecker {

    private static final Logger LOG = LogManager.getLogger(DeprecationChecker.class);

    public static void main(String[] args) {
        try {
            Config config = loadConfig();
            List<String> violations = performCheck(config);

            if (!violations.isEmpty()) {
                var message =
                        "Deprecation policy violations found (these must be marked as @Deprecated in {} before removing):\n -"
                                + String.join("\n -", violations);
                LOG.error(message, config.baseBranch);
                System.exit(1);
            }

            LOG.info("No deprecation policy violations found.");
        } catch (Exception e) {
            LOG.error("Error during deprecation check", e);
            System.exit(1);
        }
    }

    static Config loadConfig() throws IOException {
        var configPath = Paths.get(System.getProperty("user.dir"), "deprecation-config.json");

        if (!Files.exists(configPath)) {
            LOG.info("No config file found, using defaults");
            return new Config("origin/main", Set.of());
        }

        String json = Files.readString(configPath);
        com.google.gson.Gson gson = new Gson();
        ConfigJson configJson = gson.fromJson(json, ConfigJson.class);

        String baseBranch = configJson.baseBranch != null ? configJson.baseBranch : "origin/main";
        Set<String> enumFiles =
                configJson.enumFiles != null ? Set.copyOf(configJson.enumFiles) : Set.of();

        return new Config(baseBranch, enumFiles);
    }

    static List<String> performCheck(Config config) throws IOException {
        Repository repository =
                new FileRepositoryBuilder()
                        .setWorkTree(new File("."))
                        .readEnvironment()
                        .findGitDir()
                        .build();

        try (Git git = new Git(repository)) {
            ObjectId mainId = repository.resolve(config.baseBranch);
            if (mainId == null) {
                mainId = repository.resolve("refs/remotes/origin/" + config.baseBranch);
            }
            if (mainId == null) {
                return new ArrayList<>();
            }

            ObjectId headId = repository.resolve("HEAD");
            ObjectId mergeBase = findMergeBase(repository, headId, mainId);
            if (mergeBase != null) {
                mainId = mergeBase;
            }

            List<String> violations = new ArrayList<>();

            for (String filePath : config.enumFiles) {
                String oldContent = getCommitedFileContent(repository, mainId, filePath);
                String newContent = getWorkspaceFileContent(filePath);

                violations.addAll(checkEnumRemovals(filePath, oldContent, newContent));
            }

            return violations;
        }
    }

    static String getWorkspaceFileContent(String path) throws IOException {
        return Files.readString(Paths.get(path));
    }

    static String getCommitedFileContent(Repository repository, ObjectId commitId, String path) {
        try (RevWalk walk = new RevWalk(repository)) {
            RevCommit commit = walk.parseCommit(commitId);
            try (org.eclipse.jgit.treewalk.TreeWalk treeWalk =
                    new org.eclipse.jgit.treewalk.TreeWalk(repository)) {
                treeWalk.addTree(commit.getTree());
                treeWalk.setRecursive(true);
                treeWalk.setFilter(org.eclipse.jgit.treewalk.filter.PathFilter.create(path));

                if (treeWalk.next()) {
                    ObjectId fileId = treeWalk.getObjectId(0);
                    return new String(repository.open(fileId).getBytes(), StandardCharsets.UTF_8);
                }
                return "";
            }
        } catch (Exception e) {
            LOG.error("Warning: Could not read file {} from commit: {}", path, e.getMessage());
            return "";
        }
    }

    static List<String> checkEnumRemovals(String filePath, String oldContent, String newContent) {
        List<String> violations = new ArrayList<>();

        if (oldContent.equals(newContent)) {
            return violations;
        }

        try {
            JavaParser parser = new JavaParser();
            Optional<CompilationUnit> oldUnit = parser.parse(oldContent).getResult();
            Optional<CompilationUnit> newUnit = parser.parse(newContent).getResult();

            if (oldUnit.isEmpty() || newUnit.isEmpty()) {
                return violations;
            }

            List<EnumDeclaration> oldEnums = oldUnit.get().findAll(EnumDeclaration.class);
            List<EnumDeclaration> newEnums = newUnit.get().findAll(EnumDeclaration.class);

            for (EnumDeclaration oldEnum : oldEnums) {
                Optional<EnumDeclaration> newEnum =
                        newEnums.stream()
                                .filter(e -> e.getNameAsString().equals(oldEnum.getNameAsString()))
                                .findFirst();

                if (newEnum.isPresent()) {
                    Set<String> oldConstants =
                            oldEnum.getEntries().stream()
                                    .map(EnumConstantDeclaration::getNameAsString)
                                    .collect(Collectors.toSet());
                    Set<String> newConstants =
                            newEnum.get().getEntries().stream()
                                    .map(EnumConstantDeclaration::getNameAsString)
                                    .collect(Collectors.toSet());

                    oldConstants.removeAll(newConstants);
                    for (String removed : oldConstants) {
                        Optional<EnumConstantDeclaration> oldConstant =
                                oldEnum.getEntries().stream()
                                        .filter(e -> e.getNameAsString().equals(removed))
                                        .findFirst();
                        if (oldConstant.isPresent() && !isDeprecated(oldConstant.get())) {
                            violations.add(
                                    String.format(
                                            "  %s: Enum constant '%s' in enum '%s' was removed without being @Deprecated first",
                                            filePath, removed, oldEnum.getNameAsString()));
                        }
                    }
                }
            }
        } catch (Exception e) {
            LOG.error("Warning: Could not parse {}: {}", filePath, e.getMessage());
        }

        return violations;
    }

    static boolean isDeprecated(EnumConstantDeclaration constant) {
        return constant.getAnnotations().stream()
                .anyMatch(annotation -> annotation.getNameAsString().equals("Deprecated"));
    }

    static ObjectId findMergeBase(Repository repository, ObjectId commit1, ObjectId commit2) {
        try (RevWalk walk = new RevWalk(repository)) {
            RevCommit c1 = walk.parseCommit(commit1);
            RevCommit c2 = walk.parseCommit(commit2);
            walk.setRevFilter(RevFilter.MERGE_BASE);
            walk.markStart(c1);
            walk.markStart(c2);
            RevCommit mergeBase = walk.next();
            return mergeBase != null ? mergeBase.getId() : null;
        } catch (Exception e) {
            LOG.error("Could not find merge base: {}", e.getMessage());
            return null;
        }
    }

    static class Config {
        final String baseBranch;
        final Set<String> enumFiles;

        Config(String baseBranch, Set<String> enumFiles) {
            this.baseBranch = baseBranch;
            this.enumFiles = enumFiles;
        }
    }

    private static class ConfigJson {
        String baseBranch;
        java.util.List<String> enumFiles;
    }
}

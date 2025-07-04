import com.github.javaparser.JavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.EnumConstantDeclaration;
import com.github.javaparser.ast.body.EnumDeclaration;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.lib.ObjectId;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.revwalk.RevCommit;
import org.eclipse.jgit.revwalk.RevWalk;
import org.eclipse.jgit.storage.file.FileRepositoryBuilder;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;

public class DeprecationChecker {

    public static void main(String[] args) {
        try {
            Config config = loadConfig();
            List<String> violations = performCheck(config);

            if (!violations.isEmpty()) {
                System.err.println("Deprecation policy violations found:");
                violations.forEach(System.err::println);
                System.exit(1);
            }

            System.out.println("No deprecation policy violations found.");
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static Config loadConfig() throws IOException {
        String configPath = "deprecation-config.json";
        if (!Files.exists(Paths.get(configPath))) {
            return new Config("origin/main", Set.of());
        }
        String json = Files.readString(Paths.get(configPath));

        com.google.gson.Gson gson = new com.google.gson.Gson();
        ConfigJson configJson = gson.fromJson(json, ConfigJson.class);

        String baseBranch = configJson.baseBranch != null ? configJson.baseBranch : "origin/main";
        Set<String> enums = configJson.enums != null ? Set.copyOf(configJson.enums) : Set.of();

        return new Config(baseBranch, enums);
    }

    private static List<String> performCheck(Config config) throws Exception {
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

            List<String> modifiedFiles = getModifiedJavaFiles(repository);
            List<String> violations = new ArrayList<>();

            for (String filePath : modifiedFiles) {
                String oldContent = getFileContent(repository, mainId, filePath);
                String newContent = getWorkspaceFileContent(filePath);

                violations.addAll(
                        checkEnumRemovals(filePath, oldContent, newContent, config.enums));
            }

            return violations;
        }
    }

    private static String getWorkspaceFileContent(String path) throws IOException {
        return Files.readString(Paths.get(path));
    }

    private static List<String> getModifiedJavaFiles(Repository repository) throws IOException {
        try (Git git = new Git(repository)) {
            org.eclipse.jgit.api.Status status = git.status().call();
            List<String> modifiedFiles = new ArrayList<>();

            // Add modified files
            for (String file : status.getModified()) {
                if (file.endsWith(".java")) {
                    modifiedFiles.add(file);
                }
            }

            return modifiedFiles;
        } catch (Exception e) {
            throw new IOException("Failed to get git status", e);
        }
    }

    private static String getFileContent(Repository repository, ObjectId commitId, String path)
            throws IOException {
        try (RevWalk walk = new RevWalk(repository)) {
            RevCommit commit = walk.parseCommit(commitId);
            try (org.eclipse.jgit.treewalk.TreeWalk treeWalk =
                    new org.eclipse.jgit.treewalk.TreeWalk(repository)) {
                treeWalk.addTree(commit.getTree());
                treeWalk.setRecursive(true);
                treeWalk.setFilter(org.eclipse.jgit.treewalk.filter.PathFilter.create(path));

                if (treeWalk.next()) {
                    ObjectId fileId = treeWalk.getObjectId(0);
                    return new String(repository.open(fileId).getBytes());
                }
                return "";
            }
        } catch (Exception e) {
            System.err.println(
                    "Warning: Could not read file " + path + " from commit: " + e.getMessage());
            return "";
        }
    }

    private static List<String> checkEnumRemovals(
            String filePath, String oldContent, String newContent, Set<String> targetEnums) {
        List<String> violations = new ArrayList<>();

        try {
            JavaParser parser = new JavaParser();
            Optional<CompilationUnit> oldUnit = parser.parse(oldContent).getResult();
            Optional<CompilationUnit> newUnit = parser.parse(newContent).getResult();

            if (oldUnit.isEmpty() || newUnit.isEmpty()) {
                return violations;
            }

            String packageName =
                    oldUnit.get()
                            .getPackageDeclaration()
                            .map(pd -> pd.getNameAsString())
                            .orElse("");

            List<EnumDeclaration> oldEnums = oldUnit.get().findAll(EnumDeclaration.class);
            List<EnumDeclaration> newEnums = newUnit.get().findAll(EnumDeclaration.class);

            for (EnumDeclaration oldEnum : oldEnums) {
                String fullEnumName = packageName + "." + oldEnum.getNameAsString();

                if (!targetEnums.isEmpty() && !targetEnums.contains(fullEnumName)) {
                    continue;
                }

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
            System.err.println("Warning: Could not parse " + filePath + ": " + e.getMessage());
        }

        return violations;
    }

    private static boolean isDeprecated(EnumConstantDeclaration constant) {
        return constant.getAnnotations().stream()
                .anyMatch(annotation -> annotation.getNameAsString().equals("Deprecated"));
    }

    private static class Config {
        final String baseBranch;
        final Set<String> enums;

        Config(String baseBranch, Set<String> enums) {
            this.baseBranch = baseBranch;
            this.enums = enums;
        }
    }

    private static class ConfigJson {
        String baseBranch;
        java.util.List<String> enums;
    }
}

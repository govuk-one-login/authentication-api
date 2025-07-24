package uk.gov.di.deprecationchecker;

import com.google.gson.Gson;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.jgit.lib.ObjectId;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.revwalk.RevCommit;
import org.eclipse.jgit.revwalk.RevWalk;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

public class DeprecationChecker {

    private static final Logger LOG = LogManager.getLogger(DeprecationChecker.class);

    public static void main(String[] args) {
        try {
            loadConfig();
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
        Set<String> enums = configJson.enums != null ? Set.copyOf(configJson.enums) : Set.of();

        return new Config(baseBranch, enums);
    }

    static List<String> getAllJavaFiles() throws IOException {
        List<String> javaFiles = new ArrayList<>();
        var workDir = Paths.get(System.getProperty("user.dir"));
        try (var paths = Files.walk(workDir)) {
            paths.filter(path -> path.toString().endsWith(".java"))
                    .filter(path -> !path.toString().contains("/build/"))
                    .filter(path -> !path.toString().contains("/target/"))
                    .filter(path -> !path.toString().contains("/.gradle/"))
                    .map(path -> workDir.relativize(path).toString())
                    .forEach(javaFiles::add);
        }
        return javaFiles;
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

    static class Config {
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

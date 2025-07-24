package uk.gov.di.deprecationchecker;

import com.google.gson.Gson;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
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

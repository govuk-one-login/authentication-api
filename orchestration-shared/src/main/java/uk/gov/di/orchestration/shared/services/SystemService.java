package uk.gov.di.orchestration.shared.services;

public class SystemService {
    public String getenv(String name) {
        return System.getenv(name);
    }

    String getOrDefault(Object key, String defaultValue) {
        return System.getenv().getOrDefault(key, defaultValue);
    }
}

package uk.gov.di.authentication.shared.services;

public class SystemService {
    public String getenv(String name) {
        return System.getenv(name);
    }
}

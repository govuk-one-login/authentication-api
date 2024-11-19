package uk.gov.di.authentication.shared.exceptions;

public class MissingEnvVariableException extends RuntimeException {
    public MissingEnvVariableException(String variableName) {
        super("Missing required environment variable: " + variableName);
    }
}

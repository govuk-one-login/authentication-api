package uk.gov.di.authentication.shared.helpers;

public record Argon2HashParameters(int memory, int iterations, int parallelism) {}

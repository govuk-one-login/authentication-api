package uk.gov.di.orchestration.local.initialisers;

import software.amazon.awssdk.regions.Region;

import java.net.URI;

public class InitialiserConfig {
    public static final Region REGION =
            Region.of(System.getenv().getOrDefault("AWS_REGION", "eu-west-2"));
    public static final URI LOCALSTACK_ENDPOINT =
            URI.create(System.getenv().get("LOCALSTACK_ENDPOINT"));
    public static final URI DYNAMO_ENDPOINT = URI.create(System.getenv().get("DYNAMO_ENDPOINT"));

    private InitialiserConfig() {}
}

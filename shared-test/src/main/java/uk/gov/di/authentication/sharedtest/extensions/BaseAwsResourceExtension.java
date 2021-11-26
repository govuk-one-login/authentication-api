package uk.gov.di.authentication.sharedtest.extensions;

public abstract class BaseAwsResourceExtension {
    protected static final String REGION = System.getenv().getOrDefault("AWS_REGION", "eu-west-2");
    protected static final String LOCALSTACK_ENDPOINT =
            System.getenv().getOrDefault("LOCALSTACK_ENDPOINT", "http://localhost:45678");
}

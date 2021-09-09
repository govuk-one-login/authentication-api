package uk.gov.di.lambdawarmer.lambda;

public class ConfigurationService {

    // Please keep the method names in alphabetical order so we can find stuff more easily.

    public String getLambdaArn() {
        return System.getenv().get("LAMBDA_ARN");
    }

    public String getLambdaQualifier() {
        return System.getenv().get("LAMBDA_QUALIFIER");
    }

    public int getMinConcurrency() {
        return Integer.parseInt(System.getenv().getOrDefault("LAMBDA_MIN_CONCURRENCY", "10"));
    }
}

package uk.gov.di.lambdawarmer.lambda;

public class ConfigurationService {

    // Please keep the method names in alphabetical order so we can find stuff more easily.

    public String getLambdaArn() {
        return System.getenv().get("LAMBDA_ARN");
    }

    public String getLambdaQualifier() {
        return System.getenv().get("LAMBDA_QUALIFIER");
    }

    public LambdaType getLambdaType() {
        return Enum.valueOf(
                LambdaType.class, System.getenv().getOrDefault("LAMBDA_TYPE", "ENDPOINT"));
    }

    public int getMinConcurrency() {
        return Integer.parseInt(System.getenv().getOrDefault("LAMBDA_MIN_CONCURRENCY", "10"));
    }

    public enum LambdaType {
        ENDPOINT,
        AUTHORIZER
    }
}

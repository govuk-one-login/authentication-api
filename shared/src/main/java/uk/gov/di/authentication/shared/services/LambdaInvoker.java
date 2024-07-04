package uk.gov.di.authentication.shared.services;

public interface LambdaInvoker {
    void invokeAsyncWithPayload(String jsonPayload, String functionName);
}

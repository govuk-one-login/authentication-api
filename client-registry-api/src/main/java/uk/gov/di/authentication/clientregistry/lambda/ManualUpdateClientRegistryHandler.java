package uk.gov.di.authentication.clientregistry.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;

public class ManualUpdateClientRegistryHandler implements RequestHandler<String, Void> {

    public ManualUpdateClientRegistryHandler() {}

    @Override
    public Void handleRequest(String input, Context context) {
        return null;
    }
}

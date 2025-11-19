package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;

public class ClientRegistryMigrationHandler implements RequestHandler<Object, String> {

    @Override
    public String handleRequest(Object ignored, Context context) {
        return "HelloWorld";
    }
}

package uk.gov.di.authentication.sharedtest.extensions;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import uk.gov.di.authentication.shared.entity.RequestUriResponsePayload;
import uk.gov.di.authentication.sharedtest.httpstub.HttpStubExtension;

public class RequestURILambdaStubExtension extends HttpStubExtension {

    public RequestURILambdaStubExtension(int port) {
        super(port);
    }

    public void init() {
        try {
            var payload =
                    new ObjectMapper().writeValueAsString(new RequestUriResponsePayload(true));
            register(
                    "/2015-03-31/functions/arn%3Aauthorize-request%3Aeu-west-2%3A6546546465/invocations",
                    200, "application/json", payload);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}

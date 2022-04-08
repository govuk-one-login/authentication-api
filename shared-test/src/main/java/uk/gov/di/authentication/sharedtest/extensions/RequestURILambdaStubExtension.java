package uk.gov.di.authentication.sharedtest.extensions;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import uk.gov.di.authentication.shared.entity.RequestUriResponsePayload;
import uk.gov.di.authentication.sharedtest.httpstub.HttpStubExtension;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public class RequestURILambdaStubExtension extends HttpStubExtension {

    private final String arn;

    public RequestURILambdaStubExtension(String arn) {
        super();
        this.arn = arn;
    }

    public void init() {
        var encodedArn = URLEncoder.encode(arn, StandardCharsets.UTF_8);
        var registeredPath = "/2015-03-31/functions/" + encodedArn + "/invocations";
        try {
            var payload =
                    new ObjectMapper().writeValueAsString(new RequestUriResponsePayload(true));
            register(registeredPath, 200, "application/json", payload);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    public String getArn() {
        return arn;
    }
}

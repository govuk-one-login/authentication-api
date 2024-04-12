package uk.gov.di.authentication.ticf.cri.stub.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

class TICFCRIStubHandlerTest {
    private static final Context context = mock(Context.class);

    @Test
    void shouldReturn200ForSuccessfulValidRequest() {
        TICFCRIStubHandler handler = new TICFCRIStubHandler();
        var event = new APIGatewayProxyRequestEvent();
        event.setBody(
                "{\"sub\":\"urn:fdc:gov.uk:2022:test\","
                        + "\"vtr\":[\"Cl.Cm\"],"
                        + "\"govuk_signin_journey_id\":\"44444444-4444-4444-4444-444444444444\","
                        + "\"authenticated\":\"Y\"}\n");
        var result = handler.handleRequest(event, context);
        String expectedResponse =
                "{\"intervention\":{\"interventionCode\":\"01\",\"interventionReason\":\"01\"},"
                        + "\"sub\":\"urn:fdc:gov.uk:2022:test\","
                        + "\"govuk_signin_journey_id\":\"44444444-4444-4444-4444-444444444444\","
                        + "\"ci\":[\"D03\",\"F01\"]}";
        assertEquals(result.getBody(), expectedResponse);
        assertEquals(200, result.getStatusCode());
    }
}

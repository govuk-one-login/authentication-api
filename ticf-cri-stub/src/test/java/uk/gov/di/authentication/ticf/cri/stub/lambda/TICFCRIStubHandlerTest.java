package uk.gov.di.authentication.ticf.cri.stub.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;

class TICFCRIStubHandlerTest {
    private static final Context context = mock(Context.class);

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(TICFCRIStubHandler.class);

    @Test
    void shouldReturn200ForSuccessfulValidRequest() {
        TICFCRIStubHandler handler = new TICFCRIStubHandler();
        var event = new APIGatewayProxyRequestEvent();
        event.setBody(
                """
                        {
                            "sub":"urn:fdc:gov.uk:2022:test",
                            "vtr":["Cl.Cm"],
                            "govuk_signin_journey_id":"44444444-4444-4444-4444-444444444444",
                            "authenticated":"Y",
                            "initial_registration":"NEW",
                            "password_reset":"NONE",
                            "2fa_reset":"NONE"
                        }
                """);
        var result = handler.handleRequest(event, context);
        String expectedResponse =
                """
                        {\
                        "intervention":{"interventionCode":"01","interventionReason":"01"},\
                        "sub":"urn:fdc:gov.uk:2022:test",\
                        "govuk_signin_journey_id":"44444444-4444-4444-4444-444444444444",\
                        "ci":["D03","F01"]}\
                        """;
        assertEquals(result.getBody(), expectedResponse);
        assertEquals(200, result.getStatusCode());
    }

    @Test
    void shouldLogRequestFieldsExcludingInternalCommonSubjectIdentifier() {
        TICFCRIStubHandler handler = new TICFCRIStubHandler();
        var event = new APIGatewayProxyRequestEvent();
        event.setBody(
                """
                        {
                            "sub":"urn:fdc:gov.uk:2022:test",
                            "vtr":["Cl.Cm"],
                            "govuk_signin_journey_id":"44444444-4444-4444-4444-444444444444",
                            "authenticated":"Y",
                            "initial_registration":"EXISTING",
                            "password_reset":"NONE",
                            "2fa_reset":"NONE",
                            "2fa_method":["SMS"]
                        }
                """);

        handler.handleRequest(event, context);

        assertThat(logging.events(), hasItem(withMessageContaining("TICF Request")));
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                "govuk_signin_journey_id: 44444444-4444-4444-4444-444444444444")));
        assertThat(logging.events(), hasItem(withMessageContaining("vtr: [Cl.Cm]")));
        assertThat(logging.events(), hasItem(withMessageContaining("authenticated: Y")));
        assertThat(
                logging.events(), hasItem(withMessageContaining("initial_registration: EXISTING")));
        assertThat(logging.events(), hasItem(withMessageContaining("password_reset: NONE")));
        assertThat(logging.events(), hasItem(withMessageContaining("2fa_reset: NONE")));
        assertThat(logging.events(), hasItem(withMessageContaining("2fa_method:")));
        assertThat(
                logging.events(), not(hasItem(withMessageContaining("urn:fdc:gov.uk:2022:test"))));
    }
}

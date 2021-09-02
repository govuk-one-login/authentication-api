package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.ErrorResponse;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static uk.gov.di.accountmanagement.entity.UpdateInfoType.EMAIL;
import static uk.gov.di.authentication.shared.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.shared.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class UpdateInfoHandlerTest {

    private final Context context = mock(Context.class);
    private final UpdateInfoHandler handler = new UpdateInfoHandler();
    private static final String EXISTING_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String NEW_EMAIL_ADDRESS = "joe.b@digital.cabinet-office.gov.uk";

    @Test
    public void shouldReturn200ForValidRequest() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(
                format(
                        "{ \"updateInfoType\": \"%s\", \"existingProfileAttribute\": \"%s\", \"replacementProfileAttribute\": \"%s\" }",
                        EMAIL, EXISTING_EMAIL_ADDRESS, NEW_EMAIL_ADDRESS));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
    }

    @Test
    public void shouldReturn400WhenRequestIsMissingParameters() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(
                format(
                        "{ \"updateInfoType\": \"%s\", \"existingProfileAttribute\": \"%s\"}",
                        EMAIL, EXISTING_EMAIL_ADDRESS));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
    }

    @Test
    public void shouldReturn400WhenUpdateProfileTypeIsInvalid() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(
                format(
                        "{ \"updateInfoType\": \"%s\", \"existingProfileAttribute\": \"%s\", \"replacementProfileAttribute\": \"%s\" }",
                        "ADDRESS", EXISTING_EMAIL_ADDRESS, NEW_EMAIL_ADDRESS));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
    }
}

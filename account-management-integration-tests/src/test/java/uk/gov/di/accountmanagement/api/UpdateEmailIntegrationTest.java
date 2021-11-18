package uk.gov.di.accountmanagement.api;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.entity.UpdateEmailRequest;
import uk.gov.di.accountmanagement.lambda.UpdateEmailHandler;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.helper.DynamoHelper;

import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class UpdateEmailIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String EXISTING_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String NEW_EMAIL_ADDRESS = "joe.b@digital.cabinet-office.gov.uk";
    private static final String OTP = "123456";
    private static final Subject SUBJECT = new Subject();

    @BeforeEach
    void setup() {
        handler = new UpdateEmailHandler(configurationService);
    }

    @Test
    public void shouldCallLoginEndpointAndReturn204WhenLoginIsSuccessful() {
        DynamoHelper.signUp(EXISTING_EMAIL_ADDRESS, "password-1", SUBJECT);

        var response =
                makeRequest(
                        Optional.of(
                                new UpdateEmailRequest(
                                        EXISTING_EMAIL_ADDRESS, NEW_EMAIL_ADDRESS, OTP)),
                        Map.of(),
                        Map.of());

        assertThat(response, hasStatus(204));
    }
}

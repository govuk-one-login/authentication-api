package uk.gov.di.accountmanagement.api;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.entity.UpdateEmailRequest;
import uk.gov.di.accountmanagement.lambda.UpdateEmailHandler;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.helper.DynamoHelper;
import uk.gov.di.authentication.sharedtest.helper.RedisHelper;

import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class UpdateEmailIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String EXISTING_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String NEW_EMAIL_ADDRESS = "joe.b@digital.cabinet-office.gov.uk";
    private static final Subject SUBJECT = new Subject();

    @BeforeEach
    void setup() {
        handler = new UpdateEmailHandler(configurationService);
    }

    @Test
    public void shouldCallUpdateEmailEndpointAndReturn204WhenLoginIsSuccessful() {
        String publicSubjectID = DynamoHelper.signUp(EXISTING_EMAIL_ADDRESS, "password-1", SUBJECT);
        String otp = RedisHelper.generateAndSaveEmailCode(NEW_EMAIL_ADDRESS, 300);
        var response =
                makeRequest(
                        Optional.of(
                                new UpdateEmailRequest(
                                        EXISTING_EMAIL_ADDRESS, NEW_EMAIL_ADDRESS, otp)),
                        Map.of(),
                        Map.of(),
                        Map.of(),
                        Map.of("principalId", publicSubjectID));

        assertThat(response, hasStatus(204));
    }
}

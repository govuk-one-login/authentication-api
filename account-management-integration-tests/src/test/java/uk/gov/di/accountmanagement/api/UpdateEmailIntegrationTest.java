package uk.gov.di.accountmanagement.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.accountmanagement.entity.UpdateEmailRequest;
import uk.gov.di.accountmanagement.lambda.UpdateEmailHandler;
import uk.gov.di.authentication.shared.helpers.ObjectMapperFactory;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.NotifyStubExtension;

import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;
import static uk.gov.di.authentication.sharedtest.matchers.JsonMatcher.hasField;
import static uk.gov.di.authentication.sharedtest.matchers.JsonMatcher.hasFieldWithValue;

public class UpdateEmailIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String EXISTING_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String NEW_EMAIL_ADDRESS = "joe.b@digital.cabinet-office.gov.uk";
    private static final Subject SUBJECT = new Subject();

    @RegisterExtension
    private static final NotifyStubExtension notify =
            new NotifyStubExtension(8888, ObjectMapperFactory.getInstance());

    @BeforeEach
    void setup() {
        handler = new UpdateEmailHandler(TEST_CONFIGURATION_SERVICE);
        notify.init();
    }

    @AfterEach
    void resetStub() {
        notify.reset();
    }

    @Test
    public void shouldCallUpdateEmailEndpointAndReturn204WhenLoginIsSuccessful()
            throws JsonProcessingException {
        String publicSubjectID = userStore.signUp(EXISTING_EMAIL_ADDRESS, "password-1", SUBJECT);
        String otp = redis.generateAndSaveEmailCode(NEW_EMAIL_ADDRESS, 300);
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

        var notifyRequest = notify.waitForRequest(60);

        assertThat(notifyRequest, hasField("personalisation"));
        var personalisation = notifyRequest.get("personalisation");
        assertThat(personalisation, hasFieldWithValue("email-address", equalTo(NEW_EMAIL_ADDRESS)));
    }
}

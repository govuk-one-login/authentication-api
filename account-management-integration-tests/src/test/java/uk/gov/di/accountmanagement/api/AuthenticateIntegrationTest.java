package uk.gov.di.accountmanagement.api;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.http.client.utils.URIBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.accountmanagement.entity.AuthenticateRequest;
import uk.gov.di.accountmanagement.lambda.AuthenticateHandler;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.AccountInterventionsStubExtension;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.*;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsSubmittedWithMatchingNames;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class AuthenticateIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    @RegisterExtension
    public static final AccountInterventionsStubExtension accountInterventionsStubExtension =
            new AccountInterventionsStubExtension();

    protected static final ConfigurationService
            ACCOUNT_INTERVENTIONS_HANDLER_CONFIGURATION_SERVICE =
                    new AccountInterventionsTestConfigurationService(
                            accountInterventionsStubExtension);

    @BeforeEach
    void setup() {
        handler = new AuthenticateHandler(ACCOUNT_INTERVENTIONS_HANDLER_CONFIGURATION_SERVICE);
        txmaAuditQueue.clear();
    }

    @Test
    public void shouldCallLoginEndpointAndReturn204WhenLoginIsSuccessful() {
        String email = "joe.bloggs+3@digital.cabinet-office.gov.uk";
        String password = "password-1";
        String publicSubjectId = setupUserAndRetrieveUserId(email, password);
        accountInterventionsStubExtension.initWithAccountStatus(
                publicSubjectId, false, false, false, false);

        var response =
                makeRequest(
                        Optional.of(new AuthenticateRequest(email, password)), Map.of(), Map.of());

        assertThat(response, hasStatus(204));

        assertTxmaAuditEventsSubmittedWithMatchingNames(
                txmaAuditQueue, List.of(AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE));
    }

    @Test
    public void shouldCallLoginEndpointAndReturn401WhenUserHasInvalidCredentials() {
        String email = "joe.bloggs+4@digital.cabinet-office.gov.uk";
        String password = "password-1";
        userStore.signUp(email, "wrong-password");

        var response =
                makeRequest(
                        Optional.of(new AuthenticateRequest(email, password)), Map.of(), Map.of());

        assertThat(response, hasStatus(401));

        assertTxmaAuditEventsSubmittedWithMatchingNames(
                txmaAuditQueue, List.of(AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE_FAILURE));
    }

    @Test
    public void shouldCallLoginEndpointAndReturn403WhenUserIsBlockedInAis() throws Exception {
        String email = "joe.bloggs+5@digital.cabinet-office.gov.uk";
        String password = "password-1";
        String publicSubjectId = setupUserAndRetrieveUserId(email, password);
        accountInterventionsStubExtension.initWithAccountStatus(
                publicSubjectId, true, false, false, false);

        var response =
                makeRequest(
                        Optional.of(new AuthenticateRequest(email, password)), Map.of(), Map.of());

        assertThat(response, hasStatus(403));
        assertThat(response, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1084)));

        assertTxmaAuditEventsSubmittedWithMatchingNames(
                txmaAuditQueue, List.of(AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE_INTERVENTION_FAILURE));
    }

    @Test
    public void shouldCallLoginEndpointAndReturn403WhenUserIsSuspendedInAis() throws Exception {
        String email = "joe.bloggs+5@digital.cabinet-office.gov.uk";
        String password = "password-1";
        String publicSubjectId = setupUserAndRetrieveUserId(email, password);
        accountInterventionsStubExtension.initWithAccountStatus(
                publicSubjectId, false, true, false, false);

        var response =
                makeRequest(
                        Optional.of(new AuthenticateRequest(email, password)), Map.of(), Map.of());

        assertThat(response, hasStatus(403));
        assertThat(response, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1083)));

        assertTxmaAuditEventsSubmittedWithMatchingNames(
                txmaAuditQueue, List.of(AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE_INTERVENTION_FAILURE));
    }

    @Test
    public void shouldCallLoginEndpointAndReturn204WhenUserIsSuspendedInAisButHasPasswordReset() {
        String email = "joe.bloggs+3@digital.cabinet-office.gov.uk";
        String password = "password-1";
        String publicSubjectId = setupUserAndRetrieveUserId(email, password);
        accountInterventionsStubExtension.initWithAccountStatus(
                publicSubjectId, false, true, false, true);

        var response =
                makeRequest(
                        Optional.of(new AuthenticateRequest(email, password)), Map.of(), Map.of());

        assertThat(response, hasStatus(204));

        assertTxmaAuditEventsSubmittedWithMatchingNames(
                txmaAuditQueue, List.of(AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE));
    }

    @Test
    public void shouldCallLoginEndpointAndReturn204WhenUserIsSuspendedInAisButHasReproveIdentity() {
        String email = "joe.bloggs+3@digital.cabinet-office.gov.uk";
        String password = "password-1";
        String publicSubjectId = setupUserAndRetrieveUserId(email, password);
        accountInterventionsStubExtension.initWithAccountStatus(
                publicSubjectId, false, true, true, false);

        var response =
                makeRequest(
                        Optional.of(new AuthenticateRequest(email, password)), Map.of(), Map.of());

        assertThat(response, hasStatus(204));

        assertTxmaAuditEventsSubmittedWithMatchingNames(
                txmaAuditQueue, List.of(AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE));
    }

    @Test
    public void
            shouldCallLoginEndpointAndReturn204WhenUserIsSuspendedInAisButHasPasswordResetAndReproveIdentity() {
        String email = "joe.bloggs+3@digital.cabinet-office.gov.uk";
        String password = "password-1";
        String publicSubjectId = setupUserAndRetrieveUserId(email, password);
        accountInterventionsStubExtension.initWithAccountStatus(
                publicSubjectId, false, true, true, true);

        var response =
                makeRequest(
                        Optional.of(new AuthenticateRequest(email, password)), Map.of(), Map.of());

        assertThat(response, hasStatus(204));

        assertTxmaAuditEventsSubmittedWithMatchingNames(
                txmaAuditQueue, List.of(AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE));
    }

    private static class AccountInterventionsTestConfigurationService
            extends IntegrationTestConfigurationService {

        private final AccountInterventionsStubExtension accountInterventionsStubExtension;

        public AccountInterventionsTestConfigurationService(
                AccountInterventionsStubExtension accountInterventionsStubExtension) {
            super(
                    notificationsQueue,
                    tokenSigner,
                    docAppPrivateKeyJwtSigner,
                    configurationParameters);
            this.accountInterventionsStubExtension = accountInterventionsStubExtension;
        }

        @Override
        public URI getAccountInterventionServiceURI() {
            try {
                return new URIBuilder()
                        .setHost("localhost")
                        .setPort(accountInterventionsStubExtension.getHttpPort())
                        .setScheme("http")
                        .build();
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public String getTxmaAuditQueueUrl() {
            return txmaAuditQueue.getQueueUrl();
        }

        @Override
        public boolean isAccountInterventionServiceCallInAuthenticateEnabled() {
            return true;
        }
        ;
    }

    private String setupUserAndRetrieveUserId(String emailAddress, String password) {
        Subject subject = new Subject();
        userStore.signUp(emailAddress, password, subject);
        byte[] salt = userStore.addSalt(emailAddress);
        return ClientSubjectHelper.calculatePairwiseIdentifier(
                subject.getValue(), "test.account.gov.uk", salt);
    }
}

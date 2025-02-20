package uk.gov.di.authentication.shared.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.state.UserContext;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.helpers.TxmaAuditHelper.TXMA_AUDIT_ENCODED_HEADER;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;

class TxmaAuditHelperTest {
    public static final String SESSION_ID = "session-id";
    public static final String EMAIL = "joe.bloggs@test.com";

    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(TxmaAuditHelper.class);

    @Test
    void checkTxMAAuditEncodedHeaderCanBeExtracted() {
        var apiRequest = new APIGatewayProxyRequestEvent();
        var headers = new HashMap<String, String>();
        headers.put(TXMA_AUDIT_ENCODED_HEADER, "test");
        apiRequest.setHeaders(headers);

        var result = TxmaAuditHelper.getTxmaAuditEncodedHeader(apiRequest);

        assertEquals(Optional.of("test"), result);
    }

    @Test
    void checkTxMAAuditEncodedHeaderOnlyExtractsLowerCase() {
        var apiRequest = new APIGatewayProxyRequestEvent();
        var headers = new HashMap<String, String>();
        headers.put(TXMA_AUDIT_ENCODED_HEADER.toUpperCase(), "test");
        apiRequest.setHeaders(headers);

        var result = TxmaAuditHelper.getTxmaAuditEncodedHeader(apiRequest);

        assertEquals(Optional.empty(), result);
    }

    @Test
    void missingTxMAAuditEncodedHeaderReturnsEmptyOptional() {
        var apiRequest = new APIGatewayProxyRequestEvent();
        var headers = new HashMap<String, String>();
        apiRequest.setHeaders(headers);

        var result = TxmaAuditHelper.getTxmaAuditEncodedHeader(apiRequest);

        assertEquals(Optional.empty(), result);
    }

    @Test
    void canCalculatePairwiseIdentifier() {
        UserProfile userProfile = new UserProfile();
        userProfile.setSubjectID("subject-id");

        var clientRegistry = new ClientRegistry();
        clientRegistry.setOneLoginService(true);

        var authenticationService = mock(AuthenticationService.class);
        when(authenticationService.getOrGenerateSalt(userProfile))
                .thenReturn("salt".getBytes(StandardCharsets.UTF_8));

        UserContext userContext =
                UserContext.builder(new Session(SESSION_ID).setEmailAddress(EMAIL))
                        .withUserProfile(userProfile)
                        .withClient(clientRegistry)
                        .build();

        var configurationService = mock(ConfigurationService.class);
        when(configurationService.getInternalSectorUri()).thenReturn("https://gov.uk/test");

        var result =
                TxmaAuditHelper.getRpPairwiseId(
                        authenticationService, configurationService, userContext);

        assertNotNull(result);
    }

    @Test
    void checkNoUserContextReturnUnknownSpecialCaseValue() {
        var result = TxmaAuditHelper.getRpPairwiseId(null, null, null);

        assertEquals(AuditService.UNKNOWN, result);
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                "Returning empty RP pairwise identifier - no user context provided")));
    }

    @Test
    void checkNoUserProfileReturnUnknownSpecialCaseValue() {
        var result =
                TxmaAuditHelper.getRpPairwiseId(
                        null, null, UserContext.builder(new Session("")).build());

        assertEquals(AuditService.UNKNOWN, result);
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                "Returning empty RP pairwise identifier - no user profile or client found")));
    }

    @Test
    void checkNoClientRegistryReturnUnknownSpecialCaseValue() {
        var result =
                TxmaAuditHelper.getRpPairwiseId(
                        null,
                        null,
                        UserContext.builder(new Session(""))
                                .withUserProfile(new UserProfile())
                                .build());

        assertEquals(AuditService.UNKNOWN, result);
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                "Returning empty RP pairwise identifier - no user profile or client found")));
    }
}

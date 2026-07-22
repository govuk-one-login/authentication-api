package uk.gov.di.orchestration.identity.helpers;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.identity.entity.AuditEventConfiguration;
import uk.gov.di.orchestration.identity.entity.IdentityTokenService;
import uk.gov.di.orchestration.identity.testsupport.TestAuditEvent;
import uk.gov.di.orchestration.shared.api.CommonFrontend;
import uk.gov.di.orchestration.shared.domain.AuditableEvent;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.DynamoIdentityService;
import uk.gov.di.orchestration.shared.services.RedirectService;
import uk.gov.di.orchestration.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static org.apache.logging.log4j.Level.ERROR;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.sharedtest.logging.LogEventMatcher.withLevelAndMessageContaining;
import static uk.gov.di.orchestration.sharedtest.logging.LogEventMatcher.withMessageContaining;

public class IdentityCallbackHelperTest {
    private static final AuthorizationCode AUTH_CODE = new AuthorizationCode();
    private static final String CLIENT_ID = "test-client-id";
    private static final URI FRONT_END_ERROR_URI = URI.create("https://example.com/error");
    private final IdentityTokenService identityTokenService = mock(IdentityTokenService.class);
    private final CommonFrontend frontend = mock(CommonFrontend.class);
    private final AuditService auditService = mock(AuditService.class);
    private final DynamoIdentityService dynamoIdentityService = mock(DynamoIdentityService.class);
    private final AuditEventConfiguration auditEventConfiguration =
            new AuditEventConfiguration(
                    TestAuditEvent.TEST_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                    TestAuditEvent.TEST_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED);
    private final TxmaAuditUser user = mock(TxmaAuditUser.class);
    private IdentityCallbackHelper helper;

    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(IdentityCallbackHelper.class);

    @RegisterExtension
    private final CaptureLoggingExtension redirectLogging =
            new CaptureLoggingExtension(RedirectService.class);

    @BeforeEach
    void setUp() {
        helper =
                new IdentityCallbackHelper(
                        identityTokenService,
                        auditService,
                        auditEventConfiguration,
                        frontend,
                        dynamoIdentityService);
        when(frontend.errorURI()).thenReturn(FRONT_END_ERROR_URI);
    }

    @Nested
    class MakeTokenRequest {
        @Test
        void shouldRedirectToFrontendErrorPageWhenTokenResponseIsNotSuccessful() {
            withUnsuccessfulTokenResponse();

            var response = helper.makeTokenRequest(AUTH_CODE.toString(), CLIENT_ID, user);

            assertTrue(response.isPresent());
            assertThat(
                    response.get().getHeaders().get("Location"),
                    startsWith(FRONT_END_ERROR_URI.toString()));

            assertAuditEventSent(TestAuditEvent.TEST_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED);
            verifyNoMoreInteractions(auditService);

            assertThat(
                    redirectLogging.events(),
                    hasItem(
                            withLevelAndMessageContaining(
                                    ERROR,
                                    "Redirecting to frontend error page: " + FRONT_END_ERROR_URI)));
        }

        @Test
        void shouldNotRedirectWhenTokenResponseIsSuccessful() {
            withSuccessfulTokenResponse();

            var response = helper.makeTokenRequest(AUTH_CODE.toString(), CLIENT_ID, user);

            assertTrue(response.isEmpty());
            assertAuditEventSent(TestAuditEvent.TEST_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED);
            verifyNoMoreInteractions(auditService);
        }
    }

    @Nested
    class SaveIdentityClaimsToDynamo {
        private static final String CLIENT_SESSION_ID = "test-csid";
        private static final Subject RP_PAIRWISE_SUBJECT = new Subject("rp-pairwise-id");
        private static final long SPOT_QUEUED_AT = 12345L;

        @Test
        void shouldSaveAdditionalIdentityClaimsToDynamo() {
            var userInfo =
                    new UserInfo(
                            new JSONObject(
                                    Map.of(
                                            "sub", "sub-val",
                                            "vot", "P2",
                                            "vtm", "http://test-trustmark-uri",
                                            "https://vocab.account.gov.uk/v1/coreIdentity",
                                                    "core-identity",
                                            "https://vocab.account.gov.uk/v1/passport",
                                                    "passport")));
            helper.saveIdentityClaimsToDynamo(
                    CLIENT_SESSION_ID, RP_PAIRWISE_SUBJECT, userInfo, SPOT_QUEUED_AT);

            assertThat(
                    logging.events(),
                    hasItem(
                            withMessageContaining(
                                    "Checking for additional identity claims to save to dynamo")));
            assertThat(
                    logging.events(),
                    hasItem(withMessageContaining("Additional identity claims present: true")));
            verify(dynamoIdentityService)
                    .saveIdentityClaims(
                            CLIENT_SESSION_ID,
                            "rp-pairwise-id",
                            Map.of("https://vocab.account.gov.uk/v1/passport", "passport"),
                            "P2",
                            "core-identity",
                            SPOT_QUEUED_AT);
        }

        @Test
        void handlesMissingCoreIdentity() {
            var userInfo =
                    new UserInfo(
                            new JSONObject(
                                    Map.of(
                                            "sub", "sub-val",
                                            "vot", "P2",
                                            "vtm", "http://test-trustmark-uri",
                                            "https://vocab.account.gov.uk/v1/passport",
                                                    "passport")));
            helper.saveIdentityClaimsToDynamo(
                    CLIENT_SESSION_ID, RP_PAIRWISE_SUBJECT, userInfo, SPOT_QUEUED_AT);

            assertThat(
                    logging.events(),
                    hasItem(
                            withMessageContaining(
                                    "Checking for additional identity claims to save to dynamo")));
            assertThat(
                    logging.events(),
                    hasItem(withMessageContaining("Additional identity claims present: true")));
            verify(dynamoIdentityService)
                    .saveIdentityClaims(
                            CLIENT_SESSION_ID,
                            "rp-pairwise-id",
                            Map.of("https://vocab.account.gov.uk/v1/passport", "passport"),
                            "P2",
                            "",
                            SPOT_QUEUED_AT);
        }

        @Test
        void handlesNullCoreIdentity() {
            var userInfo =
                    new UserInfo(
                            new JSONObject(
                                    new HashMap<String, String>() {
                                        {
                                            put("sub", "sub-val");
                                            put("vot", "P2");
                                            put("vtm", "http://test-trustmark-url");
                                            put(
                                                    "https://vocab.account.gov.uk/v1/coreIdentity",
                                                    null);
                                            put(
                                                    "https://vocab.account.gov.uk/v1/passport",
                                                    "passport");
                                        }
                                    }));
            helper.saveIdentityClaimsToDynamo(
                    CLIENT_SESSION_ID, RP_PAIRWISE_SUBJECT, userInfo, SPOT_QUEUED_AT);

            assertThat(
                    logging.events(),
                    hasItem(
                            withMessageContaining(
                                    "Checking for additional identity claims to save to dynamo")));
            assertThat(
                    logging.events(),
                    hasItem(withMessageContaining("Additional identity claims present: true")));
            verify(dynamoIdentityService)
                    .saveIdentityClaims(
                            CLIENT_SESSION_ID,
                            "rp-pairwise-id",
                            Map.of("https://vocab.account.gov.uk/v1/passport", "passport"),
                            "P2",
                            "",
                            SPOT_QUEUED_AT);
        }

        @Test
        void handlesNullSpotQueuedAtTimestamp() {
            var userInfo =
                    new UserInfo(
                            new JSONObject(
                                    new HashMap<String, String>() {
                                        {
                                            put("sub", "sub-val");
                                            put("vot", "P2");
                                            put("vtm", "http://test-trustmark-uri");
                                            put(
                                                    "https://vocab.account.gov.uk/v1/coreIdentity",
                                                    null);
                                            put(
                                                    "https://vocab.account.gov.uk/v1/passport",
                                                    "passport");
                                        }
                                    }));
            helper.saveIdentityClaimsToDynamo(
                    CLIENT_SESSION_ID, RP_PAIRWISE_SUBJECT, userInfo, null);

            assertThat(
                    logging.events(),
                    hasItem(
                            withMessageContaining(
                                    "Checking for additional identity claims to save to dynamo")));
            assertThat(
                    logging.events(),
                    hasItem(withMessageContaining("Additional identity claims present: true")));
            verify(dynamoIdentityService)
                    .saveIdentityClaims(
                            CLIENT_SESSION_ID,
                            "rp-pairwise-id",
                            Map.of("https://vocab.account.gov.uk/v1/passport", "passport"),
                            "P2",
                            "",
                            null);
        }
    }

    private void withSuccessfulTokenResponse() {
        var successfulTokenResponse =
                new AccessTokenResponse(new Tokens(new BearerAccessToken(), null));
        when(identityTokenService.getToken(AUTH_CODE.toString()))
                .thenReturn(successfulTokenResponse);
    }

    private void withUnsuccessfulTokenResponse() {
        var unsuccessfulTokenResponse = new TokenErrorResponse(new ErrorObject("error"));
        when(identityTokenService.getToken(AUTH_CODE.toString()))
                .thenReturn(unsuccessfulTokenResponse);
    }

    private void assertAuditEventSent(AuditableEvent auditEvent) {
        verify(auditService).submitAuditEvent(auditEvent, CLIENT_ID, user);
    }
}

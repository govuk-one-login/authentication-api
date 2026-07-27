package uk.gov.di.orchestration.identity.helpers;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
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
import uk.gov.di.orchestration.identity.exceptions.IdentityCallbackException;
import uk.gov.di.orchestration.identity.service.IdentityTokenService;
import uk.gov.di.orchestration.identity.testsupport.TestAuditEvent;
import uk.gov.di.orchestration.shared.api.CommonFrontend;
import uk.gov.di.orchestration.shared.api.OidcAPI;
import uk.gov.di.orchestration.shared.domain.AuditableEvent;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.exceptions.UnsuccessfulCredentialResponseException;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.DynamoIdentityService;
import uk.gov.di.orchestration.shared.services.RedirectService;
import uk.gov.di.orchestration.sharedtest.logging.CaptureLoggingExtension;

import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.nimbusds.oauth2.sdk.OAuth2Error.ACCESS_DENIED;
import static org.apache.logging.log4j.Level.ERROR;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
    private static final URI TRUSTMARK_URI = URI.create("https://oidc.com/trustmark");
    private static final Subject SUBJECT =
            new Subject("urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6");
    private static final URI BACKEND_URI = URI.create("http://test-backend-uri");
    private final IdentityTokenService identityTokenService = mock(IdentityTokenService.class);
    private final CommonFrontend frontend = mock(CommonFrontend.class);
    private final AuditService auditService = mock(AuditService.class);
    private final DynamoIdentityService dynamoIdentityService = mock(DynamoIdentityService.class);
    private final OidcAPI oidcApi = mock(OidcAPI.class);
    private final AuditEventConfiguration auditEventConfiguration =
            new AuditEventConfiguration(
                    TestAuditEvent.TEST_UNSUCCESSFUL_AUTH_RESPONSE_RECEIVED,
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
                        dynamoIdentityService,
                        oidcApi);
        when(frontend.errorURI()).thenReturn(FRONT_END_ERROR_URI);
        when(oidcApi.trustmarkURI()).thenReturn(TRUSTMARK_URI);
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
                                            "sub",
                                            "sub-val",
                                            "vot",
                                            "P2",
                                            "vtm",
                                            "http://test-trustmark-uri",
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
                                            "sub",
                                            "sub-val",
                                            "vot",
                                            "P2",
                                            "vtm",
                                            "http://test-trustmark-uri",
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

    @Nested
    class SendUserIdentityRequest {
        private static final String SUCCESSFUL_USER_INFO_HTTP_RESPONSE_CONTENT =
                "{"
                        + " \"sub\": \""
                        + SUBJECT
                        + "\","
                        + " \"vot\": \"P2\","
                        + " \"vtm\": \""
                        + TRUSTMARK_URI
                        + "\""
                        + "}";
        private static final BearerAccessToken BEARER_ACCESS_TOKEN = new BearerAccessToken();
        private static final TokenResponse SUCCESSFUL_TOKEN_RESPONSE =
                new AccessTokenResponse(new Tokens(BEARER_ACCESS_TOKEN, null));

        @Test
        void shouldCreateUserIdentityRequest() throws Exception {
            var httpRequest =
                    helper.createUserIdentityRequest(SUCCESSFUL_TOKEN_RESPONSE, BACKEND_URI);

            assertThat(httpRequest.getMethod(), equalTo(HTTPRequest.Method.GET));
            assertThat(httpRequest.getURI(), equalTo(new URI(BACKEND_URI + "/user-identity")));
            assertThat(
                    httpRequest.getAuthorization(),
                    equalTo(BEARER_ACCESS_TOKEN.toAuthorizationHeader()));
        }

        @Test
        void shouldReturnUserInfoResponseIfUserIdentityRequestIsSuccessful() throws Exception {
            var mockedRequest = mock(HTTPRequest.class);
            when(mockedRequest.send()).thenReturn(successfulUserIdentityResponse());

            var response = helper.sendUserIdentityRequest(mockedRequest);

            assertThat(response.getSubject(), equalTo(SUBJECT));
        }

        @Test
        void shouldThrowExceptionIfUserIdentityRequestExceedsNumberOfRetries() throws Exception {
            var mockedRequest = mock(HTTPRequest.class);
            when(mockedRequest.send()).thenReturn(unsuccessfulUserIdentityResponse());

            assertThrows(
                    UnsuccessfulCredentialResponseException.class,
                    () -> helper.sendUserIdentityRequest(mockedRequest));
        }

        @Test
        void shouldReturnUserInfoResponseIfUserIdentityRequestIsSuccessfulAfterRetry()
                throws Exception {
            var mockedRequest = mock(HTTPRequest.class);
            when(mockedRequest.send())
                    .thenReturn(unsuccessfulUserIdentityResponse())
                    .thenReturn(successfulUserIdentityResponse());

            var response = helper.sendUserIdentityRequest(mockedRequest);

            assertThat(response.getSubject(), equalTo(SUBJECT));
        }

        @Test
        void shouldThrowExceptionIfUserIdentityResponseIsInvalidJSON() throws Exception {
            var invalidJsonResponse = new HTTPResponse(200);
            invalidJsonResponse.setBody("{");
            var mockedRequest = mock(HTTPRequest.class);
            when(mockedRequest.send()).thenReturn(invalidJsonResponse);

            assertThrows(
                    UnsuccessfulCredentialResponseException.class,
                    () -> helper.sendUserIdentityRequest(mockedRequest));
        }

        @Test
        void shouldThrowExceptionIfUserIdentityRequestIsInterrupted() throws Exception {
            var mockedRequest = mock(HTTPRequest.class);
            when(mockedRequest.send()).thenThrow(new IOException("Network interruption"));

            assertThrows(
                    RuntimeException.class, () -> helper.sendUserIdentityRequest(mockedRequest));
        }

        private static HTTPResponse successfulUserIdentityResponse() {
            var httpResponse = new HTTPResponse(200);
            httpResponse.setEntityContentType(ContentType.APPLICATION_JSON);
            httpResponse.setBody(SUCCESSFUL_USER_INFO_HTTP_RESPONSE_CONTENT);
            return httpResponse;
        }

        private static HTTPResponse unsuccessfulUserIdentityResponse() {
            return new HTTPResponse(500);
        }
    }

    @Nested
    class ValidateUserIdentityResponse {

        @Test
        void shouldReturnAccessDeniedIfVotDoesNotContainRequestedLoCs()
                throws IdentityCallbackException {
            var userInfo = new UserInfo(SUBJECT);
            userInfo.setClaim("vot", LevelOfConfidence.MEDIUM_LEVEL.getValue());

            var result =
                    helper.validateUserIdentityResponse(userInfo, List.of(LevelOfConfidence.NONE));

            assertTrue(result.isPresent());
            assertThat(result.get(), equalTo(ACCESS_DENIED));
        }

        @Test
        void shouldThrowExceptionWhenVtmDoesNotEqualTrustmarkUrl() {
            var userInfo = new UserInfo(SUBJECT);
            userInfo.setClaim("vot", LevelOfConfidence.MEDIUM_LEVEL.getValue());
            userInfo.setClaim("vtm", "http://different-trustmark-url");

            assertThrows(
                    IdentityCallbackException.class,
                    () ->
                            helper.validateUserIdentityResponse(
                                    userInfo, List.of(LevelOfConfidence.MEDIUM_LEVEL)));
        }

        @Test
        void shouldNotReturnErrorIfVotHasRequestedLoCAndVtmMatchesTrustmarkUrl()
                throws IdentityCallbackException {
            var userInfo = new UserInfo(SUBJECT);
            userInfo.setClaim("vot", LevelOfConfidence.MEDIUM_LEVEL.getValue());
            userInfo.setClaim("vtm", TRUSTMARK_URI);

            var result =
                    helper.validateUserIdentityResponse(
                            userInfo, List.of(LevelOfConfidence.MEDIUM_LEVEL));

            assertTrue(result.isEmpty());
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

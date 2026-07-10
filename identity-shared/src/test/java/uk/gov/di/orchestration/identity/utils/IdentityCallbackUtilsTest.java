package uk.gov.di.orchestration.identity.utils;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.identity.exceptions.IdentityCallbackException;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.exceptions.UnsuccessfulCredentialResponseException;

import java.io.IOException;
import java.net.URI;
import java.util.List;

import static com.nimbusds.oauth2.sdk.OAuth2Error.ACCESS_DENIED;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.identity.utils.IdentityCallbackUtils.validateUserIdentityResponse;

class IdentityCallbackUtilsTest {

    private static final String TRUSTMARK_URL = "http://test.com/trustmark";
    private static final Subject SUBJECT =
            new Subject("urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6");
    private static final String SUCCESSFUL_USER_INFO_HTTP_RESPONSE_CONTENT =
            "{"
                    + " \"sub\": \""
                    + SUBJECT
                    + "\","
                    + " \"vot\": \"P2\","
                    + " \"vtm\": \"<trust mark>\""
                    + "}";
    private static final String BACKEND_URI = "http://test-backend-uri";
    private static final BearerAccessToken BEARER_ACCESS_TOKEN = new BearerAccessToken();
    private static final TokenResponse SUCCESSFUL_TOKEN_RESPONSE =
            new AccessTokenResponse(new Tokens(BEARER_ACCESS_TOKEN, null));

    @Nested
    class SendUserIdentityRequest {
        @Test
        void shouldCreateUserIdentityRequest() throws Exception {
            var httpRequest =
                    IdentityCallbackUtils.createUserIdentityRequest(
                            SUCCESSFUL_TOKEN_RESPONSE, BACKEND_URI);

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

            var response = IdentityCallbackUtils.sendUserIdentityRequest(mockedRequest);

            assertThat(response.getSubject(), equalTo(SUBJECT));
        }

        @Test
        void shouldThrowExceptionIfUserIdentityRequestExceedsNumberOfRetries() throws Exception {
            var mockedRequest = mock(HTTPRequest.class);
            when(mockedRequest.send()).thenReturn(unsuccessfulUserIdentityResponse());

            assertThrows(
                    UnsuccessfulCredentialResponseException.class,
                    () -> IdentityCallbackUtils.sendUserIdentityRequest(mockedRequest));
        }

        @Test
        void shouldReturnUserInfoResponseIfUserIdentityRequestIsSuccessfulAfterRetry()
                throws Exception {
            var mockedRequest = mock(HTTPRequest.class);
            when(mockedRequest.send())
                    .thenReturn(unsuccessfulUserIdentityResponse())
                    .thenReturn(successfulUserIdentityResponse());

            var response = IdentityCallbackUtils.sendUserIdentityRequest(mockedRequest);

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
                    () -> IdentityCallbackUtils.sendUserIdentityRequest(mockedRequest));
        }

        @Test
        void shouldThrowExceptionIfUserIdentityRequestIsInterrupted() throws Exception {
            var mockedRequest = mock(HTTPRequest.class);
            when(mockedRequest.send()).thenThrow(new IOException("Network interruption"));

            assertThrows(
                    RuntimeException.class,
                    () -> IdentityCallbackUtils.sendUserIdentityRequest(mockedRequest));
        }
    }

    @Nested
    class ValidateUserIdentityResponse {

        @Test
        void shouldReturnAccessDeniedIfVotIsNotContainedInRequestedLoCs() {
            var userInfo = new UserInfo(SUBJECT);
            userInfo.setClaim("vot", LevelOfConfidence.MEDIUM_LEVEL.getValue());

            var result =
                    validateUserIdentityResponse(
                            userInfo, List.of(LevelOfConfidence.NONE), TRUSTMARK_URL);

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
                            validateUserIdentityResponse(
                                    userInfo,
                                    List.of(LevelOfConfidence.MEDIUM_LEVEL),
                                    TRUSTMARK_URL));
        }

        @Test
        void shouldNotReturnErrorIfVotIsInRequestedLoCsAndVtmMatchesTrustmarkUrl() {
            var userInfo = new UserInfo(SUBJECT);
            userInfo.setClaim("vot", LevelOfConfidence.MEDIUM_LEVEL.getValue());
            userInfo.setClaim("vtm", TRUSTMARK_URL);

            var result =
                    validateUserIdentityResponse(
                            userInfo, List.of(LevelOfConfidence.MEDIUM_LEVEL), TRUSTMARK_URL);

            assertTrue(result.isEmpty());
        }
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

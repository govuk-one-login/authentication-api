package uk.gov.di.orchestration.shared.oauth;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequestSender;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ReadOnlyHTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import uk.gov.di.orchestration.shared.entity.OAuthConfiguration;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.services.OrchJwtService;
import uk.gov.di.orchestration.sharedtest.helper.Constants;

import java.io.IOException;
import java.text.ParseException;
import java.time.temporal.ChronoUnit;
import java.util.Set;

import static com.nimbusds.common.contenttype.ContentType.APPLICATION_JSON;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class OAuthServiceTest {
    private static final NowHelper.NowClock fixedNowClock =
            new NowHelper.NowClock(Constants.FIXED_CLOCK);
    private static final OAuthConfiguration TEST_OAUTH_CONFIG =
            new OAuthConfiguration(
                    Constants.TEST_CLIENT_ID,
                    Constants.TEST_AUTHORIZE_URI,
                    Constants.TEST_TOKEN_URI,
                    Constants.TEST_USERINFO_URI,
                    Constants.TEST_CALLBACK_URI,
                    Constants.TEST_SIGNING_KEY_ALIAS,
                    Constants.TEST_PRIVATE_KEY_JWT_AUDIENCE);

    private final OrchJwtService jwtService = mock(OrchJwtService.class);
    private final HTTPRequestSender mockHttpService = mock(HTTPRequestSender.class);
    private OAuthService oAuthService;

    @BeforeEach
    void setup() {
        oAuthService =
                new OAuthService(TEST_OAUTH_CONFIG, jwtService, fixedNowClock, mockHttpService);
    }

    @Nested
    class TokenRequestTests {
        private static final String MOCK_SERIALIZED_SIGNED_JWT =
                "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2MjY2ODQ1ODQsImlzcyI6Im15IGNsaWVudCBpZCIsInN1YiI6Im15IGNsaWVudCBpZCIsImF1ZCI6Imh0dHBzOi8vbXl0ZW5hbnQuYXV0aDAuY29tLyIsImV4cCI6MTYyNjY4NDY0NCwianRpIjoiZTRkYzhlZDEtYjEwOC00OTAxLThiYmMtYzA3YTc5MTgxN2U3In0.TSn6qTq2ioriY85GtPiC-a1ZvXSX5hmPRQ36DG3KV8e4-lWgTYru24yqBdg960pyAHp3OtNYzEaO_38eu7n9OK8c3biE1A5342PbSsLNS6IuI1MQTwM9nSS-u9RGehakKCYDpgUrjQloFcP-x3i944nAFOb708x_aa54L6SsLkL_gg565T0DWa56jFY35PSvybTIaPOq0LAquLrSlhOeClBCFOwx6HfAfgaDtbgbhtLAFDwdXXEUgSvhEUpIeSmN6FOcTXiyqZhTb70C2vM6JfICm-CEneUdMe8TpSo7QdDGhVKXjf-WJwUnkzjpgvkzU3MfYJOQIbiT-g4ytAOfqg";

        @Test
        void shouldCallTokenEndpointAndReturnWhenSuccessful()
                throws IOException, com.nimbusds.oauth2.sdk.ParseException {
            mockSigningJwt();
            var expectedTokenResponse = getSuccessfulTokenHttpResponse();
            when(mockHttpService.send(any(ReadOnlyHTTPRequest.class)))
                    .thenReturn(expectedTokenResponse);

            var tokenResponse = oAuthService.getToken(Constants.AUTHORIZATION_CODE.toString());

            assertThat(tokenResponse.indicatesSuccess(), equalTo(true));
            assertEquals(
                    expectedTokenResponse.getBodyAsJSONObject(),
                    tokenResponse.toHTTPResponse().getBodyAsJSONObject());
        }

        @Test
        void shouldRetryWithNewTokenRequestIfInitialRequestFails()
                throws IOException, com.nimbusds.oauth2.sdk.ParseException {
            mockSigningJwt();
            var expectedTokenResponse = getSuccessfulTokenHttpResponse();
            when(mockHttpService.send(any(ReadOnlyHTTPRequest.class)))
                    .thenReturn(failedTokenResponse())
                    .thenReturn(expectedTokenResponse);

            var tokenResponse = oAuthService.getToken(Constants.AUTHORIZATION_CODE.toString());

            assertThat(tokenResponse.indicatesSuccess(), equalTo(true));
            verify(mockHttpService, times(2)).send(any(ReadOnlyHTTPRequest.class));
            verify(jwtService, times(2))
                    .signJWT(any(JWTClaimsSet.class), eq(TEST_OAUTH_CONFIG.signingKeyAlias()));
            assertEquals(
                    expectedTokenResponse.getBodyAsJSONObject(),
                    tokenResponse.toHTTPResponse().getBodyAsJSONObject());
        }

        @Test
        void shouldReturnAFailureIfTwoCallsToTheTokenEndpointFail()
                throws IOException, com.nimbusds.oauth2.sdk.ParseException {
            mockSigningJwt();
            when(mockHttpService.send(any(ReadOnlyHTTPRequest.class)))
                    .thenReturn(failedTokenResponse())
                    .thenReturn(failedTokenResponse());

            var tokenResponse = oAuthService.getToken(Constants.AUTHORIZATION_CODE.toString());

            assertThat(tokenResponse.indicatesSuccess(), equalTo(false));
            verify(mockHttpService, times(2)).send(any(HTTPRequest.class));
            assertEquals(
                    failedTokenResponse().getBodyAsJSONObject(),
                    tokenResponse.toHTTPResponse().getBodyAsJSONObject());
        }

        @Test
        void eachTokenRequestShouldContainUniqueClientAssertionClaims() throws IOException {
            mockSigningJwt();
            when(mockHttpService.send(any(ReadOnlyHTTPRequest.class)))
                    .thenReturn(failedTokenResponse())
                    .thenReturn(getSuccessfulTokenHttpResponse());

            oAuthService.getToken(Constants.AUTHORIZATION_CODE.toString());

            var claimsSetArgumentCaptor = ArgumentCaptor.forClass(JWTClaimsSet.class);

            verify(mockHttpService, times(2)).send(any(HTTPRequest.class));
            verify(jwtService, times(2))
                    .signJWT(
                            claimsSetArgumentCaptor.capture(),
                            eq(TEST_OAUTH_CONFIG.signingKeyAlias()));

            var firstClaimSet = claimsSetArgumentCaptor.getAllValues().get(0);
            var secondClaimSet = claimsSetArgumentCaptor.getAllValues().get(1);
            assertNotEquals(firstClaimSet, secondClaimSet);
        }

        @Test
        void tokenRequestShouldContainPrivateKeyJwtClaims() throws IOException {
            mockSigningJwt();
            when(mockHttpService.send(any(ReadOnlyHTTPRequest.class)))
                    .thenReturn(getSuccessfulTokenHttpResponse());

            oAuthService.getToken(Constants.AUTHORIZATION_CODE.toString());

            var claimsSetArgumentCaptor = ArgumentCaptor.forClass(JWTClaimsSet.class);
            var expectedClaims =
                    new JWTClaimsSet.Builder()
                            // Our Client ID is provided as the issuer
                            .issuer(TEST_OAUTH_CONFIG.clientId())
                            .audience(TEST_OAUTH_CONFIG.privateKeyJwtAudience())
                            .expirationTime(fixedNowClock.nowPlus(5, ChronoUnit.MINUTES))
                            .issueTime(fixedNowClock.now())
                            .notBeforeTime(fixedNowClock.now())
                            .build();

            var verifier =
                    getFixedTimeJwtVerifier(
                            expectedClaims, Set.of("exp", "iat", "nbf", "jti", "iss"));
            verify(jwtService)
                    .signJWT(
                            claimsSetArgumentCaptor.capture(),
                            eq(TEST_OAUTH_CONFIG.signingKeyAlias()));

            var privateKeyJwtClaimsSet = claimsSetArgumentCaptor.getAllValues().get(0);

            assertDoesNotThrow(() -> verifier.verify(privateKeyJwtClaimsSet, null));
        }

        private void mockSigningJwt() {
            try {
                when(jwtService.signJWT(
                                any(JWTClaimsSet.class), eq(Constants.TEST_SIGNING_KEY_ALIAS)))
                        .thenReturn(SignedJWT.parse(MOCK_SERIALIZED_SIGNED_JWT));
            } catch (ParseException e) {
                throw new RuntimeException("Failed to parse JWT for test");
            }
        }

        private HTTPResponse getSuccessfulTokenHttpResponse() {
            var tokenResponseContent =
                    """
                    {
                        "access_token": "740e5834-3a29-46b4-9a6f-16142fde533a",
                        "token_type": "Bearer",
                        "expires_in": 3600
                    }
                    """;
            var tokenHTTPResponse = new HTTPResponse(200);
            tokenHTTPResponse.setEntityContentType(APPLICATION_JSON);
            tokenHTTPResponse.setBody(tokenResponseContent);

            return tokenHTTPResponse;
        }

        private HTTPResponse failedTokenResponse() {
            var tokenResponseContent =
                    """
                    {
                        "error": "invalid_grant",
                        "error_description": "Client authentication failed"
                    }
                    """;

            var tokenHTTPResponse = new HTTPResponse(401);
            tokenHTTPResponse.setEntityContentType(APPLICATION_JSON);
            tokenHTTPResponse.setBody(tokenResponseContent);
            return tokenHTTPResponse;
        }

        private DefaultJWTClaimsVerifier<SecurityContext> getFixedTimeJwtVerifier(
                JWTClaimsSet expectedJwtClaimSet, Set<String> mandatoryClaims) {
            return new DefaultJWTClaimsVerifier<>(expectedJwtClaimSet, mandatoryClaims) {
                @Override
                protected java.util.Date currentTime() {
                    // Add 5 seconds so current time is ahead of iat and nbf
                    return fixedNowClock.nowPlus(5, ChronoUnit.SECONDS);
                }
            };
        }
    }
}

package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.TokenGeneratorHelper;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.nimbusds.oauth2.sdk.token.BearerTokenError.INVALID_TOKEN;
import static com.nimbusds.oauth2.sdk.token.BearerTokenError.MISSING_TOKEN;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class UserInfoHandlerTest {

    private static final String EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String PHONE_NUMBER = "01234567890";
    private static final Subject SUBJECT = new Subject();
    private final Context context = mock(Context.class);
    private final RedisConnectionService redisConnectionService =
            mock(RedisConnectionService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private static final Map<String, List<String>> INVALID_TOKEN_RESPONSE =
            new UserInfoErrorResponse(INVALID_TOKEN).toHTTPResponse().getHeaderMap();
    private UserInfoHandler handler;

    @BeforeEach
    public void setUp() {
        handler =
                new UserInfoHandler(
                        configurationService, authenticationService, redisConnectionService);
    }

    @Test
    public void shouldReturn200WithUserInfoBasedOnScopesForSuccessfulRequest()
            throws ParseException, JOSEException {
        ECKey ecSigningKey = new ECKeyGenerator(Curve.P_256).generate();
        JWSSigner signer = new ECDSASigner(ecSigningKey);
        List<String> scopes = new ArrayList<>();
        scopes.add("email");
        scopes.add("phone");
        SignedJWT signedAccessToken =
                TokenGeneratorHelper.generateAccessToken(
                        "client-id",
                        "issuer-url",
                        scopes,
                        signer,
                        SUBJECT,
                        ecSigningKey.getKeyID());
        AccessToken accessToken = new BearerAccessToken(signedAccessToken.serialize());
        UserProfile userProfile =
                new UserProfile()
                        .setEmail(EMAIL_ADDRESS)
                        .setEmailVerified(true)
                        .setPhoneNumber(PHONE_NUMBER)
                        .setPhoneNumberVerified(true)
                        .setSubjectID(SUBJECT.toString())
                        .setCreated(LocalDateTime.now().toString())
                        .setUpdated(LocalDateTime.now().toString());
        when(redisConnectionService.getValue(accessToken.toJSONString()))
                .thenReturn(SUBJECT.toString());
        when(authenticationService.getUserProfileFromSubject(SUBJECT.toString()))
                .thenReturn(userProfile);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Authorization", accessToken.toAuthorizationHeader()));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        UserInfo parsedResultBody = UserInfo.parse(result.getBody());
        assertThat(parsedResultBody.getSubject(), equalTo(SUBJECT));
        assertThat(parsedResultBody.getEmailAddress(), equalTo(EMAIL_ADDRESS));
        assertTrue(parsedResultBody.getEmailVerified());
        assertThat(parsedResultBody.getPhoneNumber(), equalTo(PHONE_NUMBER));
        assertTrue(parsedResultBody.getPhoneNumberVerified());
    }

    @Test
    public void shouldReturn401WhenBearerTokenIsNotParseable() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Authorization", "this-is-not-a-valid-token"));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(401));
        assertEquals(INVALID_TOKEN_RESPONSE, result.getMultiValueHeaders());
    }

    @Test
    public void shouldReturn401WhenAuthorizationHeaderIsMissing() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(401));
        Map<String, List<String>> missingTokenExpectedResponse =
                new UserInfoErrorResponse(MISSING_TOKEN).toHTTPResponse().getHeaderMap();
        assertEquals(missingTokenExpectedResponse, result.getMultiValueHeaders());
    }

    @Test
    public void shouldReturn401WhenAccessTokenIsNotValid() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Authorization", new BearerAccessToken().toAuthorizationHeader()));

        when(redisConnectionService.getValue(anyString())).thenReturn(null);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(401));
        assertEquals(INVALID_TOKEN_RESPONSE, result.getMultiValueHeaders());
    }
}

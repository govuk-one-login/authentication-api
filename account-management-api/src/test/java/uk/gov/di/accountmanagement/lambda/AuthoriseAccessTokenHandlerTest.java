package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.entity.AuthPolicy;
import uk.gov.di.accountmanagement.entity.TokenAuthorizerContext;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.TokenValidationService;
import uk.gov.di.authentication.sharedtest.helper.TokenGeneratorHelper;

import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthoriseAccessTokenHandlerTest {

    private final TokenValidationService tokenValidationServicen =
            mock(TokenValidationService.class);
    private final DynamoService dynamoService = mock(DynamoService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final DynamoClientService clientService = mock(DynamoClientService.class);
    private AuthoriseAccessTokenHandler handler;
    private final Context context = mock(Context.class);
    private static final String KEY_ID = "14342354354353";
    private static final String TOKEN_TYPE = "TOKEN";
    private static final String CLIENT_ID = "client-id";
    private static final String METHOD_ARN =
            "arn:aws:execute-api:eu-west-2:123456789012:ymy8tbxw7b/*/POST/";
    private static final List<String> SCOPES = List.of("openid", "email", "phone", "am");
    private static final List<String> INVALID_SCOPES = List.of("openid", "email", "phone");

    private static final Subject SUBJECT = new Subject("some-subject");

    @BeforeEach
    public void setUp() {
        handler =
                new AuthoriseAccessTokenHandler(
                        tokenValidationServicen,
                        configurationService,
                        dynamoService,
                        clientService);
    }

    @Test
    public void shouldReturnAuthPolicyForSuccessfulRequest() throws JOSEException {
        BearerAccessToken signedAccessToken =
                new BearerAccessToken(createSignedAccessToken(SCOPES).serialize());
        TokenAuthorizerContext tokenAuthorizerContext =
                new TokenAuthorizerContext(
                        TOKEN_TYPE, signedAccessToken.toAuthorizationHeader(), METHOD_ARN);
        when(tokenValidationServicen.validateAccessTokenSignature(signedAccessToken))
                .thenReturn(true);
        when(clientService.isValidClient(CLIENT_ID)).thenReturn(true);
        AuthPolicy authPolicy = handler.handleRequest(tokenAuthorizerContext, context);

        assertThat(authPolicy.getPrincipalId(), equalTo(SUBJECT.getValue()));
        assertNotNull(authPolicy.getPolicyDocument().get("Statement"));
    }

    @Test
    public void shouldThrowExceptionWhenAccessTokenHasExpired() throws JOSEException {
        BearerAccessToken signedAccessToken =
                new BearerAccessToken(createSignedExpiredAccessToken(SCOPES).serialize());
        TokenAuthorizerContext tokenAuthorizerContext =
                new TokenAuthorizerContext(
                        TOKEN_TYPE, signedAccessToken.toAuthorizationHeader(), METHOD_ARN);

        RuntimeException exception =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(tokenAuthorizerContext, context),
                        "Expected to throw exception");

        assertEquals("Unauthorized", exception.getMessage());
    }

    @Test
    public void shouldThrowExceptionWhenAccessTokenHasInvalidSignature() throws JOSEException {
        BearerAccessToken signedAccessToken =
                new BearerAccessToken(createSignedAccessToken(SCOPES).serialize());
        TokenAuthorizerContext tokenAuthorizerContext =
                new TokenAuthorizerContext(
                        TOKEN_TYPE, signedAccessToken.toAuthorizationHeader(), METHOD_ARN);
        when(tokenValidationServicen.validateAccessTokenSignature(signedAccessToken))
                .thenReturn(false);

        RuntimeException exception =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(tokenAuthorizerContext, context),
                        "Expected to throw exception");

        assertEquals("Unauthorized", exception.getMessage());
    }

    @Test
    public void shouldThrowExceptionWhenSubjectIdCannotBeLinkedToAUser() throws JOSEException {
        BearerAccessToken signedAccessToken =
                new BearerAccessToken(createSignedAccessToken(SCOPES).serialize());
        TokenAuthorizerContext tokenAuthorizerContext =
                new TokenAuthorizerContext(
                        TOKEN_TYPE, signedAccessToken.toAuthorizationHeader(), METHOD_ARN);
        when(tokenValidationServicen.validateAccessTokenSignature(signedAccessToken))
                .thenReturn(true);
        when(dynamoService.getUserProfileFromSubject(SUBJECT.getValue()))
                .thenThrow(RuntimeException.class);

        RuntimeException exception =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(tokenAuthorizerContext, context),
                        "Expected to throw exception");

        assertEquals("Unauthorized", exception.getMessage());
    }

    @Test
    public void shouldThrowExceptionWhenInvalidAccessTokenIsSentInRequest() throws JOSEException {
        String invalidAccessToken = createSignedAccessToken(SCOPES).serialize();
        TokenAuthorizerContext tokenAuthorizerContext =
                new TokenAuthorizerContext(TOKEN_TYPE, invalidAccessToken, METHOD_ARN);

        RuntimeException exception =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(tokenAuthorizerContext, context),
                        "Expected to throw exception");

        assertEquals("Unauthorized", exception.getMessage());
    }

    @Test
    public void shouldThrowExceptionWhenAccessTokenHasNotBeenSigned() {
        TokenAuthorizerContext tokenAuthorizerContext =
                new TokenAuthorizerContext(
                        TOKEN_TYPE, new BearerAccessToken().toAuthorizationHeader(), METHOD_ARN);

        RuntimeException exception =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(tokenAuthorizerContext, context),
                        "Expected to throw exception");

        assertEquals("Unauthorized", exception.getMessage());
    }

    @Test
    public void shouldThrowExceptionWhenAccessTokenHasInvalidScopes() throws JOSEException {
        BearerAccessToken signedAccessToken =
                new BearerAccessToken(createSignedAccessToken(INVALID_SCOPES).serialize());
        TokenAuthorizerContext tokenAuthorizerContext =
                new TokenAuthorizerContext(
                        TOKEN_TYPE, signedAccessToken.toAuthorizationHeader(), METHOD_ARN);
        when(tokenValidationServicen.validateAccessTokenSignature(signedAccessToken))
                .thenReturn(true);

        RuntimeException exception =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(tokenAuthorizerContext, context),
                        "Expected to throw exception");

        assertEquals("Unauthorized", exception.getMessage());
    }

    private SignedJWT createSignedAccessToken(List<String> scopes) throws JOSEException {
        ECKey ecJWK = new ECKeyGenerator(Curve.P_256).keyID(KEY_ID).generate();
        JWSSigner signer = new ECDSASigner(ecJWK);
        return TokenGeneratorHelper.generateSignedToken(
                CLIENT_ID, "http://example.com", scopes, signer, SUBJECT, "14342354354353");
    }

    private SignedJWT createSignedExpiredAccessToken(List<String> scopes) throws JOSEException {
        Date expiryDate = NowHelper.nowMinus(2, ChronoUnit.MINUTES);
        ECKey ecJWK = new ECKeyGenerator(Curve.P_256).keyID(KEY_ID).generate();
        JWSSigner signer = new ECDSASigner(ecJWK);
        return TokenGeneratorHelper.generateSignedToken(
                CLIENT_ID,
                "http://example.com",
                scopes,
                signer,
                SUBJECT,
                "14342354354353",
                expiryDate);
    }
}

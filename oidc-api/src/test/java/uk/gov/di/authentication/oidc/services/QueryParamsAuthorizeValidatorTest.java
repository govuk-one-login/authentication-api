package uk.gov.di.authentication.oidc.services;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import uk.gov.di.authentication.oidc.validators.QueryParamsAuthorizeValidator;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.CustomScopeValue;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.ValidClaims;
import uk.gov.di.orchestration.shared.exceptions.ClientRedirectUriValidationException;
import uk.gov.di.orchestration.shared.exceptions.InvalidResponseModeException;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.sharedtest.helper.JsonArrayHelper.jsonArrayOf;
import static uk.gov.di.orchestration.sharedtest.logging.LogEventMatcher.withMessageContaining;

class QueryParamsAuthorizeValidatorTest {

    private static final URI REDIRECT_URI = URI.create("http://localhost/redirect");
    private static final List<String> DEFAULT_CLIENT_LOCS =
            List.of(LevelOfConfidence.MEDIUM_LEVEL.getValue(), LevelOfConfidence.NONE.getValue());
    private static final ClientID CLIENT_ID = new ClientID();
    private static final State STATE = new State();
    private static final Nonce NONCE = new Nonce();
    private static final int MAX_AGE = 1800;
    private static final ResponseType VALID_RESPONSE_TYPE =
            new ResponseType(ResponseType.Value.CODE);
    private static final Scope VALID_SCOPES = new Scope(OIDCScopeValue.OPENID);
    private QueryParamsAuthorizeValidator queryParamsAuthorizeValidator;
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private final IPVCapacityService ipvCapacityService = mock(IPVCapacityService.class);

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(QueryParamsAuthorizeValidator.class);

    @BeforeEach
    void setUp() {
        queryParamsAuthorizeValidator =
                new QueryParamsAuthorizeValidator(
                        configurationService, dynamoClientService, ipvCapacityService);
        var keyPair = generateRsaKeyPair();
        String publicCertificateAsPem =
                "-----BEGIN PUBLIC KEY-----\n"
                        + Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded())
                        + "\n-----END PUBLIC KEY-----\n";
        when(configurationService.getOrchestrationToAuthenticationEncryptionPublicKey())
                .thenReturn(publicCertificateAsPem);
        when(configurationService.getEnvironment()).thenReturn("test");
        when(dynamoClientService.getClient(CLIENT_ID.toString()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        REDIRECT_URI.toString(), CLIENT_ID.toString())));
    }

    @AfterEach
    void tearDown() {
        assertThat(logging.events(), not(hasItem(withMessageContaining(CLIENT_ID.toString()))));
    }

    @Test
    void shouldSuccessfullyValidateAuthRequestWhenIdentityValuesAreIncludedInVtrAttribute() {
        when(ipvCapacityService.isIPVCapacityAvailable()).thenReturn(true);
        AuthenticationRequest authRequest =
                generateAuthRequest(
                        REDIRECT_URI.toString(),
                        VALID_RESPONSE_TYPE,
                        VALID_SCOPES,
                        jsonArrayOf("P2.Cl.Cm"),
                        Optional.empty());
        var errorObject = queryParamsAuthorizeValidator.validate(authRequest);

        assertThat(errorObject, equalTo(Optional.empty()));
    }

    private static Stream<Arguments> invalidVtrAttributes() {
        return Stream.of(
                Arguments.of(jsonArrayOf("Cm")),
                Arguments.of(jsonArrayOf("Cl.Cm.P3")),
                Arguments.of(jsonArrayOf("Cl.P0", "Cl.Cm.P2")),
                Arguments.of(jsonArrayOf("Cm.Cl.P1", "P1.Cl")),
                Arguments.of(jsonArrayOf("Cl.PCL250.Cm", "Cl.PCL200.Cm")));
    }

    @ParameterizedTest
    @MethodSource("invalidVtrAttributes")
    void shouldReturnErrorWhenInvalidVtrAttributeIsSentInRequest(String invalidVtrAttribute) {
        AuthenticationRequest authRequest =
                generateAuthRequest(
                        REDIRECT_URI.toString(),
                        VALID_RESPONSE_TYPE,
                        VALID_SCOPES,
                        invalidVtrAttribute,
                        Optional.empty());
        var errorObject = queryParamsAuthorizeValidator.validate(authRequest);

        assertTrue(errorObject.isPresent());

        assertThat(
                errorObject.get().errorObject(),
                equalTo(
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE, "Request vtr not valid")));
        assertEquals(STATE, errorObject.get().state());
    }

    @Test
    void shouldSuccessfullyValidateAuthRequest() {
        var errorObject =
                queryParamsAuthorizeValidator.validate(
                        generateAuthRequest(
                                REDIRECT_URI.toString(), VALID_RESPONSE_TYPE, VALID_SCOPES));

        assertTrue(errorObject.isEmpty());
    }

    private static Stream<String> validClaims() {
        return ValidClaims.getAllValidClaims().stream();
    }

    @ParameterizedTest
    @MethodSource("validClaims")
    void shouldSuccessfullyValidateAuthRequestWhenValidClaimsArePresent(String validClaim) {
        var clientRegistry =
                new ClientRegistry()
                        .withRedirectUrls(singletonList(REDIRECT_URI.toString()))
                        .withClientID(CLIENT_ID.toString())
                        .withScopes(VALID_SCOPES.toStringList())
                        .withClaims(List.of(validClaim));
        when(dynamoClientService.getClient(CLIENT_ID.toString()))
                .thenReturn(Optional.of(clientRegistry));
        var claimsSetRequest = new ClaimsSetRequest().add(validClaim);
        var oidcClaimsRequest = new OIDCClaimsRequest().withUserInfoClaimsRequest(claimsSetRequest);
        var authRequest =
                generateAuthRequest(
                        REDIRECT_URI.toString(),
                        VALID_RESPONSE_TYPE,
                        VALID_SCOPES,
                        jsonArrayOf("Cl.Cm", "Cl"),
                        Optional.of(oidcClaimsRequest));
        var errorObject = queryParamsAuthorizeValidator.validate(authRequest);

        assertTrue(errorObject.isEmpty());
    }

    @Test
    void shouldReturnErrorWhenValidatingAuthRequestWhichContainsInvalidClaims() {
        var claimsSetRequest = new ClaimsSetRequest().add("nickname").add("birthdate");
        var oidcClaimsRequest = new OIDCClaimsRequest().withUserInfoClaimsRequest(claimsSetRequest);
        AuthenticationRequest authRequest =
                generateAuthRequest(
                        REDIRECT_URI.toString(),
                        VALID_RESPONSE_TYPE,
                        VALID_SCOPES,
                        jsonArrayOf("Cl.Cm", "Cl"),
                        Optional.of(oidcClaimsRequest));
        var errorObject = queryParamsAuthorizeValidator.validate(authRequest);

        assertTrue(errorObject.isPresent());
        assertThat(
                errorObject.get().errorObject(),
                equalTo(
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE,
                                "Request contains invalid claims")));
        assertEquals(STATE, errorObject.get().state());
    }

    @Test
    void shouldAcceptEmptyClaimsObject() throws ParseException {
        var authRequest =
                AuthenticationRequest.parse(
                        "client_id="
                                + CLIENT_ID
                                + "&redirect_uri="
                                + REDIRECT_URI
                                + "&response_type=code&scope=openid&nonce=1234&vtr=%5B%22Cl%22%5D&claims=%7B%0D%0A%20%20%22userinfo%22%3A%20%7B%7D%0D%0A%7D&state=ABCD");
        var errorObject = queryParamsAuthorizeValidator.validate(authRequest);
        assertEquals(Optional.empty(), errorObject);
    }

    @Test
    void shouldSuccessfullyValidateAccountManagementAuthRequest() {
        Scope accountManagementScope =
                new Scope(OIDCScopeValue.OPENID, CustomScopeValue.ACCOUNT_MANAGEMENT);
        when(dynamoClientService.getClient(CLIENT_ID.toString()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        REDIRECT_URI.toString(),
                                        CLIENT_ID.toString(),
                                        List.of("openid", "am"))));
        var errorObject =
                queryParamsAuthorizeValidator.validate(
                        generateAuthRequest(
                                REDIRECT_URI.toString(),
                                VALID_RESPONSE_TYPE,
                                accountManagementScope));

        assertTrue(errorObject.isEmpty());
    }

    @Test
    void shouldReturnErrorForAccountManagementAuthRequestWhenScopeNotInClient() {
        Scope accountManagementScope =
                new Scope(OIDCScopeValue.OPENID, CustomScopeValue.ACCOUNT_MANAGEMENT);
        var errorObject =
                queryParamsAuthorizeValidator.validate(
                        generateAuthRequest(
                                REDIRECT_URI.toString(),
                                VALID_RESPONSE_TYPE,
                                accountManagementScope));

        assertTrue(errorObject.isPresent());
        assertThat(errorObject.get().errorObject(), equalTo(OAuth2Error.INVALID_SCOPE));
        assertEquals(STATE, errorObject.get().state());
    }

    @Test
    void shouldReturnErrorWhenClientIdIsNotValidInAuthRequest() {
        when(dynamoClientService.getClient(CLIENT_ID.toString())).thenReturn(Optional.empty());
        var runtimeException =
                assertThrows(
                        RuntimeException.class,
                        () ->
                                queryParamsAuthorizeValidator.validate(
                                        generateAuthRequest(
                                                REDIRECT_URI.toString(),
                                                VALID_RESPONSE_TYPE,
                                                VALID_SCOPES)),
                        "Expected to throw exception");

        assertThat(runtimeException.getMessage(), equalTo("No Client found with given ClientID"));
    }

    @Test
    void shouldReturnErrorWhenResponseTypeIsNotValidInAuthRequest() {
        ResponseType invalidResponseType =
                new ResponseType(ResponseType.Value.TOKEN, ResponseType.Value.CODE);
        var errorObject =
                queryParamsAuthorizeValidator.validate(
                        generateAuthRequest(
                                REDIRECT_URI.toString(), invalidResponseType, VALID_SCOPES));

        assertTrue(errorObject.isPresent());
        assertThat(errorObject.get().errorObject(), equalTo(OAuth2Error.UNSUPPORTED_RESPONSE_TYPE));
        assertEquals(STATE, errorObject.get().state());
    }

    @Test
    void shouldReturnErrorWhenScopeIsNotValidInAuthRequest() {
        Scope invalidScopes = new Scope();
        invalidScopes.add(OIDCScopeValue.OPENID);
        invalidScopes.add(OIDCScopeValue.EMAIL);
        var errorObject =
                queryParamsAuthorizeValidator.validate(
                        generateAuthRequest(
                                REDIRECT_URI.toString(), VALID_RESPONSE_TYPE, invalidScopes));

        assertTrue(errorObject.isPresent());
        assertThat(errorObject.get().errorObject(), equalTo(OAuth2Error.INVALID_SCOPE));
        assertEquals(STATE, errorObject.get().state());
    }

    @Test
    void shouldReturnErrorWhenStateIsNotIncludedInAuthRequest() {
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                VALID_RESPONSE_TYPE,
                                VALID_SCOPES,
                                new ClientID(CLIENT_ID),
                                REDIRECT_URI)
                        .nonce(new Nonce())
                        .build();
        var errorObject = queryParamsAuthorizeValidator.validate(authRequest);

        assertTrue(errorObject.isPresent());
        assertThat(
                errorObject.get().errorObject(),
                equalTo(
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE,
                                "Request is missing state parameter")));
        assertNull(errorObject.get().state());
    }

    @Test
    void shouldSuccessfullyValidateWhenNonceNotExpectedAndMissing() {
        var clientRegitry =
                generateClientRegistry(REDIRECT_URI.toString(), CLIENT_ID.toString())
                        .withPermitMissingNonce(true);

        when(dynamoClientService.getClient(CLIENT_ID.toString()))
                .thenReturn(Optional.of(clientRegitry));

        AuthenticationRequest authenticationRequest =
                new AuthenticationRequest.Builder(
                                VALID_RESPONSE_TYPE, VALID_SCOPES, CLIENT_ID, REDIRECT_URI)
                        .state(STATE)
                        .maxAge(MAX_AGE)
                        .build();
        var errorObject = queryParamsAuthorizeValidator.validate(authenticationRequest);

        assertTrue(errorObject.isEmpty());
    }

    @Test
    void shouldReturnErrorWhenNonceIsExpectedAndMissing() {
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                VALID_RESPONSE_TYPE,
                                VALID_SCOPES,
                                new ClientID(CLIENT_ID),
                                REDIRECT_URI)
                        .state(STATE)
                        .build();
        var errorObject = queryParamsAuthorizeValidator.validate(authRequest);

        assertTrue(errorObject.isPresent());
        assertThat(
                errorObject.get().errorObject(),
                equalTo(
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE,
                                "Request is missing nonce parameter")));
        assertEquals(STATE, errorObject.get().state());
    }

    private static Stream<Arguments> requestVtrsNotPermitted() {
        return Stream.of(
                Arguments.of(List.of(LevelOfConfidence.NONE.getValue()), jsonArrayOf("Cl.P2.Cm")),
                Arguments.of(
                        List.of(
                                LevelOfConfidence.NONE.getValue(),
                                LevelOfConfidence.MEDIUM_LEVEL.getValue()),
                        jsonArrayOf("Cl.PCL250.Cm")),
                Arguments.of(
                        List.of(
                                LevelOfConfidence.NONE.getValue(),
                                LevelOfConfidence.MEDIUM_LEVEL.getValue()),
                        jsonArrayOf("PCL200.Cl.Cm", "Cl.P2.Cm")),
                Arguments.of(
                        List.of(
                                LevelOfConfidence.NONE.getValue(),
                                LevelOfConfidence.HMRC250.getValue(),
                                LevelOfConfidence.MEDIUM_LEVEL.getValue()),
                        jsonArrayOf("Cl.PCL250.Cm", "Cl.PCL200.Cm")));
    }

    @ParameterizedTest
    @MethodSource("requestVtrsNotPermitted")
    void shouldReturnErrorWhenVtrInAuthRequestIsNotPermittedForGivenClient(
            List<String> clientLoCs, String vtr) {
        when(dynamoClientService.getClient(CLIENT_ID.toString()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        REDIRECT_URI.toString(),
                                        clientLoCs,
                                        CLIENT_ID.toString())));
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                VALID_RESPONSE_TYPE, VALID_SCOPES, CLIENT_ID, REDIRECT_URI)
                        .state(STATE)
                        .nonce(new Nonce())
                        .customParameter("vtr", vtr)
                        .build();
        var errorObject = queryParamsAuthorizeValidator.validate(authRequest);

        assertTrue(errorObject.isPresent());
        assertThat(
                errorObject.get().errorObject().toJSONObject(),
                equalTo(
                        new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE,
                                        "Request vtr is not permitted")
                                .toJSONObject()));
    }

    @Test
    void shouldNotReturnErrorWhenPkceCodeChallengeAndMethodAreMissingAndPkceIsNotEnabled() {
        when(configurationService.isPkceEnabled()).thenReturn(false);

        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                VALID_RESPONSE_TYPE,
                                VALID_SCOPES,
                                new ClientID(CLIENT_ID),
                                REDIRECT_URI)
                        .state(STATE)
                        .nonce(new Nonce())
                        .build();

        var errorObject = queryParamsAuthorizeValidator.validate(authRequest);

        assertTrue(errorObject.isEmpty());
    }

    @Test
    void shouldNotReturnErrorWhenPkceCodeChallengeAndMethodAreMissingAndPkceIsEnabled() {
        when(configurationService.isPkceEnabled()).thenReturn(true);
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                VALID_RESPONSE_TYPE,
                                VALID_SCOPES,
                                new ClientID(CLIENT_ID),
                                REDIRECT_URI)
                        .state(STATE)
                        .nonce(new Nonce())
                        .build();

        var errorObject = queryParamsAuthorizeValidator.validate(authRequest);

        assertTrue(errorObject.isEmpty());
    }

    @Test
    void shouldReturnErrorWhenPkceIsEnforcedAndCodeChallengeMissing() {
        var clientRegistry = generateClientRegistry(REDIRECT_URI.toString(), CLIENT_ID.toString());
        clientRegistry.setPKCEEnforced(true);
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(clientRegistry));
        when(configurationService.isPkceEnabled()).thenReturn(true);

        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                VALID_RESPONSE_TYPE,
                                VALID_SCOPES,
                                new ClientID(CLIENT_ID),
                                REDIRECT_URI)
                        .state(STATE)
                        .nonce(new Nonce())
                        .build();

        var errorObject = queryParamsAuthorizeValidator.validate(authRequest);

        assertTrue(errorObject.isPresent());
        assertThat(
                errorObject.get().errorObject().toJSONObject(),
                equalTo(
                        new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE,
                                        "Request is missing code_challenge parameter, but PKCE is enforced.")
                                .toJSONObject()));
        assertEquals(STATE, errorObject.get().state());
    }

    @Test
    @SuppressWarnings("deprecation")
    void shouldReturnErrorWhenPkceCodeChallengeMethodIsExpectedAndIsMissing()
            throws ParseException {
        when(configurationService.isPkceEnabled()).thenReturn(true);

        var codeChallenge = CodeChallenge.parse("aCodeChallenge");

        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                VALID_RESPONSE_TYPE,
                                VALID_SCOPES,
                                new ClientID(CLIENT_ID),
                                REDIRECT_URI)
                        .state(STATE)
                        .nonce(new Nonce())
                        .codeChallenge(codeChallenge, null)
                        .build();

        var errorObject = queryParamsAuthorizeValidator.validate(authRequest);

        assertTrue(errorObject.isPresent());
        assertThat(
                errorObject.get().errorObject().toJSONObject(),
                equalTo(
                        new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE,
                                        "Request is missing code_challenge_method parameter. code_challenge_method is required when code_challenge is present.")
                                .toJSONObject()));
        assertEquals(STATE, errorObject.get().state());
    }

    @Test
    @SuppressWarnings("deprecation")
    void shouldReturnErrorWhenPkceCodeChallengeMethodIsExpectedAndIsInvalid()
            throws ParseException {
        when(configurationService.isPkceEnabled()).thenReturn(true);

        var codeChallenge = CodeChallenge.parse("aCodeChallenge");
        var codeChallengeMethod = CodeChallengeMethod.PLAIN;

        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                VALID_RESPONSE_TYPE,
                                VALID_SCOPES,
                                new ClientID(CLIENT_ID),
                                REDIRECT_URI)
                        .state(STATE)
                        .nonce(new Nonce())
                        .codeChallenge(codeChallenge, codeChallengeMethod)
                        .build();

        var errorObject = queryParamsAuthorizeValidator.validate(authRequest);

        assertTrue(errorObject.isPresent());
        assertThat(
                errorObject.get().errorObject().toJSONObject(),
                equalTo(
                        new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE,
                                        "Invalid value for code_challenge_method parameter.")
                                .toJSONObject()));
        assertEquals(STATE, errorObject.get().state());
    }

    @Test
    @SuppressWarnings("deprecation")
    void shouldNotReturnErrorWhenPkceCodeChallengeAndMethodAreValid() throws ParseException {
        when(configurationService.isPkceEnabled()).thenReturn(true);

        var codeChallenge = CodeChallenge.parse("aCodeChallenge");
        var codeChallengeMethod = CodeChallengeMethod.S256;

        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                VALID_RESPONSE_TYPE,
                                VALID_SCOPES,
                                new ClientID(CLIENT_ID),
                                REDIRECT_URI)
                        .state(STATE)
                        .nonce(new Nonce())
                        .codeChallenge(codeChallenge, codeChallengeMethod)
                        .build();

        var errorObject = queryParamsAuthorizeValidator.validate(authRequest);

        assertTrue(errorObject.isEmpty());
    }

    @Test
    void shouldReturnErrorWhenIdentityIsRequiredButNoIPVCapacityIsAvailable() {
        when(ipvCapacityService.isIPVCapacityAvailable()).thenReturn(false);
        var authRequest =
                new AuthenticationRequest.Builder(
                                VALID_RESPONSE_TYPE, VALID_SCOPES, CLIENT_ID, REDIRECT_URI)
                        .state(STATE)
                        .nonce(new Nonce())
                        .customParameter("vtr", jsonArrayOf("P2.Cl.Cm"))
                        .build();
        var errorObject = queryParamsAuthorizeValidator.validate(authRequest);

        assertTrue(errorObject.isPresent());
        assertThat(errorObject.get().errorObject(), equalTo(OAuth2Error.TEMPORARILY_UNAVAILABLE));
        assertEquals(STATE, errorObject.get().state());
    }

    @Test
    void
            shouldNotReturnErrorWhenIdentityIsRequiredButNoIPVCapacityIsAvailableAndTheClientIsATestClient() {
        when(ipvCapacityService.isIPVCapacityAvailable()).thenReturn(false);
        when(dynamoClientService.getClient(CLIENT_ID.toString()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        REDIRECT_URI.toString(),
                                        CLIENT_ID.toString(),
                                        singletonList("openid"),
                                        true,
                                        DEFAULT_CLIENT_LOCS)));
        var authRequest =
                new AuthenticationRequest.Builder(
                                VALID_RESPONSE_TYPE, VALID_SCOPES, CLIENT_ID, REDIRECT_URI)
                        .state(new State())
                        .nonce(new Nonce())
                        .maxAge(MAX_AGE)
                        .customParameter("vtr", jsonArrayOf("P2.Cl.Cm"))
                        .build();
        var errorObject = queryParamsAuthorizeValidator.validate(authRequest);

        assertTrue(errorObject.isEmpty());
    }

    @Test
    void shouldThrowExceptionWhenRedirectUriIsInvalidInAuthRequest() {
        String redirectUri = "http://localhost/redirect";
        when(dynamoClientService.getClient(CLIENT_ID.toString()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        "http://localhost/wrong-redirect", CLIENT_ID.toString())));

        var exception =
                assertThrows(
                        ClientRedirectUriValidationException.class,
                        () ->
                                queryParamsAuthorizeValidator.validate(
                                        generateAuthRequest(
                                                redirectUri, VALID_RESPONSE_TYPE, VALID_SCOPES)),
                        "Expected to throw exception");
        assertThat(
                exception.getMessage(),
                equalTo(format("Invalid Redirect in request %s", redirectUri)));
    }

    @Test
    void shouldReturnErrorWhenRequestURIIsPresent() {
        var authenticationRequest =
                new AuthenticationRequest.Builder(
                                VALID_RESPONSE_TYPE, VALID_SCOPES, CLIENT_ID, REDIRECT_URI)
                        .requestURI(URI.create("https://localhost/redirect-uri"))
                        .state(STATE)
                        .build();

        var authRequestError = queryParamsAuthorizeValidator.validate(authenticationRequest);

        assertTrue(authRequestError.isPresent());
        assertThat(
                authRequestError.get().errorObject(),
                equalTo(OAuth2Error.REQUEST_URI_NOT_SUPPORTED));
        assertEquals(STATE, authRequestError.get().state());
    }

    @Test
    void shouldReturnErrorWhenMaxAgeIsInvalid() {
        AuthenticationRequest.Builder authRequestBuilder =
                new AuthenticationRequest.Builder(
                                VALID_RESPONSE_TYPE, VALID_SCOPES, CLIENT_ID, REDIRECT_URI)
                        .state(STATE)
                        .nonce(NONCE)
                        .maxAge(-5);
        var errorObject = queryParamsAuthorizeValidator.validate(authRequestBuilder.build());

        assertTrue(errorObject.isPresent());
        assertThat(
                errorObject.get().errorObject(),
                equalTo(
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE,
                                "Value of max age cannot be lower than -1")));
        assertEquals(STATE, errorObject.get().state());
    }

    @Test
    void shouldThrowInvalidResponseModeErrorWhenResponseModeIsInvalid() {
        AuthenticationRequest.Builder authRequestBuilder =
                new AuthenticationRequest.Builder(
                                VALID_RESPONSE_TYPE, VALID_SCOPES, CLIENT_ID, REDIRECT_URI)
                        .state(STATE)
                        .nonce(NONCE)
                        .responseMode(new ResponseMode("code"));

        assertThrows(
                InvalidResponseModeException.class,
                () -> queryParamsAuthorizeValidator.validate(authRequestBuilder.build()));
    }

    @Test
    void shouldThrowWhenResponseModeIsInvalidBeforeValidatingARedirectingError() {
        // No state is an error we redirect back to the RP with an error message with
        AuthenticationRequest.Builder authRequestBuilder =
                new AuthenticationRequest.Builder(
                                VALID_RESPONSE_TYPE, VALID_SCOPES, CLIENT_ID, REDIRECT_URI)
                        .nonce(NONCE)
                        .responseMode(new ResponseMode("code"));

        assertThrows(
                InvalidResponseModeException.class,
                () -> queryParamsAuthorizeValidator.validate(authRequestBuilder.build()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"query", "fragment"})
    void shouldAllowValidResponseModes(String responseMode) {
        AuthenticationRequest.Builder authRequestBuilder =
                new AuthenticationRequest.Builder(
                                VALID_RESPONSE_TYPE, VALID_SCOPES, CLIENT_ID, REDIRECT_URI)
                        .state(STATE)
                        .nonce(NONCE)
                        .responseMode(new ResponseMode(responseMode));
        var errorObject = queryParamsAuthorizeValidator.validate(authRequestBuilder.build());

        assertTrue(errorObject.isEmpty());
    }

    private ClientRegistry generateClientRegistry(String redirectURI, String clientID) {
        return generateClientRegistry(
                redirectURI, clientID, singletonList("openid"), false, DEFAULT_CLIENT_LOCS);
    }

    private ClientRegistry generateClientRegistry(
            String redirectURI, String clientID, List<String> scopes) {
        return generateClientRegistry(redirectURI, clientID, scopes, false, DEFAULT_CLIENT_LOCS);
    }

    private ClientRegistry generateClientRegistry(
            String redirectURI, List<String> clientLoCs, String clientID) {
        return generateClientRegistry(
                redirectURI, clientID, singletonList("openid"), false, clientLoCs);
    }

    private ClientRegistry generateClientRegistry(
            String redirectURI,
            String clientID,
            List<String> scopes,
            boolean testClient,
            List<String> clientLoCs) {
        return new ClientRegistry()
                .withRedirectUrls(singletonList(redirectURI))
                .withClientID(clientID)
                .withContacts(singletonList("joe.bloggs@digital.cabinet-office.gov.uk"))
                .withPublicKey(null)
                .withTestClient(testClient)
                .withClientLoCs(clientLoCs)
                .withScopes(scopes);
    }

    private AuthenticationRequest generateAuthRequest(
            String redirectUri, ResponseType responseType, Scope scope) {
        return generateAuthRequest(
                redirectUri, responseType, scope, jsonArrayOf("Cl.Cm", "Cl"), Optional.empty());
    }

    private AuthenticationRequest generateAuthRequest(
            String redirectUri,
            ResponseType responseType,
            Scope scope,
            String jsonArray,
            Optional<OIDCClaimsRequest> claimsRequest) {
        AuthenticationRequest.Builder authRequestBuilder =
                new AuthenticationRequest.Builder(
                                responseType, scope, CLIENT_ID, URI.create(redirectUri))
                        .state(STATE)
                        .nonce(NONCE)
                        .maxAge(MAX_AGE)
                        .customParameter("vtr", jsonArray);
        claimsRequest.ifPresent(authRequestBuilder::claims);

        return authRequestBuilder.build();
    }

    private KeyPair generateRsaKeyPair() {
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }
}

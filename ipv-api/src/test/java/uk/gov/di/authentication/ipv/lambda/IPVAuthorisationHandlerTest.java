package uk.gov.di.authentication.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.ipv.domain.IPVAuditableEvent;
import uk.gov.di.authentication.ipv.entity.IPVAuthorisationResponse;
import uk.gov.di.authentication.ipv.services.IPVAuthorisationService;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class IPVAuthorisationHandlerTest {

    private final Context context = mock(Context.class);
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final ClientSession clientSession = mock(ClientSession.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final ClientService clientService = mock(ClientService.class);
    private final AuditService auditService = mock(AuditService.class);

    private static final String CLIENT_SESSION_ID = "client-session-v1";
    private static final String SESSION_ID = "a-session-id";
    private static final String PERSISTENT_SESSION_ID = "a-persistent-session-id";
    private static final String CLIENT_ID = "test-client-id";
    private static final String IPV_CLIENT_ID = "ipv-client-id";
    private static final String PHONE_NUMBER = "01234567890";
    private static final Date CREATED_DATE_TIME = NowHelper.nowMinus(30, ChronoUnit.SECONDS);
    private static final Date UPDATED_DATE_TIME = NowHelper.now();
    private static final String LEGACY_SUBJECT_ID = new Subject("legacy-subject-id-1").getValue();
    private static final String PUBLIC_SUBJECT_ID = new Subject("public-subject-id-2").getValue();
    private static final String SUBJECT_ID = new Subject("subject-id-3").getValue();
    private static final ByteBuffer SALT =
            ByteBuffer.wrap("a-test-salt".getBytes(StandardCharsets.UTF_8));
    private static final URI REDIRECT_URI = URI.create("http://localhost/oidc/redirect");
    private static final URI IPV_CALLBACK_URI = URI.create("http://localhost/oidc/ipv/callback");
    private static final URI IPV_AUTHORISATION_URI = URI.create("http://localhost/ipv/authorize");
    private static final String EMAIL_ADDRESS = "test@test.com";
    private static final String IPV_SECTOR = "https://ipv.account.gov.uk";

    private final IPVAuthorisationService authorisationService =
            mock(IPVAuthorisationService.class);
    private final ClaimsSetRequest.Entry nameEntry =
            new ClaimsSetRequest.Entry("name").withClaimRequirement(ClaimRequirement.ESSENTIAL);
    private final ClaimsSetRequest.Entry birthDateEntry =
            new ClaimsSetRequest.Entry("birthdate")
                    .withClaimRequirement(ClaimRequirement.VOLUNTARY);
    private final ClaimsSetRequest claimsSetRequest =
            new ClaimsSetRequest().add(nameEntry).add(birthDateEntry);

    private IPVAuthorisationHandler handler;

    private final Session session = new Session(SESSION_ID).setEmailAddress(EMAIL_ADDRESS);

    @BeforeEach
    void setup() {
        var userProfile = generateUserProfile();
        handler =
                new IPVAuthorisationHandler(
                        configService,
                        sessionService,
                        clientSessionService,
                        clientService,
                        authenticationService,
                        auditService,
                        authorisationService);
        when(configService.getIPVAuthorisationClientId()).thenReturn(IPV_CLIENT_ID);
        when(configService.getIPVAuthorisationCallbackURI()).thenReturn(IPV_CALLBACK_URI);
        when(configService.getIPVAuthorisationURI()).thenReturn(IPV_AUTHORISATION_URI);
        when(configService.getSessionExpiry()).thenReturn(3600L);
        when(clientService.getClient(CLIENT_ID)).thenReturn(Optional.of(generateClientRegistry()));
        when(authenticationService.getUserProfileFromEmail(EMAIL_ADDRESS))
                .thenReturn(Optional.of(userProfile));
        when(authenticationService.getOrGenerateSalt(userProfile)).thenReturn(SALT.array());
        when(configService.getIPVSector()).thenReturn(IPV_SECTOR);
        when(configService.isIdentityEnabled()).thenReturn(true);
    }

    @Test
    void shouldThrowWhenIdentityIsNotEnabled() {
        usingValidSession();
        usingValidClientSession();
        when(configService.isIdentityEnabled()).thenReturn(false);

        var exception =
                assertThrows(
                        RuntimeException.class,
                        this::makeHandlerRequest,
                        "Expected to throw exception");

        assertThat(exception.getMessage(), equalTo("Identity is not enabled"));
    }

    @Test
    void shouldReturn200AndRedirectURIWithClaims()
            throws Json.JsonException, JOSEException, ParseException {
        var encryptedJWT = createEncryptedJWT();
        when(authorisationService.constructRequestJWT(
                        any(State.class), any(Scope.class), any(Subject.class), any(), anyString()))
                .thenReturn(encryptedJWT);
        usingValidSession();
        usingValidClientSession();

        var response = makeHandlerRequest();

        assertThat(response, hasStatus(200));
        var body =
                SerializationService.getInstance()
                        .getInstance()
                        .readValue(response.getBody(), IPVAuthorisationResponse.class);
        assertThat(body.getRedirectUri(), startsWith(IPV_AUTHORISATION_URI.toString()));
        assertThat(
                splitQuery(body.getRedirectUri()).get("request"),
                equalTo(encryptedJWT.serialize()));
        verify(authorisationService).storeState(eq(session.getSessionId()), any(State.class));
        verify(auditService)
                .submitAuditEvent(
                        IPVAuditableEvent.IPV_AUTHORISATION_REQUESTED,
                        context.getAwsRequestId(),
                        SESSION_ID,
                        CLIENT_ID,
                        AuditService.UNKNOWN,
                        EMAIL_ADDRESS,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PERSISTENT_SESSION_ID);
    }

    private APIGatewayProxyResponseEvent makeHandlerRequest() {
        Map<String, String> headers = new HashMap<>();
        headers.put(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, PERSISTENT_SESSION_ID);
        headers.put("Session-Id", session.getSessionId());
        headers.put("Client-Session-Id", CLIENT_SESSION_ID);
        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(headers);
        event.setBody(format("{ \"email\": \"%s\"}", EMAIL_ADDRESS));
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        return handler.handleRequest(event, context);
    }

    private void usingValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
    }

    private void usingValidClientSession() {
        when(clientSessionService.getClientSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(clientSession));
        when(clientSession.getAuthRequestParams())
                .thenReturn(withAuthenticationRequest().toParameters());
    }

    private AuthenticationRequest withAuthenticationRequest() {
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        var oidcClaimsRequest = new OIDCClaimsRequest().withUserInfoClaimsRequest(claimsSetRequest);
        return new AuthenticationRequest.Builder(
                        new ResponseType(ResponseType.Value.CODE),
                        scope,
                        new ClientID(CLIENT_ID),
                        REDIRECT_URI)
                .state(new State())
                .nonce(new Nonce())
                .claims(oidcClaimsRequest)
                .build();
    }

    public static Map<String, String> splitQuery(String stringUrl) {
        URI uri = URI.create(stringUrl);
        Map<String, String> query_pairs = new LinkedHashMap<>();
        String query = uri.getQuery();
        String[] pairs = query.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            query_pairs.put(
                    URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8),
                    URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8));
        }
        return query_pairs;
    }

    private ClientRegistry generateClientRegistry() {
        return new ClientRegistry()
                .setRedirectUrls(singletonList(REDIRECT_URI.toString()))
                .setClientID(CLIENT_ID)
                .setContacts(singletonList("joe.bloggs@digital.cabinet-office.gov.uk"))
                .setPublicKey(null)
                .setSectorIdentifierUri("http://sector-identifier")
                .setScopes(singletonList("openid"))
                .setCookieConsentShared(true)
                .setSubjectType("pairwise");
    }

    private UserProfile generateUserProfile() {
        return new UserProfile()
                .setEmail(EMAIL_ADDRESS)
                .setEmailVerified(true)
                .setPhoneNumber(PHONE_NUMBER)
                .setPhoneNumberVerified(true)
                .setPublicSubjectID(PUBLIC_SUBJECT_ID)
                .setSubjectID(SUBJECT_ID)
                .setLegacySubjectID(LEGACY_SUBJECT_ID)
                .setSalt(SALT)
                .setCreated(CREATED_DATE_TIME.toString())
                .setUpdated(UPDATED_DATE_TIME.toString());
    }

    private EncryptedJWT createEncryptedJWT() throws JOSEException, ParseException {
        var ecSigningKey =
                new ECKeyGenerator(Curve.P_256)
                        .keyID("key-id")
                        .algorithm(JWSAlgorithm.ES256)
                        .generate();
        var ecdsaSigner = new ECDSASigner(ecSigningKey);
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("client_id", CLIENT_ID)
                        .issuer(CLIENT_ID)
                        .build();
        var jwsHeader = new JWSHeader(JWSAlgorithm.ES256);
        var signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
        signedJWT.sign(ecdsaSigner);
        var rsaEncryptionKey =
                new RSAKeyGenerator(2048).keyID("encrytion-key-id").generate().toRSAPublicKey();
        var jweObject =
                new JWEObject(
                        new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                                .contentType("JWT")
                                .build(),
                        new Payload(signedJWT));
        jweObject.encrypt(new RSAEncrypter(rsaEncryptionKey));
        return EncryptedJWT.parse(jweObject.serialize());
    }
}

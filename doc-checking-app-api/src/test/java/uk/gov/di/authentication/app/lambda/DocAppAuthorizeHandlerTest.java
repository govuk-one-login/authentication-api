package uk.gov.di.authentication.app.lambda;

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
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.app.domain.DocAppAuditableEvent;
import uk.gov.di.authentication.app.entity.DocAppAuthorisationResponse;
import uk.gov.di.authentication.app.services.DocAppAuthorisationService;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class DocAppAuthorizeHandlerTest {

    private static final URI DOC_APP_CALLBACK_URI =
            URI.create("http://localhost/oidc/doc-app/callback");
    private static final URI DOC_APP_AUTHORISATION_URI =
            URI.create("http://localhost/doc-app/authorize");
    private static final String DOC_APP_CLIENT_ID = "doc-app-client-id";
    private static final URI REDIRECT_URI = URI.create("http://localhost/oidc/redirect");
    private static final String CLIENT_SESSION_ID = "client-session-v1";
    private static final String SESSION_ID = "a-session-id";
    private static final String PERSISTENT_SESSION_ID = "a-persistent-session-id";
    private static final Subject DOC_APP_SUBJECT_ID = new Subject();
    private static final Json objectMapper = SerializationService.getInstance();

    private final Context context = mock(Context.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ClientSession clientSession = mock(ClientSession.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final DocAppAuthorisationService authorisationService =
            mock(DocAppAuthorisationService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AuditService auditService = mock(AuditService.class);

    private final ClientService clientService = mock(ClientService.class);

    private DocAppAuthorizeHandler handler;
    private final Session session = new Session(SESSION_ID);

    @BeforeEach
    void setUp() {
        handler =
                new DocAppAuthorizeHandler(
                        sessionService,
                        clientSessionService,
                        authorisationService,
                        configurationService,
                        auditService,
                        clientService);
        when(configurationService.getDocAppAuthorisationClientId()).thenReturn(DOC_APP_CLIENT_ID);
        when(configurationService.getDocAppAuthorisationCallbackURI())
                .thenReturn(DOC_APP_CALLBACK_URI);
        when(configurationService.getDocAppAuthorisationURI())
                .thenReturn(DOC_APP_AUTHORISATION_URI);
        when(clientSession.getDocAppSubjectId()).thenReturn(DOC_APP_SUBJECT_ID);
    }

    @Test
    void shouldReturn200ForSuccessfulRequest()
            throws ParseException, JOSEException, Json.JsonException {
        var encryptedJWT = createEncryptedJWT();
        when(authorisationService.constructRequestJWT(
                        any(State.class), any(Subject.class), any(ClientRegistry.class)))
                .thenReturn(encryptedJWT);
        when(clientService.getClient(DOC_APP_CLIENT_ID))
                .thenReturn(Optional.of(new ClientRegistry()));
        usingValidSession();
        usingValidClientSession();

        var response = makeHandlerRequest();

        assertThat(response, hasStatus(200));
        var body = objectMapper.readValue(response.getBody(), DocAppAuthorisationResponse.class);
        assertThat(body.getRedirectUri(), startsWith(DOC_APP_AUTHORISATION_URI.toString()));
        assertThat(
                splitQuery(body.getRedirectUri()).get("request"),
                equalTo(encryptedJWT.serialize()));
        verify(authorisationService).storeState(eq(session.getSessionId()), any(State.class));
        verify(auditService)
                .submitAuditEvent(
                        DocAppAuditableEvent.DOC_APP_AUTHORISATION_REQUESTED,
                        context.getAwsRequestId(),
                        SESSION_ID,
                        AuditService.UNKNOWN,
                        DOC_APP_SUBJECT_ID.getValue(),
                        AuditService.UNKNOWN,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PERSISTENT_SESSION_ID);
    }

    @Test
    void shouldReturn400WhenSessionIdIsInvalid() {
        usingValidClientSession();
        var response = makeHandlerRequest();

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1000));
        verifyNoInteractions(authorisationService);
        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400WhenClientSessionIdIsInvalid() {
        usingValidSession();

        var response = makeHandlerRequest();

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1018));
        verifyNoInteractions(authorisationService);
        verifyNoInteractions(auditService);
    }

    private void usingValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
    }

    private APIGatewayProxyResponseEvent makeHandlerRequest() {
        Map<String, String> headers = new HashMap<>();
        headers.put(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, PERSISTENT_SESSION_ID);
        headers.put("Session-Id", session.getSessionId());
        headers.put("Client-Session-Id", CLIENT_SESSION_ID);
        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(headers);
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        return handler.handleRequest(event, context);
    }

    private void usingValidClientSession() {
        when(clientSessionService.getClientSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(clientSession));
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
                        .claim("client_id", DOC_APP_CLIENT_ID)
                        .issuer(DOC_APP_CLIENT_ID)
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

    public static Map<String, String> splitQuery(String stringUrl) {
        var uri = URI.create(stringUrl);
        Map<String, String> query_pairs = new LinkedHashMap<>();
        var query = uri.getQuery();
        var pairs = query.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            query_pairs.put(
                    URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8),
                    URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8));
        }
        return query_pairs;
    }
}

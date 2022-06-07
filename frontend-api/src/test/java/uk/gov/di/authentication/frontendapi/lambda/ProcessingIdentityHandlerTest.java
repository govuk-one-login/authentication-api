package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.ProcessingIdentityResponse;
import uk.gov.di.authentication.frontendapi.entity.ProcessingIdentityStatus;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.IdentityCredentials;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.DynamoIdentityService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class ProcessingIdentityHandlerTest {

    public static final String CLIENT_SESSION_ID = "known-client-session-id";
    public static final String SESSION_ID = "some-session-id";
    private static final String EMAIL_ADDRESS = "test@test.com";
    private static final String CLIENT_ID = "test-client-id";
    private static final String PHONE_NUMBER = "01234567890";
    private static final Subject PAIRWISE_SUBJECT = new Subject();
    private static final Date CREATED_DATE_TIME = NowHelper.nowMinus(30, ChronoUnit.SECONDS);
    private static final Date UPDATED_DATE_TIME = NowHelper.now();
    private static final String PUBLIC_SUBJECT_ID = new Subject("public-subject-id-2").getValue();
    private static final String SUBJECT_ID = new Subject("subject-id-3").getValue();
    private static final ByteBuffer SALT =
            ByteBuffer.wrap("a-test-salt".getBytes(StandardCharsets.UTF_8));
    private static final URI REDIRECT_URI = URI.create("http://localhost/oidc/redirect");

    private final Context context = mock(Context.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final DynamoIdentityService dynamoIdentityService = mock(DynamoIdentityService.class);
    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private final DynamoService dynamoService = mock(DynamoService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final Session session = new Session(SESSION_ID);
    private final APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
    protected final Json objectMapper = SerializationService.getInstance();
    private ProcessingIdentityHandler handler;

    @BeforeEach
    void setup() {
        var userProfile = generateUserProfile();
        when(dynamoClientService.getClient(CLIENT_ID))
                .thenReturn(Optional.of(generateClientRegistry()));
        when(dynamoService.getUserProfileFromEmail(EMAIL_ADDRESS))
                .thenReturn(Optional.of(userProfile));
        when(dynamoService.getOrGenerateSalt(userProfile)).thenReturn(SALT.array());
        Map<String, String> headers = new HashMap<>();
        headers.put(CLIENT_SESSION_ID_HEADER, CLIENT_SESSION_ID);
        headers.put(SESSION_ID_HEADER, SESSION_ID);
        event.setHeaders(headers);
        event.setBody(format("{ \"email\": \"%s\"}", EMAIL_ADDRESS));
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        handler =
                new ProcessingIdentityHandler(
                        dynamoIdentityService,
                        sessionService,
                        clientSessionService,
                        dynamoClientService,
                        dynamoService,
                        configurationService);
    }

    @Test
    void shouldReturnErrorIfSessionIsNotFound() throws Json.JsonException {
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1000)));
    }

    @Test
    void shouldReturnCOMPLETEDStatusWhenIdentityCredentialIsPresent() throws Json.JsonException {
        usingValidSession();
        var identityCredentials =
                new IdentityCredentials()
                        .setSubjectID(PAIRWISE_SUBJECT.getValue())
                        .setAdditionalClaims(Collections.emptyMap())
                        .setCoreIdentityJWT("a-core-identity");
        when(dynamoIdentityService.getIdentityCredentials(anyString()))
                .thenReturn(Optional.of(identityCredentials));
        when(clientSessionService.getClientSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(getClientSession()));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        assertThat(
                result,
                hasBody(
                        objectMapper.writeValueAsString(
                                new ProcessingIdentityResponse(
                                        ProcessingIdentityStatus.COMPLETED))));
    }

    @Test
    void shouldReturnPROCESSINGStatusWhenEntryIsInDynamoButNoIdentityCredentialIsPresent()
            throws Json.JsonException {
        usingValidSession();
        var identityCredentials =
                new IdentityCredentials()
                        .setSubjectID(PAIRWISE_SUBJECT.getValue())
                        .setAdditionalClaims(Collections.emptyMap());
        when(dynamoIdentityService.getIdentityCredentials(anyString()))
                .thenReturn(Optional.of(identityCredentials));
        when(clientSessionService.getClientSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(getClientSession()));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        assertThat(
                result,
                hasBody(
                        objectMapper.writeValueAsString(
                                new ProcessingIdentityResponse(
                                        ProcessingIdentityStatus.PROCESSING))));
    }

    @Test
    void shouldReturnERRORStatusWhenNoEntryIsFoundInDynamo() throws Json.JsonException {
        usingValidSession();
        when(dynamoIdentityService.getIdentityCredentials(PAIRWISE_SUBJECT.getValue()))
                .thenReturn(Optional.empty());
        when(clientSessionService.getClientSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(getClientSession()));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        assertThat(
                result,
                hasBody(
                        objectMapper.writeValueAsString(
                                new ProcessingIdentityResponse(ProcessingIdentityStatus.ERROR))));
    }

    private ClientSession getClientSession() {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                responseType,
                                scope,
                                new ClientID(CLIENT_ID),
                                URI.create("http://localhost/redirect"))
                        .build();

        return new ClientSession(authRequest.toParameters(), null, mock(VectorOfTrust.class));
    }

    private void usingValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
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
                .setSalt(SALT)
                .setCreated(CREATED_DATE_TIME.toString())
                .setUpdated(UPDATED_DATE_TIME.toString());
    }
}

package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.google.gson.JsonArray;
import org.apache.logging.log4j.Level;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import uk.gov.di.authentication.entity.InternalTICFCRIRequest;
import uk.gov.di.authentication.shared.entity.AuthSessionItem.AccountState;
import uk.gov.di.authentication.shared.entity.AuthSessionItem.ResetMfaState;
import uk.gov.di.authentication.shared.entity.AuthSessionItem.ResetPasswordState;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withLevelAndMessageContaining;

class TicfCriHandlerTest {

    public static final boolean USER_IS_AUTHENTICATED = true;
    @Mock private Context context;
    @Mock private ConfigurationService configurationService;
    @Mock private CloudwatchMetricsService cloudwatchMetricsService;
    @Mock private HttpClient httpClient;
    @Mock private HttpResponse httpResponse;

    private TicfCriHandler handler;

    private static final AccountState EXISTING_ACCOUNT_STATE = AccountState.EXISTING;
    private static final ResetPasswordState NA_RESET_PASSWORD_STATE = ResetPasswordState.NONE;
    private static final ResetMfaState NA_RESET_MFA_STATE = ResetMfaState.NONE;
    private static final MFAMethodType NA_USED_MFA_METHOD_TYPE = MFAMethodType.NONE;
    private static final String SERVICE_URI = "http://www.example.com";
    private static final String COMMON_SUBJECTID = "a-subject-id";
    private static final String JOURNEY_ID = "journey-id";
    private static final List<String> VECTORS_OF_TRUST = List.of("Cl");
    private AutoCloseable mocks;
    private static final Map<String, String> METRICS_CONTEXT =
            Map.of("Environment", "test-environment");

    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(TicfCriHandler.class);

    @BeforeEach
    void setUp() {
        mocks = MockitoAnnotations.openMocks(this);
        when(configurationService.getTicfCriServiceURI()).thenReturn(SERVICE_URI);
        when(configurationService.getTicfCriServiceCallTimeout()).thenReturn(1000L);
        when(configurationService.getEnvironment()).thenReturn("test-environment");
        handler = new TicfCriHandler(httpClient, configurationService, cloudwatchMetricsService);
    }

    @AfterEach
    void tearDown() throws Exception {
        mocks.close();
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void shouldMakeTheCorrectCallToTheTicfCriForAuthenticated(boolean userIsAuthenticated)
            throws IOException, InterruptedException, ExecutionException {
        var ticfRequest =
                new InternalTICFCRIRequest(
                        COMMON_SUBJECTID,
                        VECTORS_OF_TRUST,
                        JOURNEY_ID,
                        userIsAuthenticated,
                        EXISTING_ACCOUNT_STATE,
                        NA_RESET_PASSWORD_STATE,
                        NA_RESET_MFA_STATE,
                        NA_USED_MFA_METHOD_TYPE);
        var expectedRequestBody =
                format(
                        "{\"sub\":\"%s\",\"vtr\":%s,\"govuk_signin_journey_id\":\"%s\",\"authenticated\":\"%s\"}",
                        COMMON_SUBJECTID,
                        jsonArrayFrom(VECTORS_OF_TRUST),
                        JOURNEY_ID,
                        userIsAuthenticated ? "Y" : "N");

        when(httpResponse.statusCode()).thenReturn(200);
        when(httpClient.send(any(), any())).thenReturn(httpResponse);
        handler.handleRequest(ticfRequest, context);

        var httpRequestCaptor = ArgumentCaptor.forClass(HttpRequest.class);
        verify(httpClient).send(httpRequestCaptor.capture(), ArgumentMatchers.any());

        var actualRequestBody =
                bodyPublisherToString(httpRequestCaptor.getValue().bodyPublisher().get());

        var expectedUri = URI.create(SERVICE_URI + "/auth");
        assertEquals(expectedUri, httpRequestCaptor.getValue().uri());
        assertEquals(expectedRequestBody, actualRequestBody);
    }

    @ParameterizedTest
    @EnumSource(AccountState.class)
    void shouldMakeTheCorrectCallToTheTicfCriForInitialRegistration(AccountState accountState)
            throws IOException, InterruptedException, ExecutionException {
        var ticfRequest =
                new InternalTICFCRIRequest(
                        COMMON_SUBJECTID,
                        VECTORS_OF_TRUST,
                        JOURNEY_ID,
                        USER_IS_AUTHENTICATED,
                        accountState,
                        NA_RESET_PASSWORD_STATE,
                        NA_RESET_MFA_STATE,
                        NA_USED_MFA_METHOD_TYPE);
        var expectedRequestBody =
                format(
                        "{\"sub\":\"%s\",\"vtr\":%s,\"govuk_signin_journey_id\":\"%s\",\"authenticated\":\"%s\"%s}",
                        COMMON_SUBJECTID,
                        jsonArrayFrom(VECTORS_OF_TRUST),
                        JOURNEY_ID,
                        "Y",
                        accountState == AccountState.NEW ? ",\"initial_registration\":\"Y\"" : "");

        when(httpResponse.statusCode()).thenReturn(200);
        when(httpClient.send(any(), any())).thenReturn(httpResponse);
        handler.handleRequest(ticfRequest, context);

        var httpRequestCaptor = ArgumentCaptor.forClass(HttpRequest.class);
        verify(httpClient).send(httpRequestCaptor.capture(), ArgumentMatchers.any());

        var actualRequestBody =
                bodyPublisherToString(httpRequestCaptor.getValue().bodyPublisher().get());

        var expectedUri = URI.create(SERVICE_URI + "/auth");
        assertEquals(expectedUri, httpRequestCaptor.getValue().uri());
        assertEquals(expectedRequestBody, actualRequestBody);
    }

    @ParameterizedTest
    @MethodSource("resetPassword")
    void shouldMakeTheCorrectCallToTheTicfCriForResetPassword(
            boolean authenticated,
            ResetPasswordState resetPasswordState,
            boolean expectPasswordReset)
            throws IOException, InterruptedException, ExecutionException {
        var ticfRequest =
                new InternalTICFCRIRequest(
                        COMMON_SUBJECTID,
                        VECTORS_OF_TRUST,
                        JOURNEY_ID,
                        authenticated,
                        EXISTING_ACCOUNT_STATE,
                        resetPasswordState,
                        NA_RESET_MFA_STATE,
                        NA_USED_MFA_METHOD_TYPE);
        var expectedRequestBody =
                format(
                        "{\"sub\":\"%s\",\"vtr\":%s,\"govuk_signin_journey_id\":\"%s\",\"authenticated\":\"%s\"%s}",
                        COMMON_SUBJECTID,
                        jsonArrayFrom(VECTORS_OF_TRUST),
                        JOURNEY_ID,
                        authenticated ? "Y" : "N",
                        expectPasswordReset ? ",\"password_reset\":\"Y\"" : "");

        when(httpResponse.statusCode()).thenReturn(200);
        when(httpClient.send(any(), any())).thenReturn(httpResponse);
        handler.handleRequest(ticfRequest, context);

        var httpRequestCaptor = ArgumentCaptor.forClass(HttpRequest.class);
        verify(httpClient).send(httpRequestCaptor.capture(), ArgumentMatchers.any());

        var actualRequestBody =
                bodyPublisherToString(httpRequestCaptor.getValue().bodyPublisher().get());

        var expectedUri = URI.create(SERVICE_URI + "/auth");
        assertEquals(expectedUri, httpRequestCaptor.getValue().uri());
        assertEquals(expectedRequestBody, actualRequestBody);
    }

    private static List<Arguments> resetPassword() {
        return List.of(
                Arguments.of(false, ResetPasswordState.NONE, false),
                Arguments.of(true, ResetPasswordState.NONE, false),
                Arguments.of(false, ResetPasswordState.ATTEMPTED, true),
                Arguments.of(true, ResetPasswordState.ATTEMPTED, false),
                Arguments.of(true, ResetPasswordState.SUCCEEDED, true));
    }

    @ParameterizedTest
    @MethodSource("resetMfa")
    void shouldMakeTheCorrectCallToTheTicfCriForResetMfa(
            boolean authenticated, ResetMfaState resetMfaState, boolean expectMfaReset)
            throws IOException, InterruptedException, ExecutionException {
        var ticfRequest =
                new InternalTICFCRIRequest(
                        COMMON_SUBJECTID,
                        VECTORS_OF_TRUST,
                        JOURNEY_ID,
                        authenticated,
                        EXISTING_ACCOUNT_STATE,
                        NA_RESET_PASSWORD_STATE,
                        resetMfaState,
                        NA_USED_MFA_METHOD_TYPE);
        var expectedRequestBody =
                format(
                        "{\"sub\":\"%s\",\"vtr\":%s,\"govuk_signin_journey_id\":\"%s\",\"authenticated\":\"%s\"%s}",
                        COMMON_SUBJECTID,
                        jsonArrayFrom(VECTORS_OF_TRUST),
                        JOURNEY_ID,
                        authenticated ? "Y" : "N",
                        expectMfaReset ? ",\"2fa_reset\":\"Y\"" : "");

        when(httpResponse.statusCode()).thenReturn(200);
        when(httpClient.send(any(), any())).thenReturn(httpResponse);
        handler.handleRequest(ticfRequest, context);

        var httpRequestCaptor = ArgumentCaptor.forClass(HttpRequest.class);
        verify(httpClient).send(httpRequestCaptor.capture(), ArgumentMatchers.any());

        var actualRequestBody =
                bodyPublisherToString(httpRequestCaptor.getValue().bodyPublisher().get());

        var expectedUri = URI.create(SERVICE_URI + "/auth");
        assertEquals(expectedUri, httpRequestCaptor.getValue().uri());
        assertEquals(expectedRequestBody, actualRequestBody);
    }

    private static List<Arguments> resetMfa() {
        return List.of(
                Arguments.of(false, ResetMfaState.NONE, false),
                Arguments.of(true, ResetMfaState.NONE, false),
                Arguments.of(false, ResetMfaState.ATTEMPTED, true),
                Arguments.of(true, ResetMfaState.ATTEMPTED, false),
                Arguments.of(false, ResetMfaState.SUCCEEDED, true),
                Arguments.of(true, ResetMfaState.SUCCEEDED, true));
    }

    @ParameterizedTest
    @MethodSource("usedMfaMethodType")
    void shouldMakeTheCorrectCallToTheTicfCriForUsedMfaMethodType(
            MFAMethodType usedMfaMethodType, String expectedMfaMethodType)
            throws IOException, InterruptedException, ExecutionException {
        var ticfRequest =
                new InternalTICFCRIRequest(
                        COMMON_SUBJECTID,
                        VECTORS_OF_TRUST,
                        JOURNEY_ID,
                        true,
                        EXISTING_ACCOUNT_STATE,
                        NA_RESET_PASSWORD_STATE,
                        NA_RESET_MFA_STATE,
                        usedMfaMethodType);
        var expectedRequestBody =
                format(
                        "{\"sub\":\"%s\",\"vtr\":%s,\"govuk_signin_journey_id\":\"%s\",\"authenticated\":\"Y\"%s}",
                        COMMON_SUBJECTID,
                        jsonArrayFrom(VECTORS_OF_TRUST),
                        JOURNEY_ID,
                        expectedMfaMethodType != null
                                ? ",\"2fa_method\":[\"" + expectedMfaMethodType + "\"]"
                                : "");

        when(httpResponse.statusCode()).thenReturn(200);
        when(httpClient.send(any(), any())).thenReturn(httpResponse);
        handler.handleRequest(ticfRequest, context);

        var httpRequestCaptor = ArgumentCaptor.forClass(HttpRequest.class);
        verify(httpClient).send(httpRequestCaptor.capture(), ArgumentMatchers.any());

        var actualRequestBody =
                bodyPublisherToString(httpRequestCaptor.getValue().bodyPublisher().get());

        var expectedUri = URI.create(SERVICE_URI + "/auth");
        assertEquals(expectedUri, httpRequestCaptor.getValue().uri());
        assertEquals(expectedRequestBody, actualRequestBody);
    }

    private static List<Arguments> usedMfaMethodType() {
        return List.of(
                Arguments.of(MFAMethodType.NONE, null),
                Arguments.of(MFAMethodType.EMAIL, null),
                Arguments.of(MFAMethodType.SMS, "SMS"),
                Arguments.of(MFAMethodType.AUTH_APP, "AUTH_APP"));
    }

    @ParameterizedTest
    @MethodSource("statusCodes")
    void sendsMetricsAndLogsBasedOnTheHttpStatusCode(Integer statusCode, Level expectedLogLevel)
            throws IOException, InterruptedException {
        var ticfRequest =
                new InternalTICFCRIRequest(
                        COMMON_SUBJECTID,
                        VECTORS_OF_TRUST,
                        JOURNEY_ID,
                        USER_IS_AUTHENTICATED,
                        EXISTING_ACCOUNT_STATE,
                        NA_RESET_PASSWORD_STATE,
                        NA_RESET_MFA_STATE,
                        NA_USED_MFA_METHOD_TYPE);
        when(httpResponse.statusCode()).thenReturn(statusCode);
        when(httpClient.send(any(), any())).thenReturn(httpResponse);

        handler.handleRequest(ticfRequest, context);

        verify(cloudwatchMetricsService)
                .incrementCounter(
                        "TicfCriResponseReceived",
                        Map.ofEntries(
                                Map.entry("Environment", "test-environment"),
                                Map.entry("StatusCode", statusCode.toString())));
        assertThat(
                logging.events(),
                hasItem(
                        withLevelAndMessageContaining(
                                expectedLogLevel,
                                format(
                                        "Response received from TICF CRI Service with status %d",
                                        statusCode))));
    }

    private static List<Arguments> statusCodes() {
        return List.of(
                Arguments.of(200, Level.INFO),
                Arguments.of(404, Level.ERROR),
                Arguments.of(500, Level.INFO));
    }

    @ParameterizedTest
    @MethodSource("exceptions")
    void testIncrementsMetricAndSendsLogsWhenAnExceptionOccurs(
            Exception e, String metricName, Level expectedLogLevel) throws Exception {
        when(httpClient.send(any(), any())).thenThrow(e);

        handler.handleRequest(
                new InternalTICFCRIRequest(
                        COMMON_SUBJECTID,
                        VECTORS_OF_TRUST,
                        JOURNEY_ID,
                        USER_IS_AUTHENTICATED,
                        EXISTING_ACCOUNT_STATE,
                        NA_RESET_PASSWORD_STATE,
                        NA_RESET_MFA_STATE,
                        NA_USED_MFA_METHOD_TYPE),
                context);

        verify(cloudwatchMetricsService).incrementCounter(metricName, METRICS_CONTEXT);
        assertThat(
                logging.events(),
                hasItem(withLevelAndMessageContaining(expectedLogLevel, format(e.getMessage()))));
    }

    private static List<Arguments> exceptions() {
        return List.of(
                Arguments.of(
                        new IOException("an IO Exception"), "TicfCriServiceError", Level.ERROR),
                Arguments.of(
                        new InterruptedException("an Interrputed exception"),
                        "TicfCriServiceError",
                        Level.ERROR),
                Arguments.of(
                        new HttpTimeoutException("timed out"),
                        "TicfCriServiceTimeout",
                        Level.WARN));
    }

    private JsonArray jsonArrayFrom(List<String> elements) {
        var jsonArray = new JsonArray();
        elements.forEach(jsonArray::add);
        return jsonArray;
    }

    private String bodyPublisherToString(HttpRequest.BodyPublisher bodyPublisher)
            throws ExecutionException, InterruptedException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        CompletableFuture<Void> future = new CompletableFuture<>();
        bodyPublisher.subscribe(
                new java.util.concurrent.Flow.Subscriber<java.nio.ByteBuffer>() {
                    @Override
                    public void onSubscribe(java.util.concurrent.Flow.Subscription subscription) {
                        subscription.request(Long.MAX_VALUE);
                    }

                    @Override
                    public void onNext(java.nio.ByteBuffer item) {
                        byteArrayOutputStream.write(
                                item.array(), item.arrayOffset(), item.remaining());
                    }

                    @Override
                    public void onError(Throwable throwable) {
                        future.completeExceptionally(throwable);
                    }

                    @Override
                    public void onComplete() {
                        future.complete(null);
                    }
                });
        future.get();
        return byteArrayOutputStream.toString(StandardCharsets.UTF_8);
    }
}

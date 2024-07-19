package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.oidc.services.HttpRequestService;
import uk.gov.di.orchestration.shared.api.OidcAPI;
import uk.gov.di.orchestration.shared.entity.BackChannelLogoutMessage;
import uk.gov.di.orchestration.shared.helpers.LogLineHelper;
import uk.gov.di.orchestration.shared.helpers.NowHelper.NowClock;
import uk.gov.di.orchestration.shared.serialization.Json.JsonException;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;
import uk.gov.di.orchestration.shared.services.SerializationService;
import uk.gov.di.orchestration.shared.services.TokenService;

import java.net.URI;
import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static java.util.Collections.emptyMap;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;

public class BackChannelLogoutRequestHandler implements RequestHandler<SQSEvent, Object> {

    private static final Logger LOG = LogManager.getLogger(BackChannelLogoutRequestHandler.class);
    private final OidcAPI oidcApi;
    private final HttpRequestService httpRequestService;
    private final TokenService tokenService;
    private final NowClock clock;

    public BackChannelLogoutRequestHandler() {
        var configurationService = ConfigurationService.getInstance();
        this.oidcApi = new OidcAPI(configurationService);
        this.httpRequestService = new HttpRequestService();
        this.tokenService =
                new TokenService(
                        configurationService,
                        null,
                        new KmsConnectionService(configurationService),
                        oidcApi);
        this.clock = new NowClock(Clock.systemUTC());
    }

    public BackChannelLogoutRequestHandler(
            OidcAPI oidcApi,
            HttpRequestService httpRequestService,
            TokenService tokenService,
            NowClock clock) {
        this.oidcApi = oidcApi;
        this.httpRequestService = httpRequestService;
        this.tokenService = tokenService;
        this.clock = clock;
    }

    @Override
    public Object handleRequest(SQSEvent event, Context context) {
        ThreadContext.clearMap();
        return segmentedFunctionCall(
                "oidc-api::" + getClass().getSimpleName(),
                () -> backChannelLogoutRequestHandler(event, context));
    }

    public Object backChannelLogoutRequestHandler(SQSEvent event, Context context) {

        attachLogFieldToLogs(LogLineHelper.LogFieldName.AWS_REQUEST_ID, context.getAwsRequestId());

        event.getRecords().forEach(this::sendLogoutMessage);

        return null;
    }

    private void sendLogoutMessage(SQSMessage record) {
        LOG.info("Handling backchannel logout request with id: {}", record.getMessageId());

        try {
            var payload =
                    SerializationService.getInstance()
                            .readValue(record.getBody(), BackChannelLogoutMessage.class);

            attachLogFieldToLogs(LogLineHelper.LogFieldName.CLIENT_ID, payload.getClientId());

            var claims = generateClaims(payload);

            var body =
                    tokenService
                            .generateSignedJwtUsingExternalKey(
                                    claims, Optional.of("logout+jwt"), JWSAlgorithm.ES256)
                            .serialize();

            httpRequestService.post(URI.create(payload.getLogoutUri()), "logout_token=" + body);

        } catch (JsonException e) {
            LOG.error("Could not parse logout request payload");
        }
    }

    public JWTClaimsSet generateClaims(BackChannelLogoutMessage inputEvent) {
        return new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .audience(inputEvent.getClientId())
                .subject(inputEvent.getSubjectId())
                .expirationTime(clock.nowPlus(2, ChronoUnit.MINUTES))
                .issuer(oidcApi.baseURI().toString())
                .issueTime(clock.now())
                .claim(
                        "events",
                        Map.of("http://schemas.openid.net/event/backchannel-logout", emptyMap()))
                .build();
    }
}

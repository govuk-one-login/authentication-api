package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.oidc.entity.BackChannelLogoutMessage;
import uk.gov.di.authentication.oidc.services.HttpRequestService;
import uk.gov.di.authentication.shared.helpers.NowHelper.NowClock;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.TokenService;

import java.net.URI;
import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static java.util.Collections.emptyMap;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class BackChannelLogoutRequestHandler implements RequestHandler<SQSEvent, Object> {

    private static final Logger LOG = LogManager.getLogger(BackChannelLogoutRequestHandler.class);
    private final ConfigurationService instance;
    private final HttpRequestService httpRequestService;
    private final TokenService tokenService;
    private final NowClock clock;

    public BackChannelLogoutRequestHandler() {
        this.instance = ConfigurationService.getInstance();
        this.httpRequestService = new HttpRequestService();
        this.tokenService = new TokenService(instance, null, new KmsConnectionService(instance));
        this.clock = new NowClock(Clock.systemUTC());
    }

    public BackChannelLogoutRequestHandler(
            ConfigurationService configurationService,
            HttpRequestService httpRequestService,
            TokenService tokenService,
            NowClock clock) {
        this.instance = configurationService;
        this.httpRequestService = httpRequestService;
        this.tokenService = tokenService;
        this.clock = clock;
    }

    @Override
    public Object handleRequest(SQSEvent event, Context context) {
        return segmentedFunctionCall(
                "oidc-api::" + getClass().getSimpleName(),
                () -> backChannelLogoutRequestHandler(event, context));
    }

    public Object backChannelLogoutRequestHandler(SQSEvent event, Context context) {

        event.getRecords().forEach(this::sendLogoutMessage);

        return null;
    }

    private void sendLogoutMessage(SQSMessage record) {
        LOG.info("Handling backchannel logout request with id: {}", record.getMessageId());

        try {
            var payload =
                    SerializationService.getInstance()
                            .readValue(record.getBody(), BackChannelLogoutMessage.class);

            var claims = generateClaims(payload);

            var body =
                    tokenService.generateSignedJWT(claims, Optional.of("logout+jwt")).serialize();

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
                .issuer(instance.getOidcApiBaseURL().orElseThrow())
                .issueTime(clock.now())
                .claim(
                        "events",
                        Map.of("http://schemas.openid.net/event/backchannel-logout", emptyMap()))
                .build();
    }
}

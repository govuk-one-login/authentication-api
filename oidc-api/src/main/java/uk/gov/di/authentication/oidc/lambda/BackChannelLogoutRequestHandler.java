package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.oidc.entity.BackChannelLogoutMessage;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.sql.Date;
import java.time.Clock;
import java.util.Map;
import java.util.UUID;

import static java.util.Collections.emptyMap;

public class BackChannelLogoutRequestHandler implements RequestHandler<SQSEvent, Object> {

    private static final Logger LOG = LogManager.getLogger(BackChannelLogoutRequestHandler.class);
    private final ConfigurationService instance;
    private final Clock clock;

    public BackChannelLogoutRequestHandler() {
        this(ConfigurationService.getInstance(), Clock.systemUTC());
    }

    public BackChannelLogoutRequestHandler(ConfigurationService configurationService, Clock clock) {
        this.instance = configurationService;
        this.clock = clock;
    }

    @Override
    public Object handleRequest(SQSEvent event, Context context) {

        event.getRecords()
                .forEach(
                        record ->
                                LOG.info(
                                        "Handling backchannel logout request with id: {}",
                                        record.getMessageId()));
        return null;
    }

    public JWTClaimsSet generateClaims(BackChannelLogoutMessage inputEvent) {
        return new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .audience(inputEvent.getClientId())
                .subject(inputEvent.getSubjectId())
                .issuer(instance.getOidcApiBaseURL().orElseThrow())
                .issueTime(Date.from(clock.instant()))
                .claim(
                        "events",
                        Map.of("http://schemas.openid.net/event/backchannel-logout", emptyMap()))
                .build();
    }
}

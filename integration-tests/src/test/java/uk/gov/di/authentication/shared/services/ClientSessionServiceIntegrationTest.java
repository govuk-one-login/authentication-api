package uk.gov.di.authentication.shared.services;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.shared.entity.ClientSession;
import uk.gov.di.orchestration.shared.entity.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

public class ClientSessionServiceIntegrationTest {

    private static final String REDIS_HOST =
            System.getenv().getOrDefault("REDIS_HOST", "localhost");
    private static final Optional<String> REDIS_PASSWORD =
            Optional.ofNullable(System.getenv("REDIS_PASSWORD"));
    private static final String CLIENT_NAME = "CLIENT_NAME";
    private static List<VectorOfTrust> VTR_LIST =
            List.of(VectorOfTrust.of(CredentialTrustLevel.MEDIUM_LEVEL, LevelOfConfidence.NONE));
    private static final Subject SUBJECT_ID = new Subject("SUBJECT_ID");
    private static final String ID_TOKEN_HINT = "TOKEN_ID_HINT";

    private uk.gov.di.orchestration.shared.services.ClientSessionService orchClientSessionService;
    private uk.gov.di.authentication.shared.services.ClientSessionService authClientSessionService;

    @BeforeEach
    void setup() {
        var orchConfigurationService =
                uk.gov.di.orchestration.shared.services.ConfigurationService.getInstance();
        var authConfigurationService =
                uk.gov.di.authentication.shared.services.ConfigurationService.getInstance();
        var orchRedisConnectionService =
                new uk.gov.di.orchestration.shared.services.RedisConnectionService(
                        REDIS_HOST, 6379, false, REDIS_PASSWORD, false);
        var authRedisConnectionService =
                new uk.gov.di.authentication.shared.services.RedisConnectionService(
                        REDIS_HOST, 6379, false, REDIS_PASSWORD, false);

        orchClientSessionService =
                new uk.gov.di.orchestration.shared.services.ClientSessionService(
                        orchConfigurationService, orchRedisConnectionService);
        authClientSessionService =
                new uk.gov.di.authentication.shared.services.ClientSessionService(
                        authConfigurationService, authRedisConnectionService);
    }

    @Test
    void authAndOrchClientSessionsShouldBeAbleToHaveDifferentFieldsWithoutOverwritingOneAnother() {
        // Create Orch Client Session and store in Redis.
        var clientSessionId = orchClientSessionService.generateClientSessionId();
        var orchClientSession =
                new ClientSession(Map.of(), LocalDateTime.now(), VTR_LIST, CLIENT_NAME);
        orchClientSessionService.storeClientSession(clientSessionId, orchClientSession);

        // Get Auth Client Session from Redis and update in Redis.
        var authClientSession = authClientSessionService.getClientSession(clientSessionId).get();
        authClientSessionService.updateStoredClientSession(clientSessionId, authClientSession);

        // Get Orch Client Session from Redis, set ID Token Hint, and update in Redis.
        orchClientSession = orchClientSessionService.getClientSession(clientSessionId).get();
        orchClientSession.setIdTokenHint(ID_TOKEN_HINT);
        orchClientSessionService.updateStoredClientSession(clientSessionId, orchClientSession);

        // Check fields have expected values in Orch copy.
        assertThat(orchClientSession.getClientName(), is(equalTo(CLIENT_NAME)));
        assertThat(orchClientSession.getVtrList(), is(equalTo(VTR_LIST)));

        // Check fields have expected values in Auth copy.
        assertThat(authClientSession.getClientName(), is(equalTo(CLIENT_NAME)));
        assertThat(
                authClientSession.getEffectiveVectorOfTrust().toString(),
                is(equalTo(VTR_LIST.get(0).toString())));
    }

    @Test
    void authAndOrchClientSessionsShouldBeAbleToDeleteFieldValuesBySettingThemToNull() {
        // Create Orch client session, set ID Token Hint and Subject ID and store in Redis.
        var clientSessionId = orchClientSessionService.generateClientSessionId();
        var orchClientSession =
                new ClientSession(Map.of(), LocalDateTime.now(), VTR_LIST, CLIENT_NAME);
        orchClientSession.setIdTokenHint(ID_TOKEN_HINT);
        orchClientSession.setDocAppSubjectId(SUBJECT_ID);
        orchClientSessionService.storeClientSession(clientSessionId, orchClientSession);

        // Get Auth Client Session from Redis and update in Redis.
        var authClientSession = authClientSessionService.getClientSession(clientSessionId).get();
        authClientSessionService.updateStoredClientSession(clientSessionId, authClientSession);

        // Get Orch Client Session from Redis, set ID Token Hint to null, and update in Redis.
        orchClientSession = orchClientSessionService.getClientSession(clientSessionId).get();
        orchClientSession.setIdTokenHint(null);
        orchClientSession.setDocAppSubjectId(null);
        orchClientSessionService.updateStoredClientSession(clientSessionId, orchClientSession);

        // Get Orch / Auth client sessions from Redis.
        orchClientSession = orchClientSessionService.getClientSession(clientSessionId).get();
        authClientSession = authClientSessionService.getClientSession(clientSessionId).get();

        // Check expected null fields are null.
        assertThat(orchClientSession.getIdTokenHint(), is(nullValue()));
        assertThat(orchClientSession.getDocAppSubjectId(), is(nullValue()));
    }
}

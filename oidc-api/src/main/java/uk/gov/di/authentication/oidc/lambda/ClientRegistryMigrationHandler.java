package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jcajce.provider.digest.SHA256;
import org.bouncycastle.util.encoders.Hex;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.authentication.oidc.services.ClientRegistryMigrationService;
import uk.gov.di.orchestration.shared.helpers.LogLineHelper;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachTraceId;

public class ClientRegistryMigrationHandler implements RequestHandler<Object, String> {
    private static final Logger LOG = LogManager.getLogger(ClientRegistryMigrationHandler.class);
    private final ClientRegistryMigrationService authClientRegistry;
    private final ClientRegistryMigrationService orchClientRegistry;

    public ClientRegistryMigrationHandler(ConfigurationService configurationService) {
        this.authClientRegistry = new ClientRegistryMigrationService(configurationService, false);
        this.orchClientRegistry = new ClientRegistryMigrationService(configurationService, true);
    }

    public ClientRegistryMigrationHandler(
            ClientRegistryMigrationService authClientRegistryMigrationService,
            ClientRegistryMigrationService orchClientRegistryMigrationService) {
        this.authClientRegistry = authClientRegistryMigrationService;
        this.orchClientRegistry = orchClientRegistryMigrationService;
    }

    public ClientRegistryMigrationHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public String handleRequest(Object ignored, Context context) {
        attachTraceId();
        attachLogFieldToLogs(LogLineHelper.LogFieldName.AWS_REQUEST_ID, context.getAwsRequestId());
        LOG.info("Migrate client registry handler invoked");
        return migrateClientRegistry();
    }

    private String migrateClientRegistry() {
        var authClients = authClientRegistry.getAllClients();
        LOG.info("Found {} clients in Auth table", authClients.size());
        logHashOfEntries(authClients, "Auth client registry hash");

        authClients.forEach(orchClientRegistry::putClientToDynamo);
        LOG.info("Finished writing clients to Orch table");

        var orchClients = orchClientRegistry.getAllClients();
        LOG.info("Found {} clients in Orch table", orchClients.size());
        logHashOfEntries(orchClients, "Orch client registry hash");

        return "Finished";
    }

    private void logHashOfEntries(List<Map<String, AttributeValue>> clients, String logPrefix) {
        var totalDigest = new SHA256.Digest();
        clients.stream()
                .map(this::hashRawClient)
                .forEach(hash -> totalDigest.update(hash.getBytes(StandardCharsets.UTF_8)));
        var totalHashString = new String(Hex.encode(totalDigest.digest()), StandardCharsets.UTF_8);
        LOG.info("{}: {}", logPrefix, totalHashString);
    }

    private String hashRawClient(Map<String, AttributeValue> client) {
        var digest = new SHA256.Digest();
        client.forEach(
                (key, value) ->
                        digest.update(
                                (key + "=" + value.toString()).getBytes(StandardCharsets.UTF_8)));
        return new String(Hex.encode(digest.digest()), StandardCharsets.UTF_8);
    }
}

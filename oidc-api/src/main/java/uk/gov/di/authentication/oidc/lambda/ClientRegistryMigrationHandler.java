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
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachTraceId;

public class ClientRegistryMigrationHandler implements RequestHandler<Object, String> {
    private static final Logger LOG = LogManager.getLogger(ClientRegistryMigrationHandler.class);
    private final ClientRegistryMigrationService authClientRegistry;
    private final ClientRegistryMigrationService orchClientRegistry;
    private final ConfigurationService configurationService;

    public ClientRegistryMigrationHandler(ConfigurationService configurationService) {
        this.authClientRegistry = new ClientRegistryMigrationService(configurationService, false);
        this.orchClientRegistry = new ClientRegistryMigrationService(configurationService, true);
        this.configurationService = configurationService;
    }

    public ClientRegistryMigrationHandler(
            ConfigurationService configurationService,
            ClientRegistryMigrationService authClientRegistryMigrationService,
            ClientRegistryMigrationService orchClientRegistryMigrationService) {
        this.authClientRegistry = authClientRegistryMigrationService;
        this.orchClientRegistry = orchClientRegistryMigrationService;
        this.configurationService = configurationService;
    }

    public ClientRegistryMigrationHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public String handleRequest(Object ignored, Context context) {
        attachTraceId();
        attachLogFieldToLogs(LogLineHelper.LogFieldName.AWS_REQUEST_ID, context.getAwsRequestId());

        if (configurationService.isOrchClientRegistryEnabled()) {
            var err =
                    "Cannot invoke Migrate client registry handler as Orch Client Registry is enabled";
            LOG.error(err);
            return err;
        }

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
        var clientsHash = hashListOfClients(clients);
        LOG.info("{}: {}", logPrefix, clientsHash);
    }

    public String hashListOfClients(List<Map<String, AttributeValue>> clients) {
        var totalDigest = new SHA256.Digest();

        clients.stream()
                // Sort the clients to ensure we hash in the same order
                // each time. We want the digest of the contents - we don't care
                // ordering!
                .sorted(Comparator.comparing(c -> c.get("ClientID").s()))
                .map(this::hashRawClient)
                .forEach(hash -> totalDigest.update(hash.getBytes(StandardCharsets.UTF_8)));
        return new String(Hex.encode(totalDigest.digest()), StandardCharsets.UTF_8);
    }

    private String hashRawClient(Map<String, AttributeValue> client) {
        var digest = new SHA256.Digest();

        var mapEntries = new ArrayList<>(client.entrySet());
        // Ensure we sort the keys of the individual client to ensure we hash in the same order
        mapEntries.sort(Map.Entry.comparingByKey());
        mapEntries.forEach(
                entry -> {
                    digest.update(
                            (entry.getKey() + "=" + entry.getValue().toString())
                                    .getBytes(StandardCharsets.UTF_8));
                });

        return new String(Hex.encode(digest.digest()), StandardCharsets.UTF_8);
    }
}

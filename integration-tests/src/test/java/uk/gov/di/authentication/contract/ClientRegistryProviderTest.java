package uk.gov.di.authentication.contract;

import au.com.dius.pact.provider.junitsupport.State;
import com.nimbusds.jose.JWSAlgorithm;
import org.junit.jupiter.api.BeforeAll;
import uk.gov.di.authentication.clientregistry.lambda.ClientRegistrationHandler;
import uk.gov.di.authentication.clientregistry.lambda.UpdateClientConfigHandler;
import uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService;
import uk.gov.di.orchestration.shared.entity.Channel;
import uk.gov.di.orchestration.shared.entity.PublicKeySource;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.sharedtest.basetest.PactProviderTest;
import uk.gov.di.orchestration.sharedtest.pact.LambdaHandlerConfig;

import java.util.List;

public class ClientRegistryProviderTest extends PactProviderTest {

    private static final String CLIENT_ID = "testClientIdExampleText1234";
    private static final String CLIENT_NAME = "testClientUpdateResponseName";
    private static final List<String> REDIRECT_URIS = List.of("http://localhost/");
    private static final List<String> CONTRACTS =
            List.of("pacttest.account@digital.cabinet-office.gov.uk");
    private static final List<String> SCOPES = List.of("openid", "email", "phone");
    private static final String PUBLIC_KEY_SOURCE = PublicKeySource.STATIC.getValue();
    private static final String PUBLIC_KEY =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0o0K0A7H58Ngl4FyxTKece+hNhWIbeqm/YO4g7G2Cm8UvNvg4kUDsLVtTKMJNuoEaugkILOm393u4MPy7VT0O0ksL8e3tI6ehtfKiIaCaX/pyFiTimojBJTugwtrraJ3gd6rXm/qzUdBoY+AbYzN5OUkpuJ6/Hfm2w7GrOur5bMgiD8DvqQZA5HOqTswjoPeQK/NW3jaca7gQ9LRKu/QeuYXpQHsALoW2xr+Xpz57NWyutq1Ttt5aWHUQ7EzUBfwBDsBDef8a0cWKMUPcEdUaPD8MLVgbRRGbabkBAEO7sYdMlb3IhYMM9j8N8oct8cPgJtEYEN20TFai5fwQM3dUQIDAQAB";
    private static final List<String> POST_LOGOUT_REDIRECT_URIS = List.of();
    private static final String BACK_CHANNEL_LOGOUT_URI = null;
    private static final String SERVICE_TYPE = "MANDATORY";
    private static final String SECTOR_IDENTIFIER_URI = "http://gov.uk";
    private static final String SUBJECT_TYPE = "pairwise";
    private static final boolean JAR_VALIDATION_REQUIRED = false;
    private static final List<String> CLAIMS = List.of();
    private static final String CLIENT_TYPE = "web";
    private static final boolean IDENTITY_VERIFICATION_SUPPORTED = false;
    private static final String CLIENT_SECRET = null;
    private static final String TOKEN_AUTH_METHOD = "private_key_jwt";
    private static final String ID_TOKEN_SIGNING_ALGORITHM = JWSAlgorithm.ES256.getName();
    private static final List<String> CLIENT_LOCS = List.of();
    private static final String CHANNEL = Channel.WEB.getValue();
    private static final boolean MAX_AGE_ENABLED = false;
    private static final boolean PKCE_ENFORCED = false;
    private static final String LANDING_PAGE_URL = "http://landing-page.com";

    private DynamoClientService clientService;

    @BeforeAll
    static void setupServer() {
        System.setProperty("pact.verifier.publishResults", "true");
    }

    @Override
    protected List<LambdaHandlerConfig> getHandlerConfig() {
        clientService = new DynamoClientService(TXMA_ENABLED_CONFIGURATION_SERVICE);
        var validationService = new ClientConfigValidationService();
        var auditService = new AuditService(TXMA_ENABLED_CONFIGURATION_SERVICE);

        var registrationHandler =
                new ClientRegistrationHandler(clientService, validationService, auditService);
        var updateHandler =
                new UpdateClientConfigHandler(clientService, validationService, auditService);

        return List.of(
                new LambdaHandlerConfig("POST", "/connect/register", registrationHandler),
                new LambdaHandlerConfig("PUT", "/connect/register/{clientId}", updateHandler));
    }

    @State("valid configuration to add a client")
    public void validConfigurationToAddAClient() {}

    @State("testClientIdExampleText1234 is a valid clientId")
    public void testClientIdExampleText1234IsAValidClientId() {
        clientService.addClient(
                CLIENT_ID,
                CLIENT_NAME,
                REDIRECT_URIS,
                CONTRACTS,
                PUBLIC_KEY_SOURCE,
                PUBLIC_KEY,
                null,
                SCOPES,
                POST_LOGOUT_REDIRECT_URIS,
                BACK_CHANNEL_LOGOUT_URI,
                SERVICE_TYPE,
                SECTOR_IDENTIFIER_URI,
                SUBJECT_TYPE,
                JAR_VALIDATION_REQUIRED,
                CLAIMS,
                CLIENT_TYPE,
                IDENTITY_VERIFICATION_SUPPORTED,
                CLIENT_SECRET,
                TOKEN_AUTH_METHOD,
                ID_TOKEN_SIGNING_ALGORITHM,
                CLIENT_LOCS,
                CHANNEL,
                MAX_AGE_ENABLED,
                PKCE_ENFORCED,
                LANDING_PAGE_URL);
    }
}

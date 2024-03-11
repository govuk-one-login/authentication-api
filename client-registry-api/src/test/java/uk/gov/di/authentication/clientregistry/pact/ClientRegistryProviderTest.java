package uk.gov.di.authentication.clientregistry.pact;

import au.com.dius.pact.provider.junit5.HttpTestTarget;
import au.com.dius.pact.provider.junit5.PactVerificationContext;
import au.com.dius.pact.provider.junit5.PactVerificationInvocationContextProvider;
import au.com.dius.pact.provider.junitsupport.Provider;
import au.com.dius.pact.provider.junitsupport.State;
import au.com.dius.pact.provider.junitsupport.loader.PactFolder;
import com.nimbusds.oauth2.sdk.id.ClientID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import uk.gov.di.authentication.clientregistry.lambda.ClientRegistrationHandler;
import uk.gov.di.authentication.clientregistry.lambda.UpdateClientConfigHandler;
import uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.UpdateClientConfigRequest;
import uk.gov.di.orchestration.shared.pact.LambdaHttpServer;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.ClientService;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.List;

import static java.util.Objects.isNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@PactFolder("pacts")
@Provider("ClientRegistryProvider")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ClientRegistryProviderTest {

    private static final String HOST = "localhost";
    private static final int PORT = 5050;
    private static final String PATH = "/connect/register";
    private static final String CLIENT_ID = "1234567890";
    private static final String SUBJECT_TYPE = "pairwise";
    private static final String CLIENT_TYPE = "web";

    private LambdaHttpServer httpServer;
    private final ClientConfigValidationService configValidationService =
            new ClientConfigValidationService();
    @Mock private ClientService clientService;
    @Mock private AuditService auditService;

    @BeforeEach
    void setUp(PactVerificationContext context) throws IOException, NoSuchAlgorithmException {
        var registrationHandler =
                new ClientRegistrationHandler(clientService, configValidationService, auditService);
        var updateHandler =
                new UpdateClientConfigHandler(clientService, configValidationService, auditService);

        httpServer =
                LambdaHttpServer.builder()
                        .atAddress(HOST, PORT)
                        .handle("POST", "/connect/register", registrationHandler)
                        .handle("PUT", "/connect/register/{clientId}", updateHandler)
                        .build();

        httpServer.start();

        context.setTarget(new HttpTestTarget(HOST, PORT));
    }

    @AfterEach
    public void tearDown() {
        httpServer.stop();
    }

    @State("Client not exists")
    public void setUpClientNotExists() {
        when(clientService.generateClientID()).thenReturn(new ClientID(CLIENT_ID));
    }

    @State("Client exists")
    public void setUpClientExists() {
        when(clientService.isValidClient(CLIENT_ID)).thenReturn(true);
        when(clientService.updateClient(eq(CLIENT_ID), any(UpdateClientConfigRequest.class)))
                .thenAnswer(
                        i -> {
                            String clientId = (String) i.getArguments()[0];
                            UpdateClientConfigRequest request =
                                    (UpdateClientConfigRequest) i.getArguments()[1];
                            return new ClientRegistry()
                                    .withClientName(
                                            !isNull(request.getClientName())
                                                    ? request.getClientName()
                                                    : "My test service")
                                    .withClientID(clientId)
                                    .withRedirectUrls(
                                            !isNull(request.getRedirectUris())
                                                    ? request.getRedirectUris()
                                                    : List.of("http://localhost/"))
                                    .withContacts(
                                            !isNull(request.getContacts())
                                                    ? request.getContacts()
                                                    : List.of(
                                                            "pacttest.account@digital.cabinet-office.gov.uk"))
                                    .withScopes(
                                            !isNull(request.getScopes())
                                                    ? request.getScopes()
                                                    : List.of("openid", "email", "phone"))
                                    .withPostLogoutRedirectUrls(
                                            !isNull(request.getPostLogoutRedirectUris())
                                                    ? request.getPostLogoutRedirectUris()
                                                    : Collections.emptyList())
                                    .withServiceType(
                                            !isNull(request.getServiceType())
                                                    ? request.getServiceType()
                                                    : "MANDATORY")
                                    .withSubjectType(SUBJECT_TYPE)
                                    .withSectorIdentifierUri(
                                            !isNull(request.getSectorIdentifierUri())
                                                    ? request.getSectorIdentifierUri()
                                                    : "http://gov.uk")
                                    .withClientType(
                                            !isNull(request.getClientType())
                                                    ? request.getClientType()
                                                    : CLIENT_TYPE);
                        });
    }

    @TestTemplate
    @ExtendWith(PactVerificationInvocationContextProvider.class)
    void verifyInteraction(PactVerificationContext context) {
        context.verifyInteraction();
    }
}

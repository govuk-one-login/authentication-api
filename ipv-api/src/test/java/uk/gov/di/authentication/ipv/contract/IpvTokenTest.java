package uk.gov.di.authentication.ipv.contract;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.PactDslJsonBody;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.consumer.junit.MockServerConfig;
import au.com.dius.pact.consumer.junit5.PactConsumerTest;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.core.model.PactSpecVersion;
import au.com.dius.pact.core.model.RequestResponsePact;
import au.com.dius.pact.core.model.annotations.Pact;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.id.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.authentication.ipv.services.IPVTokenService;
import uk.gov.di.orchestration.shared.helpers.*;
import uk.gov.di.orchestration.shared.services.*;

import java.net.URI;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;


@PactConsumerTest
@MockServerConfig(hostInterface = "localHost", port = "1234")
public class IpvTokenTest {
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final KmsConnectionService kmsConnectionService = mock(KmsConnectionService.class);
    private IPVTokenService ipvTokenService;

    private static final URI IPV_URI = URI.create("http://ipv/");
    private static final ClientID CLIENT_ID = new ClientID("authOrchestrator");
    private static final String IPV_TOKEN_PATH = "token";
    private final String ACCESS_TOKEN_FIELD = "access_token";
    private final String TOKEN_TYPE_FIELD = "token_type";
    private final String EXPIRES_IN_FIELD = "expires_in";
    private final String URI_FIELD = "uri";
    private final String ACCESS_TOKEN_VALUE = "740e5834-3a29-46b4-9a6f-16142fde533a";
    private final String TOKEN_TYPE_VALUE = "Bearer";
    private final String EXPIRES_IN_VALUE = "3600";
    private final String URI_VALUE = "https://localhost";
    private static final String KEY_ID = "14342354354353";

    private static final String PRIVATE_JWT_KEY =
            "{\"kty\":\"EC\",\"d\":\"A2cfN3vYKgOQ_r1S6PhGHCLLiVEqUshFYExrxMwkq_A\",\"crv\":\"P-256\",\"kid\":\"14342354354353\",\"x\":\"BMyQQqr3NEFYgb9sEo4hRBje_HHEsy87PbNIBGL4Uiw\",\"y\":\"qoXdkYVomy6HWT6yNLqjHSmYoICs6ioUF565Btx0apw\",\"alg\":\"ES256\"}";

    private static final String CLIENT_ASSERTION_HEADER =
            "eyJraWQiOiIxNDM0MjM1NDM1NDM1MyIsImFsZyI6IkVTMjU2In0";
    private static final String CLIENT_ASSERTION_BODY =
            "eyJzdWIiOiJhdXRoT3JjaGVzdHJhdG9yIiwiYXVkIjoiaHR0cDovL2lwdi8iLCJuYmYiOjk0NjY4NDgwMCwiaXNzIjoiYXV0aE9yY2hlc3RyYXRvciIsImV4cCI6NDA3MDkwODgwMCwiaWF0Ijo5NDY2ODQ4MDAsImp0aSI6IjEifQ";
    private static final String CLIENT_ASSERTION_SIGNATURE =
            "L3h9FCeYLIUCpjMGjnBm6Ca8GmKqICHSGY5Aq0svbMNTmLP04dzh5V8E6N2InzbXC9_4Q7u6mAo3yubbYsVSdA";
    private static final byte[] SIGNATURE_BYTES = {
        (byte) 48,
        (byte) 68,
        (byte) 2,
        (byte) 32,
        (byte) 47,
        (byte) 120,
        (byte) 125,
        (byte) 20,
        (byte) 39,
        (byte) -104,
        (byte) 44,
        (byte) -123,
        (byte) 2,
        (byte) -90,
        (byte) 51,
        (byte) 6,
        (byte) -114,
        (byte) 112,
        (byte) 102,
        (byte) -24,
        (byte) 38,
        (byte) -68,
        (byte) 26,
        (byte) 98,
        (byte) -86,
        (byte) 32,
        (byte) 33,
        (byte) -46,
        (byte) 25,
        (byte) -114,
        (byte) 64,
        (byte) -85,
        (byte) 75,
        (byte) 47,
        (byte) 108,
        (byte) -61,
        (byte) 2,
        (byte) 32,
        (byte) 83,
        (byte) -104,
        (byte) -77,
        (byte) -12,
        (byte) -31,
        (byte) -36,
        (byte) -31,
        (byte) -27,
        (byte) 95,
        (byte) 4,
        (byte) -24,
        (byte) -35,
        (byte) -120,
        (byte) -97,
        (byte) 54,
        (byte) -41,
        (byte) 11,
        (byte) -33,
        (byte) -8,
        (byte) 67,
        (byte) -69,
        (byte) -70,
        (byte) -104,
        (byte) 10,
        (byte) 55,
        (byte) -54,
        (byte) -26,
        (byte) -37,
        (byte) 98,
        (byte) -59,
        (byte) 82,
        (byte) 116
    };

    @BeforeEach
    void setUp() {
        ipvTokenService = new IPVTokenService(configService, kmsConnectionService);
    }

    @Pact(consumer = "IPV-orch-token-consumer")
    RequestResponsePact success(PactDslWithProvider builder) {
        return builder.given("dummyAuthCode is a valid authorization code")
                .given("localHost is a valid resource URI")
                .given("the JWT is signed with " + PRIVATE_JWT_KEY)
                .uponReceiving("token request")
                .path("/" + IPV_TOKEN_PATH)
                .method("POST")
                .body(
                        "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&"
                                + "code=dummyAuthCode&"
                                + "grant_type=authorization_code&"
                                + "resource="
                                + "http://localhost:1234/token"
                                + "&"
                                + "client_assertion="
                                + CLIENT_ASSERTION_HEADER
                                + "."
                                + CLIENT_ASSERTION_BODY
                                + "."
                                + CLIENT_ASSERTION_SIGNATURE
                                + "&"
                                + "client_id="
                                + CLIENT_ID.getValue())
                .headers("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
                .willRespondWith()
                .status(200)
                .body(
                        new PactDslJsonBody()
                                .stringType(ACCESS_TOKEN_FIELD, ACCESS_TOKEN_VALUE)
                                .stringType(TOKEN_TYPE_FIELD, TOKEN_TYPE_VALUE)
                                .stringType(EXPIRES_IN_FIELD, EXPIRES_IN_VALUE)
                                .stringType(URI_FIELD, URI_VALUE))
                .toPact();
    }

    @Test
    @PactTestFor(
            providerName = "IPV-orch-token-provider",
            pactMethod = "success",
            pactVersion = PactSpecVersion.V3)
    void getIPVResponse(MockServer mockServer) {
        when(configService.getIPVAuthorisationClientId()).thenReturn(CLIENT_ID.getValue());
        when(configService.getIPVBackendURI()).thenReturn(URI.create(mockServer.getUrl()));
        when(configService.getIPVAudience()).thenReturn(IPV_URI.toString());
        when(configService.getIPVTokenSigningKeyAlias()).thenReturn(KEY_ID);
        when(kmsConnectionService.sign(any(SignRequest.class))).thenReturn(mockKmsReturn());

        TokenResponse tokenResponse;

        try (MockedStatic<NowHelper> mockedNowHelperClass = Mockito.mockStatic(NowHelper.class)) {
            mockedNowHelperClass
                    .when(NowHelper::now)
                    .thenReturn(Date.from(Instant.parse("2000-01-01T00:00:00.00Z")));
            mockedNowHelperClass
                    .when(() -> NowHelper.nowPlus(5L, ChronoUnit.MINUTES))
                    .thenReturn(Date.from(Instant.parse("2099-01-01T00:00:00.00Z")));
            try (var mockJwtId =
                    mockConstruction(
                            JWTID.class,
                            (mock, context) -> {
                                when(mock.getValue()).thenReturn("1");
                            })) {
                   tokenResponse = ipvTokenService.getToken("dummyAuthCode");
            }
        }

        assertThat(tokenResponse.indicatesSuccess(), equalTo(true));
        assertThat(tokenResponse.toSuccessResponse().getTokens().toString(), equalTo(getSuccessfulTokenHttpResponse()));
    }

    private SignResponse mockKmsReturn() {
        return SignResponse.builder()
                .signature(SdkBytes.fromByteArray(SIGNATURE_BYTES))
                .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                .keyId(KEY_ID)
                .build();
    }

    public String getSuccessfulTokenHttpResponse() {
        return "{"
                        + "\""
                        + ACCESS_TOKEN_FIELD
                        + "\":\""
                        + ACCESS_TOKEN_VALUE
                        + "\","
                        + "\""
                        + TOKEN_TYPE_FIELD
                        + "\":\""
                        + TOKEN_TYPE_VALUE
                        + "\","
                        + "\""
                        + EXPIRES_IN_FIELD
                        + "\":"
                        + EXPIRES_IN_VALUE
                        + "}";
    }
}

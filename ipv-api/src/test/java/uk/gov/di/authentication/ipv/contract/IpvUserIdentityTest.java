package uk.gov.di.authentication.ipv.contract;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.consumer.junit5.PactConsumerTest;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.core.model.PactSpecVersion;
import au.com.dius.pact.core.model.RequestResponsePact;
import au.com.dius.pact.core.model.annotations.Pact;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.*;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.ipv.services.IPVTokenService;
import uk.gov.di.orchestration.shared.exceptions.UnsuccessfulCredentialResponseException;
import uk.gov.di.orchestration.shared.helpers.*;
import uk.gov.di.orchestration.shared.services.*;

import static au.com.dius.pact.consumer.dsl.LambdaDsl.newJsonBody;
import static com.nimbusds.common.contenttype.ContentType.APPLICATION_JSON;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

@PactConsumerTest
public class IpvUserIdentityTest {
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final KmsConnectionService kmsConnectionService = mock(KmsConnectionService.class);
    private IPVTokenService ipvTokenService;
    private Tokens tokens;

    private final String IPV_USER_IDENTITY_PATH = "user-identity";
    private final String SUB_FIELD = "sub";
    private final String VOT_FIELD = "vot";
    private final String VTM_FIELD = "vtm";
    private final String CREDENTIALS_JWT_FIELD = "https://vocab.account.gov.uk/v1/credentialJWT";
    private final String CORE_IDENTITY_FIELD = "https://vocab.account.gov.uk/v1/coreIdentity";
    private final String CORE_IDENTITY_NAME_FIELD = "name";
    private final String CORE_IDENTITY_NAME_PARTS_FIELD = "nameParts";
    private final String CORE_IDENTITY_BIRTH_FIELD = "birthDate";
    private final String SUB_VALUE = "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6";
    private final String VOT_VALUE = "P2";
    private final String VTM_VALUE = "http://localhost/trustmark";
    private final String CREDENTIALS_JWT_VALUE = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9";
    private final String CORE_IDENTITY_BIRTH_VALUE = "1964-11-07";

    @BeforeEach
    void setUp() {
        ipvTokenService = new IPVTokenService(configService, kmsConnectionService);
        tokens = new Tokens(new BearerAccessToken("accessToken"), null);
    }

    @Pact(consumer = "OrchUserIdentityConsumer")
    RequestResponsePact validRequestReturnsValidUserInfo(PactDslWithProvider builder) {
        return builder.given("accessToken is a valid access token")
                .uponReceiving("Valid access token")
                .path("/" + IPV_USER_IDENTITY_PATH)
                .method("GET")
                .matchHeader(
                        "Authorization",
                        "^(?i)Bearer (.*)(?-i)",
                        tokens.getAccessToken().toAuthorizationHeader())
                .willRespondWith()
                .status(200)
                .body(
                        newJsonBody(
                                        (body) -> {
                                            body.stringType(SUB_FIELD, SUB_VALUE);
                                            body.stringType(VOT_FIELD, VOT_VALUE);
                                            body.stringType(VTM_FIELD, VTM_VALUE);
                                            body.unorderedMinArray(
                                                    CREDENTIALS_JWT_FIELD,
                                                    1,
                                                    (jwt) -> {
                                                        jwt.stringType(CREDENTIALS_JWT_VALUE);
                                                    });
                                            body.object(
                                                    CORE_IDENTITY_FIELD,
                                                    (core) -> {
                                                        core.minArrayLike(
                                                                CORE_IDENTITY_NAME_FIELD,
                                                                1,
                                                                (name) -> {
                                                                    name.eachLike(
                                                                            CORE_IDENTITY_NAME_PARTS_FIELD,
                                                                            2,
                                                                            (nameParts) -> {
                                                                                nameParts
                                                                                        .stringType(
                                                                                                "type",
                                                                                                "Name");
                                                                                nameParts
                                                                                        .stringType(
                                                                                                "value",
                                                                                                "Kenneth");
                                                                            });
                                                                });
                                                        core.minArrayLike(
                                                                CORE_IDENTITY_BIRTH_FIELD,
                                                                1,
                                                                (birthDate) -> {
                                                                    birthDate.stringType(
                                                                            "value",
                                                                            CORE_IDENTITY_BIRTH_VALUE);
                                                                });
                                                    });
                                        })
                                .build())
                .toPact();
    }

    @Test
    @PactTestFor(
            providerName = "IpvCoreBackUserIdentityProvider",
            pactMethod = "validRequestReturnsValidUserInfo",
            pactVersion = PactSpecVersion.V3)
    void getIPVUserInfoSuccessResponse(MockServer mockServer)
            throws UnsuccessfulCredentialResponseException, ParseException {

        var userInfo =
                ipvTokenService.sendIpvUserIdentityRequest(
                        new UserInfoRequest(
                                ConstructUriHelper.buildURI(
                                        mockServer.getUrl(), IPV_USER_IDENTITY_PATH),
                                tokens.getBearerAccessToken()));

        assertThat(userInfo, equalTo(getUserInfoFromSuccessfulUserIdentityHttpResponse()));
    }

    @Pact(consumer = "OrchUserIdentityConsumer")
    RequestResponsePact invalidTokenReturnErrorResponse(PactDslWithProvider builder) {
        return builder.given("accessToken is a invalid access token")
                .uponReceiving("Invalid access token")
                .path("/" + IPV_USER_IDENTITY_PATH)
                .method("GET")
                .matchHeader(
                        "Authorization",
                        "^(?i)Bearer (.*)(?-i)",
                        tokens.getAccessToken().toAuthorizationHeader())
                .willRespondWith()
                .comment("test")
                .status(403)
                .toPact();
    }

    @Test
    @PactTestFor(
            providerName = "IpvCoreBackUserIdentityProvider",
            pactMethod = "invalidTokenReturnErrorResponse",
            pactVersion = PactSpecVersion.V3)
    void getIPVUserInfoErrorResponse(MockServer mockServer) {

        UnsuccessfulCredentialResponseException exception =
                assertThrows(
                        UnsuccessfulCredentialResponseException.class,
                        () -> {
                            ipvTokenService.sendIpvUserIdentityRequest(
                                    new UserInfoRequest(
                                            ConstructUriHelper.buildURI(
                                                    mockServer.getUrl(), IPV_USER_IDENTITY_PATH),
                                            tokens.getBearerAccessToken()));
                        });

        assertThat(exception.getHttpCode(), equalTo(0));
    }

    private UserInfo getUserInfoFromSuccessfulUserIdentityHttpResponse() throws ParseException {
        var userInfoHTTPResponse = new HTTPResponse(200);
        userInfoHTTPResponse.setEntityContentType(APPLICATION_JSON);
        userInfoHTTPResponse.setBody(
                "{"
                        + " \""
                        + SUB_FIELD
                        + "\": \""
                        + SUB_VALUE
                        + "\","
                        + " \""
                        + VOT_FIELD
                        + "\": \""
                        + VOT_VALUE
                        + "\","
                        + " \""
                        + VTM_FIELD
                        + "\": \""
                        + VTM_VALUE
                        + "\","
                        + " \""
                        + CREDENTIALS_JWT_FIELD
                        + "\": ["
                        + "     \""
                        + CREDENTIALS_JWT_VALUE
                        + "\""
                        + "],"
                        + " \""
                        + CORE_IDENTITY_FIELD
                        + "\": {"
                        + "     \""
                        + CORE_IDENTITY_NAME_FIELD
                        + "\": ["
                        + "         { \""
                        + CORE_IDENTITY_NAME_PARTS_FIELD
                        + "\": ["
                        + "         { \"type\":\"Name\",\"value\":\"Kenneth\" }, { \"type\":\"Name\",\"value\":\"Kenneth\" } "
                        + "         ] "
                        + "     } "
                        + "     ],"
                        + "     \""
                        + CORE_IDENTITY_BIRTH_FIELD
                        + "\": [ "
                        + "         { \"value\": \""
                        + CORE_IDENTITY_BIRTH_VALUE
                        + "\" } "
                        + "     ]"
                        + " }"
                        + "}");
        var userIdentityResponse = UserInfoResponse.parse(userInfoHTTPResponse);
        return userIdentityResponse.toSuccessResponse().getUserInfo();
    }
}

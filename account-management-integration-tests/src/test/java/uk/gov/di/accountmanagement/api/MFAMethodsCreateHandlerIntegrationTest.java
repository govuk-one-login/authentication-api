package uk.gov.di.accountmanagement.api;

import com.google.gson.JsonParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.accountmanagement.lambda.MFAMethodsCreateHandler;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.entity.mfa.MfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.request.RequestAuthAppMfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.request.RequestSmsMfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.response.ResponseAuthAppMfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.response.ResponseSmsMfaDetail;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;

class MFAMethodsCreateHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String TEST_EMAIL = "test@email.com";
    private static final String TEST_PASSWORD = "test-password";
    private static final String TEST_PHONE_NUMBER = "07700900000";
    private static final String TEST_PHONE_NUMBER_TWO = "07700900111";
    private static final String TEST_CREDENTIAL = "ZZ11BB22CC33DD44EE55FF66GG77HH88II99JJ00";
    private static final String INTERNAL_SECTOR_HOST = "test.account.gov.uk";
    private static String TEST_PUBLIC_SUBJECT;
    private static String testInternalSubject;
    private static final MFAMethod defaultPrioritySms =
            MFAMethod.smsMfaMethod(
                    true,
                    true,
                    TEST_PHONE_NUMBER,
                    PriorityIdentifier.DEFAULT,
                    UUID.randomUUID().toString());
    private static final MFAMethod backupPrioritySms =
            MFAMethod.smsMfaMethod(
                    true,
                    true,
                    TEST_PHONE_NUMBER_TWO,
                    PriorityIdentifier.BACKUP,
                    UUID.randomUUID().toString());
    private static final MFAMethod defaultPriorityAuthApp =
            MFAMethod.authAppMfaMethod(
                    TEST_CREDENTIAL,
                    true,
                    true,
                    PriorityIdentifier.DEFAULT,
                    UUID.randomUUID().toString());

    @BeforeEach
    void setUp() {
        ConfigurationService mfaMethodEnabledConfigurationService =
                new ConfigurationService() {
                    @Override
                    public boolean isMfaMethodManagementApiEnabled() {
                        return true;
                    }
                };

        handler = new MFAMethodsCreateHandler(mfaMethodEnabledConfigurationService);
        userStore.signUp(TEST_EMAIL, TEST_PASSWORD);
        TEST_PUBLIC_SUBJECT =
                userStore.getUserProfileFromEmail(TEST_EMAIL).get().getPublicSubjectID();
        byte[] salt = userStore.addSalt(TEST_EMAIL);
        testInternalSubject =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        userStore.getUserProfileFromEmail(TEST_EMAIL).get().getSubjectID(),
                        INTERNAL_SECTOR_HOST,
                        salt);
    }

    @Test
    void shouldReturn200AndMfaMethodDataWhenAuthAppUserAddsSmsMfa() {
        userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, defaultPriorityAuthApp);
        userStore.setMfaMethodsMigrated(TEST_EMAIL, true);

        var response =
                makeRequest(
                        Optional.of(
                                constructRequestBody(
                                        PriorityIdentifier.BACKUP,
                                        new RequestSmsMfaDetail(TEST_PHONE_NUMBER, "123456"))),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", TEST_PUBLIC_SUBJECT),
                        Map.of("principalId", testInternalSubject));

        assertEquals(200, response.getStatusCode());

        List<MFAMethod> mfaMethods = userStore.getMfaMethod(TEST_EMAIL);

        var retrievedSmsMethod =
                mfaMethods.stream()
                        .filter(
                                mfaMethod ->
                                        mfaMethod
                                                .getMfaMethodType()
                                                .equals(MFAMethodType.SMS.getValue()))
                        .findFirst()
                        .get();

        assertEquals(PriorityIdentifier.BACKUP.toString(), retrievedSmsMethod.getPriority());
        assertEquals(TEST_PHONE_NUMBER, retrievedSmsMethod.getDestination());
        assertTrue(retrievedSmsMethod.isEnabled());
        assertTrue(retrievedSmsMethod.isMethodVerified());

        var extractedMfaIdentifier = retrievedSmsMethod.getMfaIdentifier();
        var expectedJson =
                constructExpectedResponse(
                        extractedMfaIdentifier,
                        PriorityIdentifier.BACKUP,
                        true,
                        new ResponseSmsMfaDetail(TEST_PHONE_NUMBER));
        var expectedResponse = JsonParser.parseString(expectedJson).getAsJsonObject().toString();

        assertEquals(expectedResponse, response.getBody());
    }

    @Test
    void shouldReturn200AndMfaMethodDataWhenSmsUserAddsAuthAppMfa() {
        userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, defaultPrioritySms);
        userStore.setMfaMethodsMigrated(TEST_EMAIL, true);

        var response =
                makeRequest(
                        Optional.of(
                                constructRequestBody(
                                        PriorityIdentifier.BACKUP,
                                        new RequestAuthAppMfaDetail(TEST_CREDENTIAL))),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", TEST_PUBLIC_SUBJECT),
                        Map.of("principalId", testInternalSubject));
        assertEquals(200, response.getStatusCode());

        List<MFAMethod> mfaMethods = userStore.getMfaMethod(TEST_EMAIL);

        var retrievedAuthAppMethod =
                mfaMethods.stream()
                        .filter(
                                mfaMethod ->
                                        mfaMethod
                                                .getMfaMethodType()
                                                .equals(MFAMethodType.AUTH_APP.getValue()))
                        .findFirst()
                        .get();

        assertEquals(TEST_CREDENTIAL, retrievedAuthAppMethod.getCredentialValue());
        assertEquals(PriorityIdentifier.BACKUP.toString(), retrievedAuthAppMethod.getPriority());
        assertTrue(retrievedAuthAppMethod.isEnabled());
        assertTrue(retrievedAuthAppMethod.isMethodVerified());

        var extractedMfaIdentifier = retrievedAuthAppMethod.getMfaIdentifier();
        var expectedJson =
                constructExpectedResponse(
                        extractedMfaIdentifier,
                        PriorityIdentifier.BACKUP,
                        true,
                        new ResponseAuthAppMfaDetail(TEST_CREDENTIAL));

        var expectedResponse = JsonParser.parseString(expectedJson).getAsJsonObject().toString();

        assertEquals(expectedResponse, response.getBody());
    }

    @Test
    void shouldReturn400AndBadRequestWhenPathParameterIsNotPresent() {
        var response =
                makeRequest(
                        Optional.of(
                                constructRequestBody(
                                        PriorityIdentifier.BACKUP,
                                        new RequestSmsMfaDetail(TEST_PHONE_NUMBER, "123456"))),
                        Collections.emptyMap(),
                        Collections.emptyMap());
        assertEquals(400, response.getStatusCode());
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1001));
    }

    @Test
    void shouldReturn400AndBadRequestWhenPublicSubjectIsNotInUserStore() {
        var response =
                makeRequest(
                        Optional.of(
                                constructRequestBody(
                                        PriorityIdentifier.BACKUP,
                                        new RequestSmsMfaDetail(TEST_PHONE_NUMBER, "123456"))),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", "incorrect-public-subject-id"),
                        Map.of("principalId", testInternalSubject));
        assertEquals(404, response.getStatusCode());
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1056));
    }

    private static Stream<MFAMethodType> invalidMfaMethodTypes() {
        return Stream.of(MFAMethodType.EMAIL, MFAMethodType.NONE);
    }

    @ParameterizedTest
    @MethodSource("invalidMfaMethodTypes")
    void shouldReturn400AndBadRequestWhenMfaMethodTypeIsInvalid(MFAMethodType invalidMethodType) {
        var response =
                makeRequest(
                        Optional.of(
                                format(
                                        """
                                                {
                                                  "mfaMethod": {
                                                    "priorityIdentifier": "BACKUP",
                                                    "method": {
                                                       "mfaMethodType": "%s",
                                                       "phoneNumber": "07900000000"
                                                    }
                                                  }
                                                }
                                                """,
                                        invalidMethodType)),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", TEST_PUBLIC_SUBJECT),
                        Map.of("principalId", testInternalSubject));
        assertEquals(400, response.getStatusCode());
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1001));
    }

    @Test
    void shouldReturn400ErrorResponseWhenAddingMfaAfterMfaCountLimitReached() {
        userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, defaultPrioritySms);
        userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, backupPrioritySms);
        userStore.setMfaMethodsMigrated(TEST_EMAIL, true);

        var response =
                makeRequest(
                        Optional.of(
                                constructRequestBody(
                                        PriorityIdentifier.BACKUP,
                                        new RequestSmsMfaDetail(TEST_PHONE_NUMBER, "123456"))),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", TEST_PUBLIC_SUBJECT),
                        Map.of("principalId", testInternalSubject));

        assertEquals(400, response.getStatusCode());
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1068));
    }

    @Test
    void shouldReturn400ErrorResponseWhenSmsUserAddsSmsMfaWithSamePhoneNumber() {
        userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, defaultPrioritySms);
        userStore.setMfaMethodsMigrated(TEST_EMAIL, true);

        var response =
                makeRequest(
                        Optional.of(
                                constructRequestBody(
                                        PriorityIdentifier.BACKUP,
                                        new RequestSmsMfaDetail(TEST_PHONE_NUMBER, "123456"))),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", TEST_PUBLIC_SUBJECT),
                        Map.of("principalId", testInternalSubject));

        assertEquals(400, response.getStatusCode());
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1069));
    }

    @Test
    void shouldReturn400ErrorResponseWhenAuthAppAddsSecondAuthApp() {
        userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, defaultPriorityAuthApp);
        userStore.setMfaMethodsMigrated(TEST_EMAIL, true);

        var response =
                makeRequest(
                        Optional.of(
                                constructRequestBody(
                                        PriorityIdentifier.BACKUP,
                                        new RequestAuthAppMfaDetail(
                                                "AA99BB88CC77DD66EE55FF44GG33HH22II11JJ00"))),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", TEST_PUBLIC_SUBJECT),
                        Map.of("principalId", testInternalSubject));

        assertEquals(400, response.getStatusCode());
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1070));
    }

    @Test
    void shouldReturn401WhenPrincipalIsInvalid() {
        var response =
                makeRequest(
                        Optional.of(
                                constructRequestBody(
                                        PriorityIdentifier.BACKUP,
                                        new RequestAuthAppMfaDetail(
                                                MFAMethodType.AUTH_APP,
                                                "AA99BB88CC77DD66EE55FF44GG33HH22II11JJ00"))),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", TEST_PUBLIC_SUBJECT),
                        Map.of("principalId", "invalid"));

        assertEquals(401, response.getStatusCode());
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1079));
    }

    private static String constructRequestBody(
            PriorityIdentifier priorityIdentifier, MfaDetail mfaDetail) {
        return format(
                """
                        {
                          "mfaMethod": {
                            "priorityIdentifier": "%s",
                            "method": %s
                          }
                        }
                        """,
                priorityIdentifier, constructRequestMfaDetailJson(mfaDetail));
    }

    private static String constructExpectedResponse(
            String mfaIdentifier,
            PriorityIdentifier priorityIdentifier,
            boolean methodVerified,
            MfaDetail mfaDetail) {
        return format(
                """
                        {
                          "mfaIdentifier": "%s",
                          "priorityIdentifier": "%s",
                          "methodVerified": %s,
                          "method": %s
                        }
                        """,
                mfaIdentifier,
                priorityIdentifier,
                methodVerified,
                constructResponseMfaDetailJson(mfaDetail));
    }

    private static String constructResponseMfaDetailJson(MfaDetail mfaDetail) {
        if (mfaDetail instanceof ResponseSmsMfaDetail) {
            return format(
                    """
                            {
                              "mfaMethodType": "%s",
                              "phoneNumber": "%s"
                            }
                            """,
                    (mfaDetail).mfaMethodType(), ((ResponseSmsMfaDetail) mfaDetail).phoneNumber());
        } else {
            return format(
                    """
                            {
                              "mfaMethodType": "%s",
                              "credential": "%s"
                            }
                            """,
                    ((ResponseAuthAppMfaDetail) mfaDetail).mfaMethodType(),
                    ((ResponseAuthAppMfaDetail) mfaDetail).credential());
        }
    }

    private static String constructRequestMfaDetailJson(MfaDetail mfaDetail) {
        if (mfaDetail instanceof RequestSmsMfaDetail) {
            return format(
                    """
                            {
                              "mfaMethodType": "%s",
                              "phoneNumber": "%s",
                              "otp": "%s"
                            }
                            """,
                    ((RequestSmsMfaDetail) mfaDetail).mfaMethodType(),
                    ((RequestSmsMfaDetail) mfaDetail).phoneNumber(),
                    ((RequestSmsMfaDetail) mfaDetail).otp());
        } else {
            return format(
                    """
                            {
                              "mfaMethodType": "%s",
                              "credential": "%s"
                            }
                            """,
                    ((RequestAuthAppMfaDetail) mfaDetail).mfaMethodType(),
                    ((RequestAuthAppMfaDetail) mfaDetail).credential());
        }
    }
}

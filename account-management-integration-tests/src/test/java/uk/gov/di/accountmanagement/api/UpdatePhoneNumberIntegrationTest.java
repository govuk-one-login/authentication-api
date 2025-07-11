package uk.gov.di.accountmanagement.api;

import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.entity.UpdatePhoneNumberRequest;
import uk.gov.di.accountmanagement.lambda.UpdatePhoneNumberHandler;
import uk.gov.di.accountmanagement.testsupport.helpers.NotificationAssertionHelper;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static com.google.i18n.phonenumbers.PhoneNumberUtil.PhoneNumberType.MOBILE;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_UPDATE_PHONE_NUMBER;
import static uk.gov.di.accountmanagement.entity.NotificationType.PHONE_NUMBER_UPDATED;
import static uk.gov.di.accountmanagement.testsupport.helpers.NotificationAssertionHelper.assertNoNotificationsReceived;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsSubmittedWithMatchingNames;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class UpdatePhoneNumberIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String TEST_EMAIL = "joe.bloggs+3@digital.cabinet-office.gov.uk";
    private static final String NEW_PHONE_NUMBER =
            Long.toString(
                    PhoneNumberUtil.getInstance()
                            .getExampleNumberForType("GB", MOBILE)
                            .getNationalNumber());
    private static final String INTERNAl_SECTOR_HOST = "test.account.gov.uk";
    private static final Subject SUBJECT = new Subject();

    @BeforeEach
    void setup() {
        handler = new UpdatePhoneNumberHandler(TXMA_ENABLED_CONFIGURATION_SERVICE);
        txmaAuditQueue.clear();
    }

    private static Stream<String> phoneNumbers() {
        return Stream.of(
                "+447316763843",
                "+4407316763843",
                "+33645453322",
                "+447316763843",
                "+33645453322",
                "+33645453322",
                "07911123456",
                NEW_PHONE_NUMBER);
    }

    @ParameterizedTest
    @MethodSource("phoneNumbers")
    void shouldSendNotificationAndReturn204WhenUpdatingPhoneNumberIsSuccessful(String phoneNumber) {
        var internalSubId = setupUserAndRetrieveInternalCommonSubId();
        var otp = redis.generateAndSavePhoneNumberCode(TEST_EMAIL, 300);

        var response =
                makeRequest(
                        Optional.of(new UpdatePhoneNumberRequest(TEST_EMAIL, phoneNumber, otp)),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("principalId", internalSubId));

        assertThat(response, hasStatus(HttpStatus.SC_NO_CONTENT));

        var expectedMatchType = PhoneNumberUtil.MatchType.NSN_MATCH;

        if (phoneNumber.startsWith("+")) {
            expectedMatchType = PhoneNumberUtil.MatchType.EXACT_MATCH;
        }

        assertThat(
                PhoneNumberUtil.getInstance()
                        .isNumberMatch(
                                userStore.getPhoneNumberForUser(TEST_EMAIL).get(), phoneNumber),
                is(expectedMatchType));

        NotificationAssertionHelper.assertNotificationsReceived(
                notificationsQueue,
                List.of(new NotifyRequest(TEST_EMAIL, PHONE_NUMBER_UPDATED, SupportedLanguage.EN)));

        assertTxmaAuditEventsSubmittedWithMatchingNames(
                txmaAuditQueue, List.of(AUTH_UPDATE_PHONE_NUMBER));
    }

    @Test
    void shouldReturn400WhenOtpIsInvalid() throws Exception {
        var internalSubId = setupUserAndRetrieveInternalCommonSubId();
        redis.generateAndSavePhoneNumberCode(TEST_EMAIL, 300);
        var badOtp = "012345";

        var response =
                makeRequest(
                        Optional.of(
                                new UpdatePhoneNumberRequest(TEST_EMAIL, NEW_PHONE_NUMBER, badOtp)),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("principalId", internalSubId));

        assertThat(response, hasStatus(HttpStatus.SC_BAD_REQUEST));
        assertThat(response, hasBody(objectMapper.writeValueAsString(ErrorResponse.INVALID_OTP)));

        assertNoNotificationsReceived(notificationsQueue);

        AuditAssertionsHelper.assertNoTxmaAuditEventsReceived(txmaAuditQueue);
    }

    @Test
    void shouldThrowExceptionWhenUserAttemptsToUpdateDifferentAccount() {
        var internalSubId = setupUserAndRetrieveInternalCommonSubId();
        userStore.signUp("other.user@digital.cabinet-office.gov.uk", "password-2", new Subject());
        var otp =
                redis.generateAndSavePhoneNumberCode(
                        "other.user@digital.cabinet-office.gov.uk", 300);

        Exception ex =
                assertThrows(
                        RuntimeException.class,
                        () ->
                                makeRequest(
                                        Optional.of(
                                                new UpdatePhoneNumberRequest(
                                                        "other.user@digital.cabinet-office.gov.uk",
                                                        NEW_PHONE_NUMBER,
                                                        otp)),
                                        Collections.emptyMap(),
                                        Collections.emptyMap(),
                                        Collections.emptyMap(),
                                        Map.of("principalId", internalSubId)));

        assertThat(ex.getMessage(), is("Invalid Principal in request"));
    }

    @Test
    void shouldThrowExceptionWhenSubjectIdMissing() {
        setupUserAndRetrieveInternalCommonSubId();
        var otp = redis.generateAndSavePhoneNumberCode(TEST_EMAIL, 300);

        Exception ex =
                assertThrows(
                        RuntimeException.class,
                        () ->
                                makeRequest(
                                        Optional.of(
                                                new UpdatePhoneNumberRequest(
                                                        TEST_EMAIL, NEW_PHONE_NUMBER, otp)),
                                        Collections.emptyMap(),
                                        Collections.emptyMap()));

        assertThat(ex.getMessage(), is("Invalid Principal in request"));
    }

    private String setupUserAndRetrieveInternalCommonSubId() {
        userStore.signUp(TEST_EMAIL, "password-1", SUBJECT);
        byte[] salt = userStore.addSalt(TEST_EMAIL);
        var internalCommonSubjectId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        SUBJECT.getValue(), INTERNAl_SECTOR_HOST, salt);
        accountModifiersStore.setAccountRecoveryBlock(internalCommonSubjectId);
        return internalCommonSubjectId;
    }
}

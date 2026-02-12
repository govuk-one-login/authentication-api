package uk.gov.di.authentication.userpermissions.example;

import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.userpermissions.PermissionDecisionManager;
import uk.gov.di.authentication.userpermissions.PermissionDecisions;
import uk.gov.di.authentication.userpermissions.UserActions;
import uk.gov.di.authentication.userpermissions.UserActionsManager;
import uk.gov.di.authentication.userpermissions.entity.PermissionContext;

import static java.lang.String.format;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class ExampleSmsVerificationHandler {
    private static final String EXPECTED_OTP = "372615";

    private final PermissionDecisions permissionDecisions;
    private final UserActions userActions;

    public ExampleSmsVerificationHandler() {
        var configurationService = ConfigurationService.getInstance();
        this.permissionDecisions = new PermissionDecisionManager(configurationService);
        this.userActions = new UserActionsManager(configurationService);
    }

    public ExampleSmsVerificationHandler(
            PermissionDecisions permissionDecisions, UserActions userActions) {
        this.permissionDecisions = permissionDecisions;
        this.userActions = userActions;
    }

    public String handle(String submittedOtp) {
        JourneyType journeyType = JourneyType.SIGN_IN;
        var permissionContext =
                PermissionContext.builder()
                        .withInternalSubjectId("439qklhxm39qfja3sdg43")
                        .withRpPairwiseId(
                                "urn:fdc:gov.uk:2022:D0eushEU31EeUDUi_EJVz2seIGwfF_QfTZSm_yq1Rfs")
                        .withEmailAddress("test@example.com")
                        .withAuthSessionItem(new AuthSessionItem())
                        .build();

        var checkResult =
                permissionDecisions.canVerifyMfaOtp(
                        journeyType,
                        permissionContext,
                        permitted -> {
                            if (!submittedOtp.equals(EXPECTED_OTP)) {
                                userActions.incorrectSmsOtpReceived(journeyType, permissionContext);
                                return "400: Incorrect OTP received";
                            }

                            sendAuditEvent(
                                    "OTP_VERIFIED",
                                    AuditContext.emptyAuditContext()
                                            .withMetadataItem(
                                                    pair(
                                                            "attempts",
                                                            permitted.attemptCount() + 1)));

                            userActions.correctSmsOtpReceived(journeyType, permissionContext);
                            return "200: Success";
                        },
                        lockedOut -> {
                            sendAuditEvent(
                                    "LOCKED_OUT",
                                    AuditContext.emptyAuditContext()
                                            .withMetadataItem(
                                                    pair("reason", lockedOut.forbiddenReason()))
                                            .withMetadataItem(
                                                    pair("until", lockedOut.lockedUntil())));
                            return format(
                                    "403: User is temporarily locked out due to %s until %s",
                                    lockedOut.forbiddenReason(), lockedOut.lockedUntil());
                        });
        if (checkResult.isFailure()) {
            return (format("500: %s", checkResult.getFailure().name()));
        }

        return checkResult.getSuccess();
    }

    private void sendAuditEvent(String eventName, AuditContext auditContext) {
        System.out.println(eventName + auditContext.toString());
    }
}

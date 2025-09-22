package uk.gov.di.authentication.userpermissions;

import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.userpermissions.entity.Decision;
import uk.gov.di.authentication.userpermissions.entity.DecisionError;
import uk.gov.di.authentication.userpermissions.entity.UserPermissionContext;

/**
 * Interface defining permission checks for user authentication actions.
 *
 * <p>This interface provides methods to determine if a user is permitted to perform specific
 * authentication actions based on their context and journey type.
 */
public interface PermissionDecisions {
    /**
     * Checks if a user is permitted to submit an email address.
     *
     * @param journeyType The type of authentication journey
     * @param userPermissionContext The user's permission context
     * @return A Result containing either a Decision or a DecisionError
     */
    Result<DecisionError, Decision> canReceiveEmailAddress(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    /**
     * Checks if the system can send an email OTP notification to the user.
     *
     * @param journeyType The type of authentication journey
     * @param userPermissionContext The user's permission context
     * @return A Result containing either a Decision or a DecisionError
     */
    Result<DecisionError, Decision> canSendEmailOtpNotification(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    /**
     * Checks if a user is permitted to verify an email OTP.
     *
     * @param journeyType The type of authentication journey
     * @param userPermissionContext The user's permission context
     * @return A Result containing either a Decision or a DecisionError
     */
    Result<DecisionError, Decision> canVerifyEmailOtp(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    /**
     * Checks if a user is permitted to submit a password.
     *
     * @param journeyType The type of authentication journey
     * @param userPermissionContext The user's permission context
     * @return A Result containing either a Decision or a DecisionError
     */
    Result<DecisionError, Decision> canReceivePassword(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    /**
     * Checks if the system can send an SMS OTP notification to the user.
     *
     * @param journeyType The type of authentication journey
     * @param userPermissionContext The user's permission context
     * @return A Result containing either a Decision or a DecisionError
     */
    Result<DecisionError, Decision> canSendSmsOtpNotification(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    @Experimental()
    Result<DecisionError, Decision> canVerifyMfaOtp(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    /**
     * Checks if a user is permitted to verify an SMS OTP.
     *
     * @param journeyType The type of authentication journey
     * @param userPermissionContext The user's permission context
     * @return A Result containing either a Decision or a DecisionError
     */
    Result<DecisionError, Decision> canVerifySmsOtp(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    /**
     * Checks if a user is permitted to verify an authenticator app OTP.
     *
     * @param journeyType The type of authentication journey
     * @param userPermissionContext The user's permission context
     * @return A Result containing either a Decision or a DecisionError
     */
    Result<DecisionError, Decision> canVerifyAuthAppOtp(
            JourneyType journeyType, UserPermissionContext userPermissionContext);

    /**
     * Checks if a user is permitted to login.
     *
     * <p>This is an experimental method that could replace canReceivePassword.
     *
     * @param journeyType The type of authentication journey
     * @param userPermissionContext The user's permission context
     * @return A Result containing either a Decision or a DecisionError
     */
    @Experimental("Could be an alternative to canReceivePassword")
    default Result<DecisionError, Decision> canLogin(
            JourneyType journeyType, UserPermissionContext userPermissionContext) {
        return canReceiveEmailAddress(journeyType, userPermissionContext);
    }

    /**
     * Checks if a user is permitted to start an authentication journey.
     *
     * @param journeyType The type of authentication journey
     * @param userPermissionContext The user's permission context
     * @return A Result containing either a Decision or a DecisionError
     */
    Result<DecisionError, Decision> canStartJourney(
            JourneyType journeyType, UserPermissionContext userPermissionContext);
}

package uk.gov.di.authentication.shared.services.policymanager;

import uk.gov.di.authentication.shared.entity.JourneyType;

public interface AuthenticationSecurityPolicyManager {

    // Delegation  methods to AuthenticationAttemptsService

    // MFA
    boolean isMfaVerificationLocked(String subjectId, JourneyType journeyType, String activeMfaMethodId);
    boolean isMfaCodeResendLocked(String subjectId, JourneyType journeyType, String activeMfaMethodId);
    boolean isEmailVerificationLocked(String subjectId, JourneyType journeyType);
    boolean isEmailCodeResendLocked(String subjectId, JourneyType journeyType);

    void incrementAttemptCount(String subjectId, JourneyType journeyType, String countType);

    void resetAttempts(String subjectId);

    // Delegation methods to RedisConnectionService

    // Auth Session table
//    public void updateSession(AuthSessionItem sessionItem) {
//        authSessionService.updateSession(
//                authSessionItem.incrementCodeRequestCount(
//                        request.getNotificationType(), request.getJourneyType()));
//    }



    // Future extensions?
    int getCount(String subjectId, JourneyType journeyType, String countType);

    boolean isAccountUnderIntervention(String subjectId);
    boolean isEmailBlockedByFraud(String subjectId);


}

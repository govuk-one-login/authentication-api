package uk.gov.di.authentication.shared.services;

import uk.gov.di.authentication.shared.entity.JourneyType;

public interface AuthenticationSecurityPolicyManager {

    boolean isMfaVerificationLocked(String subjectId, JourneyType journeyType, String activeMfaMethodId);
    boolean isMfaCodeResendLocked(String subjectId, JourneyType journeyType, String activeMfaMethodId);
    boolean isEmailVerificationLocked(String subjectId, JourneyType journeyType);
    boolean isEmailCodeResendLocked(String subjectId, JourneyType journeyType);

    void incrementAttemptCount(String subjectId, JourneyType journeyType, String countType);

    int getCount(String subjectId, JourneyType journeyType, String countType);

    void resetAttempts(String subjectId);

    // Future extensions?

    boolean isAccountUnderIntervention(String subjectId);
    boolean isEmailBlockedByFraud(String subjectId);


}

package uk.gov.di.authentication.shared.entity;

import java.util.HashMap;
import java.util.Map;

public enum CodeRequestType {
    EMAIL_REGISTRATION(NotificationType.VERIFY_EMAIL, JourneyType.REGISTRATION),
    EMAIL_ACCOUNT_RECOVERY(
            NotificationType.VERIFY_CHANGE_HOW_GET_SECURITY_CODES, JourneyType.ACCOUNT_RECOVERY),
    SMS_ACCOUNT_RECOVERY(NotificationType.VERIFY_PHONE_NUMBER, JourneyType.ACCOUNT_RECOVERY),
    SMS_REGISTRATION(NotificationType.VERIFY_PHONE_NUMBER, JourneyType.REGISTRATION),
    SMS_SIGN_IN(NotificationType.MFA_SMS, JourneyType.SIGN_IN);

    private static final Map<CodeRequestTypeKey, CodeRequestType> codeRequestTypeMap =
            new HashMap<>();

    static {
        for (CodeRequestType codeRequestType : CodeRequestType.values()) {
            CodeRequestTypeKey key =
                    new CodeRequestTypeKey(
                            codeRequestType.getNotificationType(),
                            codeRequestType.getJourneyType());
            codeRequestTypeMap.put(key, codeRequestType);
        }
    }

    private final NotificationType notificationType;
    private final JourneyType journeyType;

    CodeRequestType(NotificationType notificationType, JourneyType journeyType) {
        this.notificationType = notificationType;
        this.journeyType = journeyType;
    }

    public static CodeRequestType getCodeRequestType(
            NotificationType notificationType, JourneyType journeyType) {
        CodeRequestTypeKey key = new CodeRequestTypeKey(notificationType, journeyType);
        return codeRequestTypeMap.get(key);
    }

    private NotificationType getNotificationType() {
        return notificationType;
    }

    private JourneyType getJourneyType() {
        return journeyType;
    }

    private static class CodeRequestTypeKey {
        private final NotificationType notificationType;
        private final JourneyType journeyType;

        CodeRequestTypeKey(NotificationType notificationType, JourneyType journeyType) {
            this.notificationType = notificationType;
            this.journeyType = journeyType;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null || getClass() != obj.getClass()) {
                return false;
            }
            CodeRequestTypeKey other = (CodeRequestTypeKey) obj;
            return notificationType == other.notificationType && journeyType == other.journeyType;
        }

        @Override
        public int hashCode() {
            return 31 * notificationType.hashCode() + journeyType.hashCode();
        }
    }
}

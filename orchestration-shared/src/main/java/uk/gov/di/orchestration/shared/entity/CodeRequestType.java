package uk.gov.di.orchestration.shared.entity;

import java.util.HashMap;
import java.util.Map;

public enum CodeRequestType {
    EMAIL_REGISTRATION(MFAMethodType.EMAIL, JourneyType.REGISTRATION),
    EMAIL_ACCOUNT_RECOVERY(MFAMethodType.EMAIL, JourneyType.ACCOUNT_RECOVERY),
    EMAIL_PASSWORD_RESET(MFAMethodType.EMAIL, JourneyType.PASSWORD_RESET),
    SMS_ACCOUNT_RECOVERY(MFAMethodType.SMS, JourneyType.ACCOUNT_RECOVERY),
    SMS_REGISTRATION(MFAMethodType.SMS, JourneyType.REGISTRATION),
    SMS_SIGN_IN(MFAMethodType.SMS, JourneyType.SIGN_IN),
    AUTH_APP_ACCOUNT_RECOVERY(MFAMethodType.AUTH_APP, JourneyType.ACCOUNT_RECOVERY),
    AUTH_APP_SIGN_IN(MFAMethodType.AUTH_APP, JourneyType.SIGN_IN),
    AUTH_APP_REGISTRATION(MFAMethodType.AUTH_APP, JourneyType.REGISTRATION);

    private static final Map<CodeRequestTypeKey, CodeRequestType> codeRequestTypeMap =
            new HashMap<>();

    static {
        for (CodeRequestType codeRequestType : CodeRequestType.values()) {
            CodeRequestTypeKey key =
                    new CodeRequestTypeKey(
                            codeRequestType.getMfaMethodType(), codeRequestType.getJourneyType());
            codeRequestTypeMap.put(key, codeRequestType);
        }
    }

    private final MFAMethodType mfaMethodType;
    private final JourneyType journeyType;

    CodeRequestType(MFAMethodType mfaMethodType, JourneyType journeyType) {
        this.mfaMethodType = mfaMethodType;
        this.journeyType = journeyType;
    }

    public static CodeRequestType getCodeRequestType(
            NotificationType notificationType, JourneyType journeyType) {
        return getCodeRequestType(notificationType.getMfaMethodType(), journeyType);
    }

    public static CodeRequestType getCodeRequestType(
            MFAMethodType mfaMethodType, JourneyType journeyType) {
        CodeRequestTypeKey key = new CodeRequestTypeKey(mfaMethodType, journeyType);
        return codeRequestTypeMap.get(key);
    }

    public MFAMethodType getMfaMethodType() {
        return mfaMethodType;
    }

    private JourneyType getJourneyType() {
        return journeyType;
    }

    private static class CodeRequestTypeKey {
        private final MFAMethodType mfaMethodType;
        private final JourneyType journeyType;

        CodeRequestTypeKey(MFAMethodType mfaMethodType, JourneyType journeyType) {
            this.mfaMethodType = mfaMethodType;
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
            return mfaMethodType == other.mfaMethodType && journeyType == other.journeyType;
        }

        @Override
        public int hashCode() {
            return 31 * mfaMethodType.hashCode() + journeyType.hashCode();
        }
    }
}

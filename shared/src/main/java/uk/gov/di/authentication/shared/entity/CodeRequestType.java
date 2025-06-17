package uk.gov.di.authentication.shared.entity;

import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.exceptions.CodeRequestTypeNotFoundException;

import java.util.HashMap;
import java.util.Map;

public enum CodeRequestType {
    EMAIL_REGISTRATION(MFAMethodType.EMAIL, JourneyType.REGISTRATION),
    EMAIL_ACCOUNT_RECOVERY(MFAMethodType.EMAIL, JourneyType.ACCOUNT_RECOVERY),
    EMAIL_PASSWORD_RESET(MFAMethodType.EMAIL, JourneyType.PASSWORD_RESET),
    SMS_ACCOUNT_RECOVERY(MFAMethodType.SMS, JourneyType.ACCOUNT_RECOVERY),
    PW_RESET_MFA_SMS(MFAMethodType.SMS, JourneyType.PASSWORD_RESET_MFA),
    SMS_REGISTRATION(MFAMethodType.SMS, JourneyType.REGISTRATION),
    SMS_SIGN_IN(MFAMethodType.SMS, JourneyType.SIGN_IN),
    AUTH_APP_ACCOUNT_RECOVERY(MFAMethodType.AUTH_APP, JourneyType.ACCOUNT_RECOVERY),
    AUTH_APP_SIGN_IN(MFAMethodType.AUTH_APP, JourneyType.SIGN_IN),
    PW_RESET_MFA_AUTH_APP(MFAMethodType.AUTH_APP, JourneyType.PASSWORD_RESET_MFA),
    AUTH_APP_REGISTRATION(MFAMethodType.AUTH_APP, JourneyType.REGISTRATION),
    SMS_REAUTHENTICATION(MFAMethodType.SMS, JourneyType.REAUTHENTICATION),
    AUTH_APP_REAUTHENTICATION(MFAMethodType.AUTH_APP, JourneyType.REAUTHENTICATION);

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

    public static boolean isValidCodeRequestType(
            MFAMethodType mfaMethodType, JourneyType journeyType) {
        CodeRequestTypeKey key = new CodeRequestTypeKey(mfaMethodType, journeyType);
        return codeRequestTypeMap.containsKey(key);
    }

    public static CodeRequestType getCodeRequestType(
            NotificationType notificationType, JourneyType journeyType) {
        return getCodeRequestType(notificationType.getMfaMethodType(), journeyType);
    }

    public static CodeRequestType getCodeRequestType(
            MFAMethodType mfaMethodType, JourneyType journeyType) {
        if (!isValidCodeRequestType(mfaMethodType, journeyType)) {
            throw new CodeRequestTypeNotFoundException(
                    String.format(
                            "CodeRequestType not found for MFA Type and Journey Type: [%s , %s]",
                            mfaMethodType.getValue(), journeyType.getValue()));
        }

        CodeRequestTypeKey key = new CodeRequestTypeKey(mfaMethodType, journeyType);
        return codeRequestTypeMap.get(key);
    }

    public MFAMethodType getMfaMethodType() {
        return mfaMethodType;
    }

    public JourneyType getJourneyType() {
        return journeyType;
    }

    private record CodeRequestTypeKey(MFAMethodType mfaMethodType, JourneyType journeyType) {

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

    }
}

package uk.gov.di.authentication.shared.entity;

import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.exceptions.CodeRequestTypeNotFoundException;

import java.util.HashMap;
import java.util.Map;

public enum CodeRequestType {
    EMAIL_REGISTRATION(SupportedCodeType.EMAIL, JourneyType.REGISTRATION),
    EMAIL_ACCOUNT_RECOVERY(SupportedCodeType.EMAIL, JourneyType.ACCOUNT_RECOVERY),
    EMAIL_PASSWORD_RESET(SupportedCodeType.EMAIL, JourneyType.PASSWORD_RESET),
    MFA_ACCOUNT_RECOVERY(SupportedCodeType.MFA, JourneyType.ACCOUNT_RECOVERY),
    MFA_PW_RESET_MFA(SupportedCodeType.MFA, JourneyType.PASSWORD_RESET_MFA),
    MFA_REGISTRATION(SupportedCodeType.MFA, JourneyType.REGISTRATION),
    MFA_SIGN_IN(SupportedCodeType.MFA, JourneyType.SIGN_IN),
    MFA_REAUTHENTICATION(SupportedCodeType.MFA, JourneyType.REAUTHENTICATION);

    private static final Map<CodeRequestTypeKey, CodeRequestType> codeRequestTypeMap =
            new HashMap<>();

    static {
        for (CodeRequestType codeRequestType : CodeRequestType.values()) {
            CodeRequestTypeKey key =
                    new CodeRequestTypeKey(
                            codeRequestType.getSupportedCodeType(),
                            codeRequestType.getJourneyType());
            codeRequestTypeMap.put(key, codeRequestType);
        }
    }

    private final SupportedCodeType supportedCodeType;
    private final JourneyType journeyType;

    CodeRequestType(SupportedCodeType codeType, JourneyType journeyType) {
        this.supportedCodeType = codeType;
        this.journeyType = journeyType;
    }

    public static boolean isValidCodeRequestType(
            MFAMethodType mfaMethodType, JourneyType journeyType) {
        SupportedCodeType supportedCodeType = SupportedCodeType.getFromMfaMethodType(mfaMethodType);
        CodeRequestTypeKey key = new CodeRequestTypeKey(supportedCodeType, journeyType);
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

        SupportedCodeType supportedCodeType = SupportedCodeType.getFromMfaMethodType(mfaMethodType);

        CodeRequestTypeKey key = new CodeRequestTypeKey(supportedCodeType, journeyType);
        return codeRequestTypeMap.get(key);
    }

    // TODO remove temporary ZDD measure to reference existing deprecated keys when expired
    public static String getDeprecatedCodeRequestTypeString(
            MFAMethodType mfaMethodType, JourneyType journeyType) {
        if (!isValidCodeRequestType(mfaMethodType, journeyType)) return null;
        if (!mfaMethodType.equals(MFAMethodType.SMS)
                && !mfaMethodType.equals(MFAMethodType.AUTH_APP)) return null;

        if (journeyType.equals(JourneyType.PASSWORD_RESET_MFA)) {
            return String.format("PW_RESET_MFA_%s", mfaMethodType);
        } else {
            return String.format("%s_%s", mfaMethodType, journeyType);
        }
    }

    public SupportedCodeType getSupportedCodeType() {
        return supportedCodeType;
    }

    public JourneyType getJourneyType() {
        return journeyType;
    }

    private static class CodeRequestTypeKey {
        private final SupportedCodeType supportedCodeType;
        private final JourneyType journeyType;

        CodeRequestTypeKey(SupportedCodeType supportedCodeType, JourneyType journeyType) {
            this.supportedCodeType = supportedCodeType;
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
            return supportedCodeType == other.supportedCodeType && journeyType == other.journeyType;
        }

        @Override
        public int hashCode() {
            return 31 * supportedCodeType.hashCode() + journeyType.hashCode();
        }
    }

    public enum SupportedCodeType {
        EMAIL("EMAIL"),
        MFA("MFA");

        private final String value;

        SupportedCodeType(String value) {
            this.value = value;
        }

        public static SupportedCodeType getFromMfaMethodType(MFAMethodType mfaMethodType) {
            if (mfaMethodType.equals(MFAMethodType.EMAIL)) return SupportedCodeType.EMAIL;
            if (mfaMethodType.equals(MFAMethodType.SMS)) return SupportedCodeType.MFA;
            if (mfaMethodType.equals(MFAMethodType.AUTH_APP)) return SupportedCodeType.MFA;

            throw new IllegalArgumentException(
                    String.format(
                            "Unsupported MFAMethodType provided: %s", mfaMethodType.getValue()));
        }

        public String getValue() {
            return value;
        }
    }
}

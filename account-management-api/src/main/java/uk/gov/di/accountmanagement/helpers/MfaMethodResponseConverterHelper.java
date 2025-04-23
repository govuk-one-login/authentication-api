package uk.gov.di.accountmanagement.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.response.MfaMethodResponse;
import uk.gov.di.authentication.shared.services.mfa.MfaRetrieveFailureReason;

import java.util.List;

public class MfaMethodResponseConverterHelper {
    private static final Logger LOG = LogManager.getLogger(MfaMethodResponseConverterHelper.class);

    private MfaMethodResponseConverterHelper() {
        throw new IllegalStateException("Utility class");
    }

    public static Result<MfaRetrieveFailureReason, List<MfaMethodResponse>>
            convertMfaMethodsToMfaMethodResponse(List<MFAMethod> mfaMethods) {
        List<Result<MfaRetrieveFailureReason, MfaMethodResponse>> mfaMethodDataResults =
                mfaMethods.stream()
                        .map(
                                mfaMethod -> {
                                    var mfaMethodData = MfaMethodResponse.from(mfaMethod);
                                    if (mfaMethodData.isFailure()) {
                                        LOG.error(
                                                "Error converting mfa method with type {} to mfa method data: {}",
                                                mfaMethod.getMfaMethodType(),
                                                mfaMethodData.getFailure());
                                        return Result
                                                .<MfaRetrieveFailureReason, MfaMethodResponse>
                                                        failure(
                                                                MfaRetrieveFailureReason
                                                                        .ERROR_CONVERTING_MFA_METHOD_TO_MFA_METHOD_DATA);
                                    } else {
                                        return Result
                                                .<MfaRetrieveFailureReason, MfaMethodResponse>
                                                        success(mfaMethodData.getSuccess());
                                    }
                                })
                        .toList();
        return Result.sequenceSuccess(mfaMethodDataResults);
    }
}

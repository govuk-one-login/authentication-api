package uk.gov.di.authentication.shared.interceptors;

import software.amazon.awssdk.core.interceptor.Context;
import software.amazon.awssdk.core.interceptor.ExecutionAttributes;
import software.amazon.awssdk.core.interceptor.ExecutionInterceptor;
import software.amazon.awssdk.core.interceptor.SdkExecutionAttribute;
import software.amazon.awssdk.services.kms.model.SignRequest;

import java.util.HashSet;

public class KmsAccessInterceptor implements ExecutionInterceptor {
    private HashSet<String> signingKeysUsed = new HashSet<>();

    public boolean wasKeyUsedToSign(String keyId) {
        return signingKeysUsed.contains(keyId);
    }

    @Override
    public void beforeExecution(
            Context.BeforeExecution context, ExecutionAttributes executionAttributes) {
        String operation = executionAttributes.getAttribute(SdkExecutionAttribute.OPERATION_NAME);
        if (operation != null && (operation.equals("Sign"))) {
            SignRequest signRequest = (SignRequest) context.request();
            signingKeysUsed.add(signRequest.keyId());
        }
    }
}

package uk.gov.di.authentication.shared.interceptors;

import software.amazon.awssdk.core.interceptor.Context;
import software.amazon.awssdk.core.interceptor.ExecutionAttributes;
import software.amazon.awssdk.core.interceptor.ExecutionInterceptor;
import software.amazon.awssdk.core.interceptor.SdkExecutionAttribute;
import software.amazon.awssdk.services.kms.model.SignRequest;

public class KmsAccessInterceptor implements ExecutionInterceptor {
    public String getAccessedKeyId() {
        return accessedKeyId;
    }

    private String accessedKeyId = "";

    @Override
    public void beforeExecution(
            Context.BeforeExecution context, ExecutionAttributes executionAttributes) {
        String operation = executionAttributes.getAttribute(SdkExecutionAttribute.OPERATION_NAME);
        if (operation != null && (operation.equals("Sign"))) {
            SignRequest encryptRequest = (SignRequest) context.request();
            accessedKeyId = encryptRequest.keyId();
        }
    }
}

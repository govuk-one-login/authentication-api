package uk.gov.di.authentication.frontendapi.entity;

import uk.gov.di.authentication.shared.entity.BaseFrontendRequest;

public class CheckEmailFraudBlockRequest extends BaseFrontendRequest {

    public CheckEmailFraudBlockRequest(String email) {
        this.email = email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}

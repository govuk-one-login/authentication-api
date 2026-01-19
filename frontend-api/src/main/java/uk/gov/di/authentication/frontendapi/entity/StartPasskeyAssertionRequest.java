package uk.gov.di.authentication.frontendapi.entity;

import uk.gov.di.authentication.shared.entity.BaseFrontendRequest;

public class StartPasskeyAssertionRequest extends BaseFrontendRequest {

    public StartPasskeyAssertionRequest() {}

    public StartPasskeyAssertionRequest(String email) {
        this.email = email;
    }
}

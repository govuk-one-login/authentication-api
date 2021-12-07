package uk.gov.di.authentication.frontendapi.entity;

import uk.gov.di.authentication.shared.entity.BaseFrontendRequest;

public class CheckUserExistsRequest extends BaseFrontendRequest {

    public CheckUserExistsRequest() {}

    public CheckUserExistsRequest(String email) {
        this.email = email;
    }

    @Override
    public String toString() {
        return "CheckUserExistsRequest{" + "email='" + email + '\'' + '}';
    }
}

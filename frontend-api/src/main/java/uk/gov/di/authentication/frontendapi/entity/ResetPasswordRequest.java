package uk.gov.di.authentication.frontendapi.entity;

public class ResetPasswordRequest extends BaseFrontendRequest {

    public ResetPasswordRequest() {}

    public ResetPasswordRequest(String email) {
        this.email = email;
    }

    @Override
    public String toString() {
        return "ResetPasswordRequest{" + "email='" + email + '\'' + '}';
    }
}

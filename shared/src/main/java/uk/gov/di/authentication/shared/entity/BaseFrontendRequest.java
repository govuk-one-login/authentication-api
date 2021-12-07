package uk.gov.di.authentication.shared.entity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import jakarta.validation.constraints.NotNull;
import uk.gov.di.authentication.shared.serialization.EmailDeserializer;

@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class BaseFrontendRequest {
    @NotNull
    @JsonProperty("email")
    @JsonDeserialize(using = EmailDeserializer.class)
    protected String email;

    public String getEmail() {
        return email;
    }
}

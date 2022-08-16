package uk.gov.di.authentication.shared.entity;

public interface TemplateAware {
    String getTemplateId();

    String getTemplateId(String language);
}

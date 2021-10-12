package uk.gov.di.authentication.accountmigration;

import com.opencsv.bean.CsvBindByName;
import com.opencsv.bean.CsvCustomBindByName;

import java.time.LocalDateTime;

public class ImportRecord {

    @CsvBindByName(column = "email")
    private String email;

    @CsvBindByName(column = "encrypted_password")
    private String encryptedPassword;

    @CsvBindByName(column = "subject_identifier")
    private String subjectIdentifier;

    @CsvBindByName(column = "phone")
    private String phone;

    @CsvCustomBindByName(column = "created_at", converter = LocalDateConverter.class)
    private LocalDateTime createdAt;

    public String getEmail() {
        return email;
    }

    public String getEncryptedPassword() {
        return encryptedPassword;
    }

    public String getSubjectIdentifier() {
        return subjectIdentifier;
    }

    public String getPhone() {
        return phone;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public ImportRecord setEmail(String email) {
        this.email = email;
        return this;
    }

    public ImportRecord setEncryptedPassword(String encryptedPassword) {
        this.encryptedPassword = encryptedPassword;
        return this;
    }

    public ImportRecord setSubjectIdentifier(String subjectIdentifier) {
        this.subjectIdentifier = subjectIdentifier;
        return this;
    }

    public ImportRecord setPhone(String phone) {
        this.phone = phone;
        return this;
    }

    public ImportRecord setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
        return this;
    }
}

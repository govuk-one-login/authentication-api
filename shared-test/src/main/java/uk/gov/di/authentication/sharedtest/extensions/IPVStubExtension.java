package uk.gov.di.authentication.sharedtest.extensions;

import uk.gov.di.authentication.sharedtest.httpstub.HttpStubExtension;

import static java.lang.String.format;

public class IPVStubExtension extends HttpStubExtension {

    public IPVStubExtension(int port) {
        super(port);
    }

    public IPVStubExtension() {
        super();
    }

    public void init() {
        register(
                "/token",
                200,
                "application/json",
                format(
                        "{"
                                + "  \"access_token\": \"740e5834-3a29-46b4-9a6f-16142fde533a\","
                                + "  \"token_type\": \"bearer\","
                                + "  \"expires_in\": \"3600\","
                                + "  \"uri\": \"http://localhost:%1$d\""
                                + "}",
                        getHttpPort()));

        register(
                "/user-identity",
                200,
                "application/json",
                "{"
                        + "  \"sub\": \"urn:fdc:gov.uk:2022:740e5834-3a29-46b4-9a6f-16142fde533a\","
                        + "  \"vot\": \"P2\","
                        + "  \"vtm\": \"http://localhost/trustmark\","
                        + "  \"https://vocab.account.gov.uk/v1/credentialJWT\": [\"eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczpcL1wvaW50ZWdyYXRpb24tZGktaXB2LWNyaS1hZGRyZXNzLWZyb250LmxvbmRvbi5jbG91ZGFwcHMuZGlnaXRhbCIsInN1YiI6InVybjpmZGM6Z292LnVrOjIwMjI6XzM5VVBHaU1KakVWUG9faEZVcGRqNmRuUVdaM2RLRHZZeVM4TVl6XzIzQSIsIm5iZiI6MTY1NDg2NzE2MSwiZXhwIjoxNjU0ODY5ODYxLCJ2YyI6eyJjcmVkZW50aWFsU3ViamVjdCI6eyJhZGRyZXNzIjpbeyJ1cHJuIjpudWxsLCJidWlsZGluZ051bWJlciI6IjgiLCJidWlsZGluZ05hbWUiOiIiLCJzdHJlZXROYW1lIjoiSEFETEVZIFJPQUQiLCJhZGRyZXNzTG9jYWxpdHkiOiJCQVRIIiwicG9zdGFsQ29kZSI6IkJBMiA1QUEiLCJhZGRyZXNzQ291bnRyeSI6IkdCIiwidmFsaWRGcm9tIjoiMjAwMC0wMS0wMSJ9XX0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJBZGRyZXNzQ3JlZGVudGlhbCJdLCJAY29udGV4dCI6WyJodHRwczpcL1wvd3d3LnczLm9yZ1wvMjAxOFwvY3JlZGVudGlhbHNcL3YxIiwiaHR0cHM6XC9cL3ZvY2FiLmxvbmRvbi5jbG91ZGFwcHMuZGlnaXRhbFwvY29udGV4dHNcL2lkZW50aXR5LXYxLmpzb25sZCJdfX0.MEUCIEjlQYJ_Tp5sH_twF6FNhByRqyEq_6VOUWV8DpLoYs2FAiEA-om1BW1HXy2y-elaK98N109FVDxHSVmz-WyLfU1Laq8\",\"eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczpcL1wvaW50ZWdyYXRpb24tZGktaXB2LWNyaS1mcmF1ZC1mcm9udC5sb25kb24uY2xvdWRhcHBzLmRpZ2l0YWwiLCJzdWIiOiJ1cm46ZmRjOmdvdi51azoyMDIyOl8zOVVQR2lNSmpFVlBvX2hGVXBkajZkblFXWjNkS0R2WXlTOE1Zel8yM0EiLCJuYmYiOjE2NTQ4NjcxODQsImV4cCI6MTY1NDg2OTg4NCwidmMiOnsiY3JlZGVudGlhbFN1YmplY3QiOnsiYmlydGhEYXRlIjpbeyJ2YWx1ZSI6IjE5NjQtMTEtMDcifV0sImFkZHJlc3MiOlt7ImJ1aWxkaW5nTmFtZSI6IiIsInN0cmVldE5hbWUiOiJIQURMRVkgUk9BRCIsInBvQm94TnVtYmVyIjpudWxsLCJhZGRyZXNzVHlwZSI6IkNVUlJFTlQiLCJwb3N0YWxDb2RlIjoiQkEyIDVBQSIsImJ1aWxkaW5nTnVtYmVyIjoiOCIsImlkIjpudWxsLCJhZGRyZXNzTG9jYWxpdHkiOiJCQVRIIiwic3ViQnVpbGRpbmdOYW1lIjpudWxsfV0sIm5hbWUiOlt7Im5hbWVQYXJ0cyI6W3sidHlwZSI6IkdpdmVuTmFtZSIsInZhbHVlIjoia2VubmV0aCJ9LHsidHlwZSI6IkZhbWlseU5hbWUiLCJ2YWx1ZSI6ImRlY2VycXVlaXJhIn1dfV19LCJldmlkZW5jZSI6W3sidHhuIjoiUkIwMDAwOTk3MDI2MTYiLCJ0eXBlIjoiSWRlbnRpdHlDaGVjayIsImlkZW50aXR5RnJhdWRTY29yZSI6MSwiY2kiOltdfV0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJJZGVudGl0eUNoZWNrQ3JlZGVudGlhbCJdfX0.MEYCIQD5ClbV90UKbTBle9UzWvgq1SdiwKlw1-K2W03pMgv5iwIhAK0sr2ebq8Bac0vGARafUZrhy2RraWf53MP0pmAy-_g2\",\"eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczpcL1wvaW50ZWdyYXRpb24tZGktaXB2LWNyaS1rYnYtZnJvbnQubG9uZG9uLmNsb3VkYXBwcy5kaWdpdGFsIiwic3ViIjoidXJuOmZkYzpnb3YudWs6MjAyMjpfMzlVUEdpTUpqRVZQb19oRlVwZGo2ZG5RV1ozZEtEdll5UzhNWXpfMjNBIiwibmJmIjoxNjU0ODY3MzUwLCJleHAiOjE2NTQ4NzAwNTAsInZjIjp7ImV2aWRlbmNlIjpbeyJ0eG4iOiI3SkFRSjRGQzRHIiwidmVyaWZpY2F0aW9uU2NvcmUiOjIsInR5cGUiOiJJZGVudGl0eUNoZWNrIn1dLCJjcmVkZW50aWFsU3ViamVjdCI6eyJuYW1lIjpbeyJuYW1lUGFydHMiOlt7InR5cGUiOiJHaXZlbk5hbWUiLCJ2YWx1ZSI6Imtlbm5ldGgifSx7InR5cGUiOiJGYW1pbHlOYW1lIiwidmFsdWUiOiJkZWNlcnF1ZWlyYSJ9XX1dLCJhZGRyZXNzIjpbeyJhZGRyZXNzQ291bnRyeSI6IkdCIiwidXBybiI6bnVsbCwiYnVpbGRpbmdOYW1lIjoiIiwic3RyZWV0TmFtZSI6IkhBRExFWSBST0FEIiwicG9zdGFsQ29kZSI6IkJBMiA1QUEiLCJidWlsZGluZ051bWJlciI6IjgiLCJhZGRyZXNzTG9jYWxpdHkiOiJCQVRIIiwidmFsaWRGcm9tIjoiMjAwMC0wMS0wMSJ9LHsidXBybiI6bnVsbCwiYnVpbGRpbmdOYW1lIjoiIiwic3RyZWV0TmFtZSI6IkhBRExFWSBST0FEIiwicG9zdGFsQ29kZSI6IkJBMiA1QUEiLCJidWlsZGluZ051bWJlciI6IjgiLCJhZGRyZXNzTG9jYWxpdHkiOiJCQVRIIn1dLCJiaXJ0aERhdGUiOlt7InZhbHVlIjoiMTk2NC0xMS0wNyJ9XX0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJJZGVudGl0eUNoZWNrQ3JlZGVudGlhbCJdfX0.MEQCICA_FEuk_sVCfqQLS2FKnxCEkaH8KOtKE1RbqwzrMKPQAiBKy2V_u0ZQ5O1fwaww6WTZhZUk2k0f5abLDB48ViwjKg\",\"eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1cm46ZmRjOmdvdi51azoyMDIyOl8zOVVQR2lNSmpFVlBvX2hGVXBkajZkblFXWjNkS0R2WXlTOE1Zel8yM0EiLCJhdWQiOiJodHRwczpcL1wvaWRlbnRpdHkuaW50ZWdyYXRpb24uYWNjb3VudC5nb3YudWsiLCJuYmYiOjE2NTQ4NjcwODYsImlzcyI6Imh0dHBzOlwvXC9yZXZpZXctcC5pbnRlZ3JhdGlvbi5hY2NvdW50Lmdvdi51ayIsImV4cCI6MTY1NDg2OTQ4NiwidmMiOnsiZXZpZGVuY2UiOlt7InZhbGlkaXR5U2NvcmUiOjIsInN0cmVuZ3RoU2NvcmUiOjQsImNpIjpudWxsLCJ0eG4iOiIzMjY3NzY2NC1mMGRkLTQ4YWQtYjY1NC03MzYzNGMwZTJkMmIiLCJ0eXBlIjoiSWRlbnRpdHlDaGVjayJ9XSwiY3JlZGVudGlhbFN1YmplY3QiOnsicGFzc3BvcnQiOlt7ImV4cGlyeURhdGUiOiIyMDMwLTAxLTAxIiwiZG9jdW1lbnROdW1iZXIiOiIzMjE2NTQ5ODcifV0sIm5hbWUiOlt7Im5hbWVQYXJ0cyI6W3sidHlwZSI6IkdpdmVuTmFtZSIsInZhbHVlIjoia2VubmV0aCJ9LHsidHlwZSI6IkZhbWlseU5hbWUiLCJ2YWx1ZSI6ImRlY2VycXVlaXJhIn1dfV0sImJpcnRoRGF0ZSI6W3sidmFsdWUiOiIxOTY0LTExLTA3In1dfSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIklkZW50aXR5Q2hlY2tDcmVkZW50aWFsIl19fQ.MEUCIQD3z0rGb7YPFvOKt7p-tlkarsU16lpuOzcdlyNP3WutHgIgfbP0zxvHFAS54VGbnpumfTAxvMM1dsVhfje-2xWTQ0I\"],"
                        + "  \"https://vocab.account.gov.uk/v1/coreIdentity\": {\"name\":[{\"nameParts\":[{\"type\":\"GivenName\",\"value\":\"kenneth\"},{\"type\":\"FamilyName\",\"value\":\"decerqueira\"}]}],\"birthDate\":[{\"value\":\"1964-11-07\"}]},"
                        + "  \"https://vocab.account.gov.uk/v1/address\": [{\"addressCountry\":\"GB\",\"uprn\":null,\"buildingName\":\"\",\"streetName\":\"HADLEY ROAD\",\"postalCode\":\"BA2 5AA\",\"buildingNumber\":\"8\",\"addressLocality\":\"BATH\",\"validFrom\":\"2000-01-01\"}],"
                        + "  \"https://vocab.account.gov.uk/v1/passport\": [{\"documentNumber\":\"1223456\",\"expiryDate\":\"2022-02-02\"}]"
                        + "}");
    }
}

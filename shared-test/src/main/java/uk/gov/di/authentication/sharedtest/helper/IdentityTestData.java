package uk.gov.di.authentication.sharedtest.helper;

public final class IdentityTestData {
    private IdentityTestData() {}

    public static final String ADDRESS_CLAIM =
            "[{\"buildingNumber\":\"10\",\"streetName\":\"DowningStreet\",\"dependentAddressLocality\":\"Westminster\",\"addressLocality\":\"London\",\"postalCode\":\"SW1A2AA\",\"addressCountry\":\"GB\",\"validFrom\":\"2019-07-24\"}]";

    public static final String PASSPORT_CLAIM =
            "[{\"documentNumber\":\"12345678\",\"expiryDate\":\"2022-02-01\"}]";

    public static final String CORE_IDENTITY_CLAIM =
            "{\"name\":[{\"nameParts\":[{\"type\":\"GivenName\",\"value\":\"kenneth\"},{\"type\":\"FamilyName\",\"value\":\"decerqueira\"}]}],\"birthDate\":[{\"value\":\"1964-11-07\"}]}";

    public static final String CREDENTIAL_JWT_CLAIM =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJBdWRpZW5jZSIsInN1YiI6InRlc3RDbGllbnRJZCIsIm5iZiI6MTY1MTY3MzQ3NCwic2hhcmVkX2NsYWltcyI6eyJhZGRyZXNzIjpbeyJhZGRyZXNzQ291bnRyeSI6bnVsbCwib3JnYW5pemF0aW9uTmFtZSI6bnVsbCwic3RyZWV0QWRkcmVzcyI6bnVsbCwicG9zdGFsQ29kZSI6bnVsbCwiYWRkcmVzc0xvY2FsaXR5IjpudWxsLCJ0eXBlIjpudWxsLCJhZGRyZXNzUmVnaW9uIjpudWxsfV0sIm5hbWUiOlt7Im5hbWVQYXJ0cyI6W3sidmFsaWRVbnRpbCI6bnVsbCwidmFsaWRGcm9tIjpudWxsLCJ0eXBlIjoiZmlyc3RfbmFtZSIsInZhbHVlIjoiRGFuIn1dfV0sImJpcnRoRGF0ZSI6W3sidmFsdWUiOiIyMDExLTAxLTAxIn1dfSwiaXNzIjoidGVzdENsaWVudElkIiwicmVzcG9uc2VfdHlwZSI6ImNvZGUiLCJyZWRpcmVjdF91cmkiOiJjYWxsYmFja1VyaT9pZD1jcmlfaWQiLCJzdGF0ZSI6InJlYWQiLCJleHAiOjE2NTE2NzQzNzQsImlhdCI6MTY1MTY3MzQ3NCwiY2xpZW50X2lkIjoidGVzdENsaWVudElkIn0.jfYDzFJjANSkwC7Zxd45aJBzv8dgXNRdi3oWvFUEg3aWWfXW6a-R29CDrCZZXNueoOEQFjkz88R5Az0urnohgw";
}

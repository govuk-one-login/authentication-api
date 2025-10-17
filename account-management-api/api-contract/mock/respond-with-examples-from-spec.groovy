// Script to parse the OpenAPI spec for examples and return the example that matches the request.
//
// For GET and POST requests the expectation is that there will be a path parameter called publicSubjectId
//
// Example of what the OpenAPI spec looks like when loaded into the context:
//
// context.operation.responses["200"].content["application/json"].examples["user-with-single-mfa-type-app"])

import groovy.json.JsonSlurper

def request = context.request
def method = request.method.toLowerCase()
def path = request.path

if (method == "get" || method == "post" || method == "put" || method == "delete") {
    // Handle /authenticate endpoint
    if (path == "/authenticate" && method == "post") {
        handleAuthenticate(request)
        return
    }
    
    def publicSubjectId = context.request.pathParams?.publicSubjectId

    // Skip processing if no publicSubjectId
    if (publicSubjectId == null) {
        return
    }
    def responseStatusCode
    def responseBody

    context.operation.responses.each { statusCode, response ->
        def examples = response.content.get("application/json")?.examples
        if (examples?.containsKey(publicSubjectId)) {
            responseStatusCode = statusCode
            responseBody = examples[publicSubjectId]?.value
            if (responseStatusCode == "200") {
                respond().withExampleName(publicSubjectId)
            } else {
                respond()
                        .withContent(responseBody.toString())
                        .withHeader("Content-Type", "application/json")
                        .withStatusCode(statusCode as Integer)
            }
        }
    }
}

def handleAuthenticate(request) {
    def requestBody = [:]
    try {
        if (request.body) {
            requestBody = new JsonSlurper().parseText(request.body)
        }
    } catch (Exception e) {
        // Invalid JSON, treat as empty
    }
    
    def email = requestBody?.email
    def missingEmail = !email
    
    if (missingEmail) {
        def response400 = context.operation.responses["400"]
        def example = response400.content["application/json"].examples["post-when-request-is-missing-parameters"]
        respond()
            .withContent(example.value.toString())
            .withHeader("Content-Type", "application/json")
            .withStatusCode(400)
        return
    }
    
    // 401 - Invalid credentials
    if (email == "invalid@example.gov.uk") {
        def response401 = context.operation.responses["401"]
        def example = response401.content["application/json"].examples["post-when-invalid-credentials"]
        respond()
            .withContent(example.value.toString())
            .withHeader("Content-Type", "application/json")
            .withStatusCode(401)
        return
    }
    
    // 403 - Blocked account
    if (email == "blocked@example.gov.uk") {
        def response403 = context.operation.responses["403"]
        def example = response403.content["application/json"].examples["post-when-user-has-blocked-intervention"]
        respond()
            .withContent(example.value.toString())
            .withHeader("Content-Type", "application/json")
            .withStatusCode(403)
        return
    }
    
    // 403 - Suspended account
    if (email == "suspended@example.gov.uk") {
        def response403 = context.operation.responses["403"]
        def example = response403.content["application/json"].examples["post-when-user-has-suspended-intervention"]
        respond()
            .withContent(example.value.toString())
            .withHeader("Content-Type", "application/json")
            .withStatusCode(403)
        return
    }
    
    // Default to 204 success for any other valid email
}

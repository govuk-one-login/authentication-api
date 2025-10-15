// Script to parse the OpenAPI spec for examples and return the example that matches the request.
//
// For GET and POST requests the expectation is that there will be a path parameter called publicSubjectId
//
// Example of what the OpenAPI spec looks like when loaded into the context:
//
// context.operation.responses["200"].content["application/json"].examples["user-with-single-mfa-type-app"])

def request = context.request
def method = request.method.toLowerCase()

if (method == "get" || method == "post" || method == "put" || method == "delete") {
    def publicSubjectId = context.request.pathParams?.publicSubjectId

    // Skip processing if no publicSubjectId (e.g., for /authenticate endpoint)
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

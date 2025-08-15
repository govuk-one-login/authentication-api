// Script to parse the OpenAPI spec for examples and return the example that matches the request.
//
// For endpoints with publicSubjectId path parameter, it matches examples by that parameter.
// For endpoints without publicSubjectId (like /update-email), it returns the default success response.
//
// Example of what the OpenAPI spec looks like when loaded into the context:
//
// context.operation.responses["200"].content["application/json"].examples["user-with-single-mfa-type-app"])

def request = context.request
def method = request.method.toLowerCase()
def path = request.path

if (method == "get" || method == "post" || method == "put" || method == "delete") {
    def publicSubjectId = context.request.pathParams.publicSubjectId
    
    // Handle endpoints with publicSubjectId parameter (MFA methods)
    if (publicSubjectId != null) {
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
    // Handle endpoints without publicSubjectId parameter (like /update-email)
    else {
        // For endpoints without path parameters, return the default success response
        // This allows the REST plugin to handle specific error cases via path matching
        if (path == "/update-email") {
            // Return 204 No Content for successful email update
            respond().withStatusCode(204)
        } else {
            // For other endpoints without publicSubjectId, try to find a default success response
            def successResponse = context.operation.responses["200"] ?: context.operation.responses["204"]
            if (successResponse) {
                def statusCode = context.operation.responses["200"] ? 200 : 204
                respond().withStatusCode(statusCode)
            }
        }
    }
}

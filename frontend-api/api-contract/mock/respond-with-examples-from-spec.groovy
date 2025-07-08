// Script to parse the OpenAPI spec for examples and return the example that matches the request.
//
// For endpoints with path parameters, the parameter value is used to select the example
// For endpoints without path parameters, the request body or query parameters can be used

def request = context.request
def method = request.method.toLowerCase()

if (method == "get" || method == "post" || method == "put" || method == "delete") {
    // For endpoints with path parameters
    if (context.request.pathParams) {
        def pathParam = context.request.pathParams.values().first()
        def responseStatusCode
        def responseBody

        context.operation.responses.each { statusCode, response ->
            def examples = response.content.get("application/json")?.examples
            if (examples?.containsKey(pathParam)) {
                responseStatusCode = statusCode
                responseBody = examples[pathParam]?.value
                if (responseStatusCode == "200") {
                    respond().withExampleName(pathParam)
                } else {
                    respond()
                            .withContent(responseBody.toString())
                            .withHeader("Content-Type", "application/json")
                            .withStatusCode(statusCode as Integer)
                }
            }
        }
    } 
    // For endpoints without path parameters, use default examples
    else {
        // Default to success example if available
        if (context.operation.responses["200"]?.content?.get("application/json")?.examples?.containsKey("success")) {
            respond().withExampleName("success")
        }
    }
}
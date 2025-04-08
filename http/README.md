# HTTP

## Client Registry API HTTP requests

The Client Registry API can be tested using the files in this folder. Duplicate the
`http-client.private.env.json.template` file and remove the `.template`. Set `sandpit-api-key` with the API key for the
sandpit client registry API that can be found in AWS, in the account sandpit deploys into.

The templates contain necessary fields, but if you want to test a new field add that to the JSON.

The public key and client id, if necessary, are also be set in `http-client.private.env.json`.

Run the HTTP requests by selecting `sandpit` in the `Run with` dropdown at the top of the file.

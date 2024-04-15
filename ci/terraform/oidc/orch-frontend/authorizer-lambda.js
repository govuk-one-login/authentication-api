'use strict';

const ip4ToInt = ip =>
    ip.split('.').reduce((int, oct) => (int << 8) + parseInt(oct, 10), 0) >>> 0;

const isIp4InCidr = ip => cidr => {
    const [range, bits = 32] = cidr.split('/');
    const mask = ~(2 ** (32 - bits) - 1);
    return mask === 0
        ? ip4ToInt(ip) === ip4ToInt(range)
        : (ip4ToInt(ip) & mask) === (ip4ToInt(range) & mask);
};

const isIp4InCidrs = (ip, cidrs) => cidrs.some(isIp4InCidr(ip));

var generatePolicy = function(principalId, effect, resource) {
    var authResponse = {};
    authResponse.principalId = principalId;
    if (effect && resource) {
        var policyDocument = {};
        policyDocument.Version = '2012-10-17';
        policyDocument.Statement = [];
        var statementOne = {};
        statementOne.Action = 'execute-api:Invoke';
        statementOne.Effect = effect;
        statementOne.Resource = resource;
        policyDocument.Statement[0] = statementOne;
        authResponse.policyDocument = policyDocument;
    }
    return authResponse;
}

var generateAllow = function(principalId, resource) {
    return generatePolicy(principalId, 'Allow', resource);
}

var generateDeny = function(principalId, resource) {
    return generatePolicy(principalId, 'Deny', resource);
}

exports.handler = (event, context, callback) => {
    console.log('Received event to orch frontend authorizer lambda: ', JSON.stringify(event, null, 2));
    const principalId = context.awsRequestId;
    if (process.env.ENVIRONMENT === 'production'  || process.env.ENVIRONMENT === 'integration') {
        callback(null, generateAllow(principalId, event.methodArn))
    }
    const ipAddress = event.requestContext.identity.sourceIp;
    const validIps = [
            '217.196.229.77/32',
            '217.196.229.79/32',
            '217.196.229.80/31',
            '51.149.8.0/25',
            '51.149.8.128/29',
            '213.86.153.211/32',
            '213.86.153.212/31',
            '213.86.153.214/32',
            '213.86.153.235/32',
            '213.86.153.236/31',
            '213.86.153.231/32',
            '3.9.227.33/32',
            '18.132.149.145/32',
        ];
    isIp4InCidrs(ipAddress, validIps) ? callback(null, generateAllow(principalId, event.methodArn)) : callback(null, generateDeny(principalId, event.methodArn));
}
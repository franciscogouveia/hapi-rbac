'use strict';

const Joi = require('joi');
const Code = require('code');
const Lab = require('lab');
const {createServer} = require('./helpers/server');

const lab = exports.lab = Lab.script();
const experiment = lab.experiment;
const test = lab.test;
const before = lab.before;

const expect = Code.expect;

/**
 * Rule based access control policy tests, based on username
 **/
experiment('Global RBAC policy, based on username', () => {

    let server;

    before(async () => {
        const users = {};

        users.sg1001 = {
            'scope': 'admin',
            'firstName': 'Some',
            'lastName': 'Guy',
            'username': 'sg1001',
            'password': 'pwtest',
            'group': ['reader']
        };

        users.sg1002 = {
            'scope': 'admin',
            'firstName': 'Some',
            'lastName': 'Other Guy',
            'username': 'sg1002',
            'password': 'pwtest',
            'group': ['reader']
        };

        // Set up the hapi server route
        server = await createServer(users, {
            policy: {
                target: {'credentials:username': 'sg1001'},
                apply: 'permit-overrides',
                rules: [
                    {
                        'effect': 'permit'
                    }
                ]
            }
        });

        // No policy configured -> use global configuration
        server.route({
            method: 'GET',
            path: '/endpoint',
            handler: (request, h) => h.response({ok: true})
        });

        // Policy configured -> use route configuration (ignore global configuration)
        server.route({
            method: 'GET',
            path: '/overriden-policy',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {
                    rbac: {
                        target: {'credentials:username': 'sg1002'},
                        apply: 'permit-overrides',
                        rules: [
                            {
                                'effect': 'permit'
                            }
                        ]
                    }
                }
            }
        });

        // Policy disabled -> do not use access control (ignore global configuration)
        server.route({
            method: 'GET',
            path: '/disabled-ac',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {
                    rbac: 'none'
                }
            }
        });


        // If param1 is 'forbiddenParam', access should be denied. Always allowed otherwise.
        server.route({
            method: 'GET',
            path: '/route-params/{param1}',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {
                    rbac: {
                        apply: 'deny-overrides',
                        rules: [
                            {
                                target: {'params:param1': 'forbiddenParam'},
                                'effect': 'deny'
                            },
                            {
                                'effect': 'permit'
                            }
                        ]
                    }
                }
            }
        });


        // If query param1 is 'forbiddenParam', access should be denied. Always allowed otherwise.
        server.route({
            method: 'GET',
            path: '/route-query-params',
            handler: (request, h) => h.response({ok: true}),
            config: {
                validate: {
                    query: {
                        param1: Joi.string().required()
                    }
                },
                plugins: {
                    rbac: {
                        apply: 'deny-overrides',
                        rules: [
                            {
                                target: {'query:param1': 'forbiddenParam'},
                                'effect': 'deny'
                            },
                            {
                                'effect': 'permit'
                            }
                        ]
                    }
                }
            }
        });

        // If request method is 'get', access should be denied. This is a stupid example, this rule would only make sense in a global configuration.
        server.route({
            method: 'GET',
            path: '/route-request-get-deny',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {
                    rbac: {
                        apply: 'deny-overrides',
                        rules: [
                            {
                                target: {'request:method': 'get'},
                                'effect': 'deny'
                            },
                            {
                                'effect': 'permit'
                            }
                        ]
                    }
                }
            }
        });

        // If request method is 'get', access should be denied. This is a stupid example, this rule would only make sense in a global configuration.
        server.route({
            method: 'GET',
            path: '/route-request-get-allow',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {
                    rbac: {
                        apply: 'deny-overrides',
                        rules: [
                            {
                                target: {'request:method': 'post'},
                                'effect': 'deny'
                            },
                            {
                                'effect': 'permit'
                            }
                        ]
                    }
                }
            }
        });

        // Target matching on the first two rules will be always false, since the fields do not exist
        server.route({
            method: 'GET',
            path: '/route-non-existing-field',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {
                    rbac: {
                        apply: 'permit-overrides',
                        rules: [
                            {   // Invalid field
                                target: {'request:somefield': 'test'},
                                'effect': 'permit'
                            },
                            {   // Invalid data source
                                target: {'somesource:somefield': 'test'},
                                'effect': 'permit'
                            },
                            {
                                'effect': 'deny'
                            }
                        ]
                    }
                }
            }
        });

        // Target matching between two fields
        server.route({
            method: 'GET',
            path: '/match-fields/{id}',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {
                    rbac: {
                        apply: 'permit-overrides',
                        rules: [
                            {
                                target: {
                                    // Valid match: /match-fields/123?test=123
                                    // Invalid match: /match-fields/123?test=456
                                    'params:id': {field: 'query:test'}
                                },
                                'effect': 'permit'
                            },
                            {
                                'effect': 'deny'
                            }
                        ]
                    }
                }
            }
        });

        // Target matching using RegExp
        server.route({
            method: 'GET',
            path: '/regex-match',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {
                    rbac: {
                        apply: 'permit-overrides',
                        rules: [
                            {
                                // Allow all users which last name starts with Other
                                target: {
                                    'credentials:lastName': /^Other.*$/
                                },
                                'effect': 'permit'
                            },
                            {
                                'effect': 'deny'
                            }
                        ]
                    }
                }
            }
        });

    });

    test('Should have access to the route, with policy targeting the username', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/endpoint',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1001:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(200);
    });

    test('Should not have access to the route, with policy targeting the username', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/endpoint',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(401);
    });

    test('Should not have access to the route, with overriden policy targeting the username', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/overriden-policy',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1001:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(401);
    });

    test('Should have access to the route, with overriden policy targeting the username', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/overriden-policy',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(200);
    });


    test('Should allow access to the route with params', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/route-params/validParam',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(200);
    });

    test('Should deny access to the route with denied param', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/route-params/forbiddenParam',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(401);
    });


    test('Should allow access to the route with query param', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/route-query-params?param1=validParam',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(200);
    });

    test('Should deny access to the route with denied query param', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/route-query-params?param1=forbiddenParam',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(401);
    });

    test('Should deny access to the route with get request method', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/route-request-get-deny',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(401);
    });

    test('Should allow access to the route with get request method', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/route-request-get-allow',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(200);
    });

    test('Should deny access to the route with get request method', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/route-non-existing-field',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(401);
    });

    test('Should allow access to the route with matching param and query fields', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/match-fields/123?test=123',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(200);
    });

    test('Should deny access to the route with non-matching param and query fields', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/match-fields/123?test=456',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(401);
    });

    test('Should have access to the route, with policy targeting a regex of last name', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/regex-match',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(200);
    });

    test('Should not have access to the route, with policy targeting a regex of last name', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/regex-match',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1001:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(401);
    });

});


/**
 * Rule based access control policy tests, with callback function configuration
 **/
experiment('Global dynamic RBAC policy with callback function', () => {

    let server;

    before(async () => {
        const users = {};

        users.sg1001 = {
            'scope': 'admin',
            'firstName': 'Some',
            'lastName': 'Guy',
            'username': 'sg1001',
            'password': 'pwtest',
            'group': ['reader']
        };

        users.sg1002 = {
            'scope': 'admin',
            'firstName': 'Some',
            'lastName': 'Other Guy',
            'username': 'sg1002',
            'password': 'pwtest',
            'group': ['reader']
        };

        // Set up the hapi server route
        server = await createServer(users, {
            policy: () => {

                /* Usually retrieved from a DB... */
                return {
                    target: {'credentials:username': 'sg1001'},
                    apply: 'permit-overrides',
                    rules: [
                        {
                            'effect': 'permit'
                        }
                    ]
                };
            }
        });

        // No policy configured -> use global configuration
        server.route({
            method: 'GET',
            path: '/endpoint',
            handler: (request, h) => h.response({ok: true})
        });

        // Policy configured -> use route configuration (ignore global configuration)
        server.route({
            method: 'GET',
            path: '/overriden-policy',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {
                    rbac: () => {

                        /* Usually retrieved from a DB... */
                        return {
                            target: {'credentials:username': 'sg1002'},
                            apply: 'permit-overrides',
                            rules: [
                                {
                                    'effect': 'permit'
                                }
                            ]
                        };
                    }
                }
            }
        });


        // Policy disabled -> do not use access control (ignore global configuration)
        server.route({
            method: 'GET',
            path: '/disabled-ac',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {
                    rbac: 'none'
                }
            }
        });
    });

    test('Should have access to the route, with policy targeting the username', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/endpoint',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1001:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(200);
    });

    test('Should not have access to the route, with policy targeting the username', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/endpoint',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(401);
    });

    test('Should not have access to the route, with overriden policy targeting the username', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/overriden-policy',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1001:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(401);
    });

    test('Should have access to the route, with overriden policy targeting the username', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/overriden-policy',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(200);
    });

    test('Should have access to the route, with disabled ac', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/disabled-ac',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(200);
    });
});

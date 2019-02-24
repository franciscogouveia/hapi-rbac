'use strict';

const {createServer} = require('./helpers/server');

const Boom = require('boom');
const Code = require('code');
const Lab = require('lab');

const lab = exports.lab = Lab.script();
const experiment = lab.experiment;
const test = lab.test;
const before = lab.before;

const expect = Code.expect;

experiment('Generic tests, with RBAC plugin configured', () => {

    let server;

    before(async () => {
        const users = {};

        users.sg1000 = {
            'scope': 'admin',
            'firstName': 'Some',
            'lastName': 'Guy',
            'username': 'sg1000',
            'password': 'pwtest',
            'group': ['admin']
        };

        // Set up the hapi server route
        server = await createServer(users, {});

        server.route({
            method: 'GET',
            path: '/wrong-credentials',
            handler: (request, h) => h.response({ok: true})
        });

        server.route({
            method: 'GET',
            path: '/user',
            handler: (request, h) => h.response({ok: true})
        });
    });

    test('Should not have access with wrong credentials', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/wrong-credentials',
            headers: {
                authorization: 'Basic ' + (new Buffer('xpto:pw-123456', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(401);
        expect(response.result.error).to.equal('Unauthorized');
        expect(response.result.message).to.equal('Bad username or password');
    });

    test('Should have access on route without ac rules', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/user',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1000:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(200);
    });
});


/**
 * Rule based access control policy tests, based on username
 **/
experiment('RBAC policy, based on username', () => {

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
        // Set up the hapi server route
        server = await createServer(users, {});

        server.route({
            method: 'GET',
            path: '/allow-username',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {
                    rbac: {
                        target: {'credentials:username': 'sg1001'},
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

        server.route({
            method: 'GET',
            path: '/disallow-username',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {
                    rbac: {
                        target: {'credentials:username': 'sg1001'},
                        apply: 'permit-overrides',
                        rules: [
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
            url: '/allow-username',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1001:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(200);
    });

    test('Should not have access to the route, with policy targeting the username', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/disallow-username',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1001:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(401);
    });

});

/**
 * Rule based access control policy tests, based on group membership
 **/
experiment('RBAC policy, based on group membership', () => {

    let server;

    before(async () => {
        const users = {};

        users.sg1002 = {
            'scope': 'admin',
            'firstName': 'Some',
            'lastName': 'Otherguy',
            'username': 'sg1002',
            'password': 'pwtest',
            'group': ['admin', 'publisher']
        };

        users.sg1003 = {
            'scope': 'admin',
            'firstName': 'Another',
            'lastName': 'Guy',
            'username': 'sg1003',
            'password': 'pwtest',
            'group': ['admin', 'reader']
        };
        // Set up the hapi server route
        server = await createServer(users, {});

        server.route({
            method: 'GET',
            path: '/permit-with-group-membership',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {
                    rbac: {
                        target: {'credentials:group': 'admin'},
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

        server.route({
            method: 'GET',
            path: '/deny-without-group-membership',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {
                    rbac: {
                        target: {'credentials:group': 'reader'},
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

        server.route({
            method: 'GET',
            path: '/permit-if-at-least-one-group-membership',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {
                    rbac: {
                        target: [{'credentials:group': 'reader'}, {'credentials:group': 'admin'}],
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

        server.route({
            method: 'GET',
            path: '/deny-if-none-group-membership',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {
                    rbac: {
                        target: [{'credentials:group': 'reader'}, {'credentials:group': 'watcher'}],
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

        server.route({
            method: 'GET',
            path: '/deny-if-not-all-group-membership',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {
                    rbac: {
                        target: {'credentials:group': ['reader', 'admin']},
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

        server.route({
            method: 'GET',
            path: '/permit-if-all-group-membership',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {
                    rbac: {
                        target: {'credentials:group': 'admin'},
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
    });

    test('Should have access to the route, with policy targeting a group inside user membership', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/permit-with-group-membership',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(200);
    });

    test('Should not have access to the route, with policy targeting a group outside user membership', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/deny-without-group-membership',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(401);
    });

    test('Should have access to the route, with policy targeting one group inside OR one group outside user membership', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/permit-if-at-least-one-group-membership',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(200);
    });


    test('Should have access to the route, with policy targeting two groups outside user membership', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/deny-if-none-group-membership',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        });
        expect(response.statusCode).to.equal(401);
    });

    test('Should not have access to the route, with policy targeting one group inside AND one group outside user membership', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/deny-if-not-all-group-membership',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(401);
    });

    test('Should have access to the route, with policy targeting two groups inside user membership', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/permit-if-all-group-membership',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(200);
    });
});


/**
 * Rule based access control policy tests, based on username
 **/
experiment('RBAC rule, based on username', () => {

    let server;

    before(async () => {
        const users = {};

        users.sg1004 = {
            'scope': 'admin',
            'firstName': 'Some',
            'lastName': 'Guy',
            'username': 'sg1004',
            'password': 'pwtest',
            'group': ['reader']
        };
        // Set up the hapi server route
        server = await createServer(users, {});
    });

    test('Should have access to the route, with policy targeting the username', async () => {

        server.route({
            method: 'GET',
            path: '/allow-username',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {
                    rbac: {
                        apply: 'permit-overrides',
                        rules: [
                            {
                                target: {'credentials:username': 'sg1004'},
                                effect: 'permit'
                            }
                        ]
                    }
                }
            }
        });

        const response = await server.inject({
            method: 'GET',
            url: '/allow-username',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1004:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(200);
    });

    test('Should not have access to the route, with policy targeting the username', async () => {

        server.route({
            method: 'GET',
            path: '/disallow-username',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {
                    rbac: {
                        apply: 'permit-overrides',
                        rules: [
                            {
                                target: {'credentials:username': 'sg1004'},
                                effect: 'deny'
                            }
                        ]
                    }
                }
            }
        });

        const response = await server.inject({
            method: 'GET',
            url: '/disallow-username',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1004:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(401);
    });

});

/**
 * Rule based access control rule tests, based on group membership
 **/
experiment('RBAC rule, based on group membership', () => {

    let server;

    before(async () => {
        const users = {};

        users.sg1005 = {
            'scope': 'admin',
            'firstName': 'Some',
            'lastName': 'Otherguy',
            'username': 'sg1005',
            'password': 'pwtest',
            'group': ['admin', 'publisher']
        };

        users.sg1006 = {
            'scope': 'admin',
            'firstName': 'Another',
            'lastName': 'Guy',
            'username': 'sg1006',
            'password': 'pwtest',
            'group': ['admin', 'reader']
        };
        // Set up the hapi server route
        server = await createServer(users, {});
    });

    test('Should have access to the route, with policy targeting a group inside user membership', async () => {
        server.route({
            method: 'GET',
            path: '/permit-with-group-membership',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {
                    rbac: {
                        apply: 'permit-overrides',
                        rules: [
                            {
                                target: {'credentials:group': 'admin'},
                                effect: 'permit'
                            }
                        ]
                    }
                }
            }
        });

        const response = await server.inject({
            method: 'GET',
            url: '/permit-with-group-membership',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1005:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(200);
    });

    test('Should not have access to the route, with policy targeting a group outside user membership', async () => {

        server.route({
            method: 'GET',
            path: '/deny-without-group-membership',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {
                    rbac: {
                        apply: 'permit-overrides',
                        rules: [
                            {
                                target: {'credentials:group': 'reader'},
                                effect: 'permit'
                            }
                        ]
                    }
                }
            }
        });

        const response = await server.inject({
            method: 'GET',
            url: '/deny-without-group-membership',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1005:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(401);
    });

    test('Should have access to the route, with policy targeting one group inside OR one group outside user membership', async () => {

        server.route({
            method: 'GET',
            path: '/permit-if-at-least-one-group-membership',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {
                    rbac: {
                        apply: 'permit-overrides',
                        rules: [
                            {
                                target: [{'credentials:group': 'reader'}, {'credentials:group': 'admin'}],
                                effect: 'permit'
                            }
                        ]
                    }
                }
            }
        });

        const response = await server.inject({
            method: 'GET',
            url: '/permit-if-at-least-one-group-membership',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1005:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(200);
    });


    test('Should have access to the route, with policy targeting two groups outside user membership', async () => {
        server.route({
            method: 'GET',
            path: '/deny-if-none-group-membership',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {
                    rbac: {
                        apply: 'permit-overrides',
                        rules: [
                            {
                                target: [{'credentials:group': 'reader'}, {'credentials:group': 'watcher'}],
                                effect: 'permit'
                            }
                        ]
                    }
                }
            }
        });

        const response = await server.inject({
            method: 'GET',
            url: '/deny-if-none-group-membership',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1005:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(401);
    });

    test('Should not have access to the route, with policy targeting one group inside AND one group outside user membership', async () => {

        server.route({
            method: 'GET',
            path: '/deny-if-not-all-group-membership',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {
                    rbac: {
                        apply: 'permit-overrides',
                        rules: [
                            {
                                target: {'credentials:group': ['reader', 'admin']},
                                effect: 'permit'
                            }
                        ]
                    }
                }
            }
        });

        const response = await server.inject({
            method: 'GET',
            url: '/deny-if-not-all-group-membership',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1005:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(401);
    });

    test('Should have access to the route, with policy targeting two groups inside user membership', async () => {

        server.route({
            method: 'GET',
            path: '/permit-if-all-group-membership',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {
                    rbac: {
                        apply: 'permit-overrides',
                        rules: [
                            {
                                target: {'credentials:group': ['publisher', 'admin']},
                                effect: 'permit'
                            }
                        ]
                    }
                }
            }
        });

        const response = await server.inject({
            method: 'GET',
            url: '/permit-if-all-group-membership',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1005:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(200);
    });
});


/**
 * Rule based access control complex policy rules test
 **/
experiment('RBAC complex rules', () => {

    let server;

    before(async () => {
        const users = {};

        users.sg1007 = {
            'scope': 'admin',
            'firstName': 'Some',
            'lastName': 'Otherguy',
            'username': 'sg1007',
            'password': 'pwtest',
            'group': ['admin', 'publisher']
        };

        users.sg1008 = {
            'scope': 'admin',
            'firstName': 'Another',
            'lastName': 'Guy',
            'username': 'sg1008',
            'password': 'pwtest',
            'group': ['admin', 'reader']
        };
        // Set up the hapi server route
        server = await createServer(users, {});

        server.route({
            method: 'GET',
            path: '/example',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {
                    rbac: {
                        target: {'credentials:group': 'admin'},
                        apply: 'deny-overrides',
                        rules: [
                            {
                                target: {'credentials:username': 'sg1007'},
                                effect: 'deny'
                            },
                            {
                                effect: 'permit'
                            }
                        ]
                    }
                }
            }
        });
    });

    test('Should have access, through the admin group membership', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/example',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1008:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(200);
    });

    test('Should not have access, through the policy exception rule', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/example',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1007:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(401);
    });

});


/**
 * Rule based access control policy tests, with async function configuration
 **/
experiment('Dynamic RBAC policy with function', () => {

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
        // Set up the hapi server route
        server = await createServer(users, {});
    });

    test('Should have access to the route, with policy targeting the username', async () => {
        server.route({
            method: 'GET',
            path: '/allow-username',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {
                    rbac: () => {

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
                }
            }
        });

        const response = await server.inject({
            method: 'GET',
            url: '/allow-username',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1001:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(200);
    });

    test('Should not have access to the route, with policy targeting the username', async () => {
        server.route({
            method: 'GET',
            path: '/disallow-username',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {

                    rbac: () => {
                        /* Usually retrieved from a DB... */
                        return {
                            target: {'credentials:username': 'sg1001'},
                            apply: 'permit-overrides',
                            rules: [
                                {
                                    'effect': 'deny'
                                }
                            ]
                        };
                    }
                }
            }
        });

        const response = await server.inject({
            method: 'GET',
            url: '/disallow-username',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1001:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(401);
    });

    test('Should have access to the route if no policy is configured', async () => {

        server.route({
            method: 'GET',
            path: '/unrestricted-access',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {

                    rbac: (request) => {
                        return null;
                    }
                }
            }
        });

        const response = await server.inject({
            method: 'GET',
            url: '/unrestricted-access',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1001:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(200);
        expect(response.result.ok).to.exist().and.equal(true);
    });

});


experiment('Setting configurable response code for deny case', () => {

    let server;

    before(async () => {
        const users = {};

        users.sg1001 = {
            'scope': 'admin',
            'firstName': 'Some',
            'lastName': 'Guy',
            'username': 'sg1001',
            'password': 'pwtest'
        };


        users.sg1002 = {
            'scope': 'admin',
            'firstName': 'Some',
            'lastName': 'Guy',
            'username': 'sg1002',
            'password': 'pwtest'
        };
        // Set up the hapi server route
        server = await createServer(users, {
            responseCode: {
                onDeny: 403,
                onUndetermined: 403
            }
        });
    });

    test('The access should be denied (request do apply to the target)', async () => {

        server.route({
            method: 'GET',
            path: '/access-denied',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {

                    rbac: () => {

                        /* Usually retrieved from a DB... */
                        return {
                            target: {'credentials:username': 'sg1001'},
                            apply: 'permit-overrides',
                            rules: [
                                {
                                    'effect': 'deny'
                                }
                            ]
                        };
                    }
                }
            }
        });

        const response = await server.inject({
            method: 'GET',
            url: '/access-denied',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1001:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(403);
    });


    test('The access should be denied (request do not apply to the target)', async () => {

        server.route({
            method: 'GET',
            path: '/access-undetermined',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {

                    rbac: () => {

                        /* Usually retrieved from a DB... */
                        return {
                            target: {'credentials:username': 'sg1001'},
                            apply: 'permit-overrides',
                            rules: [
                                {
                                    'effect': 'deny'
                                }
                            ]
                        };
                    }
                }
            }
        });

        const response = await server.inject({
            method: 'GET',
            url: '/access-undetermined',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(403);
    });
});

experiment('Setting configurable response code for undetermined case', () => {

    let server;

    before(async () => {
        const users = {};

        users.sg1001 = {
            'scope': 'admin',
            'firstName': 'Some',
            'lastName': 'Guy',
            'username': 'sg1001',
            'password': 'pwtest'
        };


        users.sg1002 = {
            'scope': 'admin',
            'firstName': 'Some',
            'lastName': 'Guy',
            'username': 'sg1002',
            'password': 'pwtest'
        };
        // Set up the hapi server route
        server = await createServer(users, {
            responseCode: {
                onUndetermined: 403
            }
        });

        server.route({
            method: 'GET',
            path: '/access-denied',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {

                    rbac: () => {

                        /* Usually retrieved from a DB... */
                        return {
                            target: {'credentials:username': 'sg1001'},
                            apply: 'permit-overrides',
                            rules: [
                                {
                                    'effect': 'deny'
                                }
                            ]
                        };
                    }
                }
            }
        });

        server.route({
            method: 'GET',
            path: '/access-undetermined',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {

                    rbac: () => {

                        /* Usually retrieved from a DB... */
                        return {
                            target: {'credentials:username': 'sg1001'},
                            apply: 'permit-overrides',
                            rules: [
                                {
                                    'effect': 'deny'
                                }
                            ]
                        };
                    }
                }
            }
        });
    });

    test('The access should be denied (request do apply to the target)', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/access-denied',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1001:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(401);
    });


    test('The access should be denied (request do not apply to the target)', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/access-undetermined',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(403);
    });
});

experiment('Setting configurable response code for both undetermined and deny case', () => {

    let server;

    before(async () => {
        const users = {};

        users.sg1001 = {
            'scope': 'admin',
            'firstName': 'Some',
            'lastName': 'Guy',
            'username': 'sg1001',
            'password': 'pwtest'
        };

        users.sg1002 = {
            'scope': 'admin',
            'firstName': 'Some',
            'lastName': 'Guy',
            'username': 'sg1002',
            'password': 'pwtest'
        };
        // Set up the hapi server route
        server = await createServer(users, {
            responseCode: {
                onDeny: 403,
                onUndetermined: 403
            }
        });

        server.route({
            method: 'GET',
            path: '/access-denied',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {

                    rbac: () => {

                        /* Usually retrieved from a DB... */
                        return {
                            target: {'credentials:username': 'sg1001'},
                            apply: 'permit-overrides',
                            rules: [
                                {
                                    'effect': 'deny'
                                }
                            ]
                        };
                    }
                }
            }
        });
        server.route({
            method: 'GET',
            path: '/access-undetermined',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {

                    rbac: () => {

                        /* Usually retrieved from a DB... */
                        return {
                            target: {'credentials:username': 'sg1001'},
                            apply: 'permit-overrides',
                            rules: [
                                {
                                    'effect': 'deny'
                                }
                            ]
                        };
                    }
                }
            }
        });
    });

    test('The access should be denied (request do apply to the target)', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/access-denied',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1001:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(403);
    });


    test('The access should be denied (request do not apply to the target)', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/access-undetermined',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(403);
    });
});

experiment('Setting configurable method to execute on error', () => {

    let server;

    before(async () => {
        const users = {};

        users.sg1001 = {
            'scope': 'admin',
            'firstName': 'Some',
            'lastName': 'Guy',
            'username': 'sg1001',
            'password': 'pwtest'
        };


        users.sg1002 = {
            'scope': 'admin',
            'firstName': 'Some',
            'lastName': 'Guy',
            'username': 'sg1002',
            'password': 'pwtest'
        };

        // Set up the hapi server route
        server = await createServer(users, {
            onError(request, h, err) {
                throw new Boom(err.message, {statusCode: 403});
            }
        });

        server.route({
            method: 'GET',
            path: '/access-denied',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {
                    rbac: () => {
                        /* Usually retrieved from a DB... */
                        return {
                            target: {'credentials:username': 'sg1001'},
                            apply: 'permit-overrides',
                            rules: [
                                {
                                    'effect': 'deny'
                                }
                            ]
                        };
                    }
                }
            }
        });

        server.route({
            method: 'GET',
            path: '/access-undetermined',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {

                    rbac: () => {

                        /* Usually retrieved from a DB... */
                        return {
                            target: {'credentials:username': 'sg1001'},
                            apply: 'permit-overrides',
                            rules: [
                                {
                                    'effect': 'deny'
                                }
                            ]
                        };
                    }
                }
            }
        });
    });

    test('The access should be denied (request do apply to the target)', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/access-denied',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1001:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(403);
    });


    test('The access should be denied (request do not apply to the target)', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/access-undetermined',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(403);
    });
});

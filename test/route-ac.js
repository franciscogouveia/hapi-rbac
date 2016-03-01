'use strict';

const Hapi = require('hapi');
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

    before((done) => {
        // Set up the hapi server route
        server = new Hapi.Server();

        server.connection();

        const users = {};

        users.sg1000 = {
            'scope': 'admin',
            'firstName': 'Some',
            'lastName': 'Guy',
            'username': 'sg1000',
            'password': 'pwtest',
            'group': ['admin']
        };

        server.register([
            {
                register: require('hapi-auth-basic')
            },
            {
                register: require('../')
            }
        ], (err) => {

            if (err) {
                return done(err);
            }

            server.auth.strategy('default', 'basic', 'required', {
                validateFunc: (request, username, password, callback) => {

                    if (!users[username] || users[username].password !== password) {
                        return callback(Boom.unauthorized('Wrong credentials'), false);
                    }

                    callback(null, true, users[username]);
                }
            });

            done();

        });

    });

    test('Should not have access with wrong credentials', (done) => {

        server.route({
            method: 'GET',
            path: '/wrong-credentials',
            handler: (request, reply) => reply({ ok: true })
        });

        server.inject({
            method: 'GET',
            url: '/wrong-credentials',
            headers: {
                authorization: 'Basic ' + (new Buffer('xpto:pw-123456', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(401);

            expect(response.result.error).to.equal('Unauthorized');
            expect(response.result.message).to.equal('Wrong credentials');

            done();
        });
    });

    test('Should have access on route without ac rules', (done) => {

        server.route({
            method: 'GET',
            path: '/user',
            handler: (request, reply) => reply({ ok: true })
        });

        server.inject({
            method: 'GET',
            url: '/user',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1000:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(200);

            done();
        });
    });

});


/**
 * Rule based access control policy tests, based on username
 **/
experiment('RBAC policy, based on username', () => {

    let server;

    before((done) => {
        // Set up the hapi server route
        server = new Hapi.Server();

        server.connection();

        const users = { };

        users.sg1001 = {
            'scope': 'admin',
            'firstName': 'Some',
            'lastName': 'Guy',
            'username': 'sg1001',
            'password': 'pwtest',
            'group': ['reader']
        };

        server.register([
            {
                register: require('hapi-auth-basic')
            },
            {
                register: require('../')
            }
        ], (err) => {

            if (err) {
                return done(err);
            }

            server.auth.strategy('default', 'basic', 'required', {
                validateFunc: (request, username, password, callback) => {

                    if (!users[username] || users[username].password !== password) {
                        return callback(Boom.unauthorized('Wrong credentials'), false);
                    }

                    callback(null, true, users[username]);
                }
            });

            done();

        });

    });

    test('Should have access to the route, with policy targeting the username', (done) => {

        server.route({
            method: 'GET',
            path: '/allow-username',
            handler: (request, reply) => reply({ ok: true }),
            config: {
                plugins: {
                    rbac: {
                        target: { 'credentials:username': 'sg1001' },
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

        server.inject({
            method: 'GET',
            url: '/allow-username',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1001:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(200);

            done();
        });
    });

    test('Should not have access to the route, with policy targeting the username', (done) => {

        server.route({
            method: 'GET',
            path: '/disallow-username',
            handler: (request, reply) => reply({ ok: true }),
            config: {
                plugins: {
                    rbac: {
                        target: { 'credentials:username': 'sg1001' },
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

        server.inject({
            method: 'GET',
            url: '/disallow-username',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1001:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(401);

            done();
        });
    });

});

/**
 * Rule based access control policy tests, based on group membership
 **/
experiment('RBAC policy, based on group membership', () => {

    let server;

    before((done) => {
        // Set up the hapi server route
        server = new Hapi.Server();

        server.connection();

        const users = { };

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

        server.register([
            {
                register: require('hapi-auth-basic')
            },
            {
                register: require('../')
            }
        ], (err) => {

            if (err) {
                return done(err);
            }

            server.auth.strategy('default', 'basic', 'required', {
                validateFunc: (request, username, password, callback) => {

                    if (!users[username] || users[username].password !== password) {
                        return callback(Boom.unauthorized('Wrong credentials'), false);
                    }

                    callback(null, true, users[username]);
                }
            });

            done();

        });

    });

    test('Should have access to the route, with policy targeting a group inside user membership', (done) => {

        server.route({
            method: 'GET',
            path: '/permit-with-group-membership',
            handler: (request, reply) => reply({ ok: true }),
            config: {
                plugins: {
                    rbac: {
                        target: { 'credentials:group': 'admin' },
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

        server.inject({
            method: 'GET',
            url: '/permit-with-group-membership',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(200);

            done();
        });
    });

    test('Should not have access to the route, with policy targeting a group outside user membership', (done) => {

        server.route({
            method: 'GET',
            path: '/deny-without-group-membership',
            handler: (request, reply) => reply({ ok: true }),
            config: {
                plugins: {
                    rbac: {
                        target: { 'credentials:group': 'reader' },
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

        server.inject({
            method: 'GET',
            url: '/deny-without-group-membership',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(401);

            done();
        });
    });

    test('Should have access to the route, with policy targeting one group inside OR one group outside user membership', (done) => {

        server.route({
            method: 'GET',
            path: '/permit-if-at-least-one-group-membership',
            handler: (request, reply) => reply({ ok: true }),
            config: {
                plugins: {
                    rbac: {
                        target: [{ 'credentials:group': 'reader' }, { 'credentials:group': 'admin' }],
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

        server.inject({
            method: 'GET',
            url: '/permit-if-at-least-one-group-membership',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(200);

            done();
        });
    });


    test('Should have access to the route, with policy targeting two groups outside user membership', (done) => {

        server.route({
            method: 'GET',
            path: '/deny-if-none-group-membership',
            handler: (request, reply) => reply({ ok: true }),
            config: {
                plugins: {
                    rbac: {
                        target: [{ 'credentials:group': 'reader' }, { 'credentials:group': 'watcher' }],
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

        server.inject({
            method: 'GET',
            url: '/deny-if-none-group-membership',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(401);

            done();
        });
    });

    test('Should not have access to the route, with policy targeting one group inside AND one group outside user membership', (done) => {

        server.route({
            method: 'GET',
            path: '/deny-if-not-all-group-membership',
            handler: (request, reply) => reply({ ok: true }),
            config: {
                plugins: {
                    rbac: {
                        target: { 'credentials:group': ['reader', 'admin'] },
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

        server.inject({
            method: 'GET',
            url: '/deny-if-not-all-group-membership',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(401);

            done();
        });
    });

    test('Should have access to the route, with policy targeting two groups inside user membership', (done) => {

        server.route({
            method: 'GET',
            path: '/permit-if-all-group-membership',
            handler: (request, reply) => reply({ ok: true }),
            config: {
                plugins: {
                    rbac: {
                        target: { 'credentials:group': 'publisher', 'credentials:group': 'admin' },
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

        server.inject({
            method: 'GET',
            url: '/permit-if-all-group-membership',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(200);

            done();
        });
    });
});


/**
 * Rule based access control policy tests, based on username
 **/
experiment('RBAC rule, based on username', () => {

    let server;

    before((done) => {

        // Set up the hapi server route
        server = new Hapi.Server();

        server.connection();

        const users = { };

        users.sg1004 = {
            'scope': 'admin',
            'firstName': 'Some',
            'lastName': 'Guy',
            'username': 'sg1004',
            'password': 'pwtest',
            'group': ['reader']
        };

        server.register([
            {
                register: require('hapi-auth-basic')
            },
            {
                register: require('../')
            }
        ], (err) => {

            if (err) {
                return done(err);
            }

            server.auth.strategy('default', 'basic', 'required', {
                validateFunc: (request, username, password, callback) => {

                    if (!users[username] || users[username].password !== password) {
                        return callback(Boom.unauthorized('Wrong credentials'), false);
                    }

                    callback(null, true, users[username]);
                }
            });

            done();

        });

    });

    test('Should have access to the route, with policy targeting the username', (done) => {

        server.route({
            method: 'GET',
            path: '/allow-username',
            handler: (request, reply) => reply({ ok: true }),
            config: {
                plugins: {
                    rbac: {
                        apply: 'permit-overrides',
                        rules: [
                            {
                                target: { 'credentials:username': 'sg1004' },
                                effect: 'permit'
                            }
                        ]
                    }
                }
            }
        });

        server.inject({
            method: 'GET',
            url: '/allow-username',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1004:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(200);

            done();
        });
    });

    test('Should not have access to the route, with policy targeting the username', (done) => {

        server.route({
            method: 'GET',
            path: '/disallow-username',
            handler: (request, reply) => reply({ ok: true }),
            config: {
                plugins: {
                    rbac: {
                        apply: 'permit-overrides',
                        rules: [
                            {
                                target: { 'credentials:username': 'sg1004' },
                                effect: 'deny'
                            }
                        ]
                    }
                }
            }
        });

        server.inject({
            method: 'GET',
            url: '/disallow-username',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1004:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(401);

            done();
        });
    });

});

/**
 * Rule based access control rule tests, based on group membership
 **/
experiment('RBAC rule, based on group membership', () => {

    let server;

    before((done) => {

        // Set up the hapi server route
        server = new Hapi.Server();

        server.connection();

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

        server.register([
            {
                register: require('hapi-auth-basic')
            },
            {
                register: require('../')
            }
        ], (err) => {

            if (err) {
                return done(err);
            }

            server.auth.strategy('default', 'basic', 'required', {
                validateFunc: (request, username, password, callback) => {

                    if (!users[username] || users[username].password !== password) {
                        return callback(Boom.unauthorized('Wrong credentials'), false);
                    }

                    callback(null, true, users[username]);
                }
            });

            done();

        });

    });

    test('Should have access to the route, with policy targeting a group inside user membership', (done) => {

        server.route({
            method: 'GET',
            path: '/permit-with-group-membership',
            handler: (request, reply) => reply({ ok: true }),
            config: {
                plugins: {
                    rbac: {
                        apply: 'permit-overrides',
                        rules: [
                            {
                                target: { 'credentials:group': 'admin' },
                                effect: 'permit'
                            }
                        ]
                    }
                }
            }
        });

        server.inject({
            method: 'GET',
            url: '/permit-with-group-membership',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1005:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(200);

            done();
        });
    });

    test('Should not have access to the route, with policy targeting a group outside user membership', (done) => {

        server.route({
            method: 'GET',
            path: '/deny-without-group-membership',
            handler: (request, reply) => reply({ ok: true }),
            config: {
                plugins: {
                    rbac: {
                        apply: 'permit-overrides',
                        rules: [
                            {
                                target: { 'credentials:group': 'reader' },
                                effect: 'permit'
                            }
                        ]
                    }
                }
            }
        });

        server.inject({
            method: 'GET',
            url: '/deny-without-group-membership',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1005:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(401);

            done();
        });
    });

    test('Should have access to the route, with policy targeting one group inside OR one group outside user membership', (done) => {

        server.route({
            method: 'GET',
            path: '/permit-if-at-least-one-group-membership',
            handler: (request, reply) => reply({ ok: true }),
            config: {
                plugins: {
                    rbac: {
                        apply: 'permit-overrides',
                        rules: [
                            {
                                target: [{ 'credentials:group': 'reader' }, { 'credentials:group': 'admin' }],
                                effect: 'permit'
                            }
                        ]
                    }
                }
            }
        });

        server.inject({
            method: 'GET',
            url: '/permit-if-at-least-one-group-membership',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1005:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(200);

            done();
        });
    });


    test('Should have access to the route, with policy targeting two groups outside user membership', (done) => {

        server.route({
            method: 'GET',
            path: '/deny-if-none-group-membership',
            handler: (request, reply) => reply({ ok: true }),
            config: {
                plugins: {
                    rbac: {
                        apply: 'permit-overrides',
                        rules: [
                            {
                                target: [{ 'credentials:group': 'reader' }, { 'credentials:group': 'watcher' }],
                                effect: 'permit'
                            }
                        ]
                    }
                }
            }
        });

        server.inject({
            method: 'GET',
            url: '/deny-if-none-group-membership',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1005:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(401);

            done();
        });
    });

    test('Should not have access to the route, with policy targeting one group inside AND one group outside user membership', (done) => {

        server.route({
            method: 'GET',
            path: '/deny-if-not-all-group-membership',
            handler: (request, reply) => reply({ ok: true }),
            config: {
                plugins: {
                    rbac: {
                        apply: 'permit-overrides',
                        rules: [
                            {
                                target: { 'credentials:group': ['reader', 'admin']},
                                effect: 'permit'
                            }
                        ]
                    }
                }
            }
        });

        server.inject({
            method: 'GET',
            url: '/deny-if-not-all-group-membership',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1005:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(401);

            done();
        });
    });

    test('Should have access to the route, with policy targeting two groups inside user membership', (done) => {

        server.route({
            method: 'GET',
            path: '/permit-if-all-group-membership',
            handler: (request, reply) => reply({ ok: true }),
            config: {
                plugins: {
                    rbac: {
                        apply: 'permit-overrides',
                        rules: [
                            {
                                target: { 'credentials:group': ['publisher', 'admin']},
                                effect: 'permit'
                            }
                        ]
                    }
                }
            }
        });

        server.inject({
            method: 'GET',
            url: '/permit-if-all-group-membership',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1005:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(200);

            done();
        });
    });
});


/**
 * Rule based access control complex policy rules test
 **/
experiment('RBAC complex rules', () => {

    let server;

    before((done) => {
        // Set up the hapi server route
        server = new Hapi.Server();

        server.connection();

        const users = { };

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

        server.register([
            {
                register: require('hapi-auth-basic')
            },
            {
                register: require('../')
            }
        ], (err) => {

            if (err) {
                return done(err);
            }

            server.auth.strategy('default', 'basic', 'required', {
                validateFunc: (request, username, password, callback) => {

                    if (!users[username] || users[username].password !== password) {
                        return callback(Boom.unauthorized('Wrong credentials'), false);
                    }

                    callback(null, true, users[username]);
                }
            });

            server.route({
                method: 'GET',
                path: '/example',
                handler: (request, reply) => reply({ ok: true }),
                config: {
                    plugins: {
                        rbac: {
                            target: { 'credentials:group': 'admin' },
                            apply: 'deny-overrides',
                            rules: [
                                {
                                    target: { 'credentials:username': 'sg1007' },
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

            done();

        });

    });

    test('Should have access, through the admin group membership', (done) => {

        server.inject({
            method: 'GET',
            url: '/example',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1008:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(200);

            done();
        });
    });

    test('Should not have access, through the policy exception rule', (done) => {

        server.inject({
            method: 'GET',
            url: '/example',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1007:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(401);

            done();
        });
    });

});



/**
 * Rule based access control policy tests, with callback function configuration
 **/
experiment('Dynamic RBAC policy with callback function', () => {

    let server;

    before((done) => {
        // Set up the hapi server route
        server = new Hapi.Server();

        server.connection();

        const users = { };

        users.sg1001 = {
            'scope': 'admin',
            'firstName': 'Some',
            'lastName': 'Guy',
            'username': 'sg1001',
            'password': 'pwtest',
            'group': ['reader']
        };

        server.register([
            {
                register: require('hapi-auth-basic')
            },
            {
                register: require('../')
            }
        ], (err) => {

            if (err) {
                return done(err);
            }

            server.auth.strategy('default', 'basic', 'required', {
                validateFunc: (request, username, password, callback) => {

                    if (!users[username] || users[username].password !== password) {
                        return callback(Boom.unauthorized('Wrong credentials'), false);
                    }

                    callback(null, true, users[username]);
                }
            });

            done();

        });

    });

    test('Should have access to the route, with policy targeting the username', (done) => {

        server.route({
            method: 'GET',
            path: '/allow-username',
            handler: (request, reply) => reply({ ok: true }),
            config: {
                plugins: {
                    rbac: (request, callback) => {

                        /* Usually retrieved from a DB... */
                        const policy = {
                            target: { 'credentials:username': 'sg1001' },
                            apply: 'permit-overrides',
                            rules: [
                                {
                                    'effect': 'permit'
                                }
                            ]
                        };

                        callback(null, policy);
                    }
                }
            }
        });

        server.inject({
            method: 'GET',
            url: '/allow-username',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1001:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(200);

            done();
        });
    });

    test('Should not have access to the route, with policy targeting the username', (done) => {

        server.route({
            method: 'GET',
            path: '/disallow-username',
            handler: (request, reply) => reply({ ok: true }),
            config: {
                plugins: {

                    rbac: (request, callback) => {

                        /* Usually retrieved from a DB... */
                        const policy = {
                            target: { 'credentials:username': 'sg1001' },
                            apply: 'permit-overrides',
                            rules: [
                                {
                                    'effect': 'deny'
                                }
                            ]
                        };

                        callback(null, policy);
                    }
                }
            }
        });

        server.inject({
            method: 'GET',
            url: '/disallow-username',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1001:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(401);

            done();
        });
    });

    test('Should have access to the route if no policy is configured', (done) => {

        server.route({
            method: 'GET',
            path: '/unrestricted-access',
            handler: (request, reply) => reply({ ok: true }),
            config: {
                plugins: {

                    rbac: (request, callback) => {

                        /* Usually retrieved from a DB... */
                        const policy = null;

                        callback(null, policy);
                    }
                }
            }
        });

        server.inject({
            method: 'GET',
            url: '/unrestricted-access',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1001:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(200);
            expect(response.result.ok).to.exist().and.equal(true);

            done();
        });
    });

});


experiment('Setting configurable response code for deny case', () => {

    let server;

    before((done) => {
        // Set up the hapi server route
        server = new Hapi.Server();

        server.connection();

        const users = { };

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

        server.register([
            {
                register: require('hapi-auth-basic')
            },
            {
                register: require('../'),
                options: {
                    responseCode: {
                        onDeny: 403
                    }
                }
            }
        ], (err) => {

            if (err) {
                return done(err);
            }

            server.auth.strategy('default', 'basic', 'required', {
                validateFunc: (request, username, password, callback) => {

                    if (!users[username] || users[username].password !== password) {
                        return callback(Boom.unauthorized('Wrong credentials'), false);
                    }

                    callback(null, true, users[username]);
                }
            });

            done();

        });

    });

    test('The access should be denied (request do apply to the target)', (done) => {

        server.route({
            method: 'GET',
            path: '/access-denied',
            handler: (request, reply) => reply({ ok: true }),
            config: {
                plugins: {

                    rbac: (request, callback) => {

                        /* Usually retrieved from a DB... */
                        const policy = {
                            target: { 'credentials:username': 'sg1001' },
                            apply: 'permit-overrides',
                            rules: [
                                {
                                    'effect': 'deny'
                                }
                            ]
                        };

                        callback(null, policy);
                    }
                }
            }
        });

        server.inject({
            method: 'GET',
            url: '/access-denied',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1001:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(403);

            done();
        });
    });


    test('The access should be denied (request do not apply to the target)', (done) => {

        server.route({
            method: 'GET',
            path: '/access-undetermined',
            handler: (request, reply) => reply({ ok: true }),
            config: {
                plugins: {

                    rbac: (request, callback) => {

                        /* Usually retrieved from a DB... */
                        const policy = {
                            target: { 'credentials:username': 'sg1001' },
                            apply: 'permit-overrides',
                            rules: [
                                {
                                    'effect': 'deny'
                                }
                            ]
                        };

                        callback(null, policy);
                    }
                }
            }
        });

        server.inject({
            method: 'GET',
            url: '/access-undetermined',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(401);

            done();
        });
    });
});

experiment('Setting configurable response code for undetermined case', () => {

    let server;

    before((done) => {
        // Set up the hapi server route
        server = new Hapi.Server();

        server.connection();

        const users = { };

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

        server.register([
            {
                register: require('hapi-auth-basic')
            },
            {
                register: require('../'),
                options: {
                    responseCode: {
                        onUndetermined: 403
                    }
                }
            }
        ], (err) => {

            if (err) {
                return done(err);
            }

            server.auth.strategy('default', 'basic', 'required', {
                validateFunc: (request, username, password, callback) => {

                    if (!users[username] || users[username].password !== password) {
                        return callback(Boom.unauthorized('Wrong credentials'), false);
                    }

                    callback(null, true, users[username]);
                }
            });

            done();

        });

    });

    test('The access should be denied (request do apply to the target)', (done) => {

        server.route({
            method: 'GET',
            path: '/access-denied',
            handler: (request, reply) => reply({ ok: true }),
            config: {
                plugins: {

                    rbac: (request, callback) => {

                        /* Usually retrieved from a DB... */
                        const policy = {
                            target: { 'credentials:username': 'sg1001' },
                            apply: 'permit-overrides',
                            rules: [
                                {
                                    'effect': 'deny'
                                }
                            ]
                        };

                        callback(null, policy);
                    }
                }
            }
        });

        server.inject({
            method: 'GET',
            url: '/access-denied',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1001:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(401);

            done();
        });
    });


    test('The access should be denied (request do not apply to the target)', (done) => {

        server.route({
            method: 'GET',
            path: '/access-undetermined',
            handler: (request, reply) => reply({ ok: true }),
            config: {
                plugins: {

                    rbac: (request, callback) => {

                        /* Usually retrieved from a DB... */
                        const policy = {
                            target: { 'credentials:username': 'sg1001' },
                            apply: 'permit-overrides',
                            rules: [
                                {
                                    'effect': 'deny'
                                }
                            ]
                        };

                        callback(null, policy);
                    }
                }
            }
        });

        server.inject({
            method: 'GET',
            url: '/access-undetermined',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(403);

            done();
        });
    });
});

experiment('Setting configurable response code for both undetermined and deny case', () => {

    let server;

    before((done) => {
        // Set up the hapi server route
        server = new Hapi.Server();

        server.connection();

        const users = { };

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

        server.register([
            {
                register: require('hapi-auth-basic')
            },
            {
                register: require('../'),
                options: {
                    responseCode: {
                        onDeny: 403,
                        onUndetermined: 403
                    }
                }
            }
        ], (err) => {

            if (err) {
                return done(err);
            }

            server.auth.strategy('default', 'basic', 'required', {
                validateFunc: (request, username, password, callback) => {

                    if (!users[username] || users[username].password !== password) {
                        return callback(Boom.unauthorized('Wrong credentials'), false);
                    }

                    callback(null, true, users[username]);
                }
            });

            done();

        });

    });

    test('The access should be denied (request do apply to the target)', (done) => {

        server.route({
            method: 'GET',
            path: '/access-denied',
            handler: (request, reply) => reply({ ok: true }),
            config: {
                plugins: {

                    rbac: (request, callback) => {

                        /* Usually retrieved from a DB... */
                        const policy = {
                            target: { 'credentials:username': 'sg1001' },
                            apply: 'permit-overrides',
                            rules: [
                                {
                                    'effect': 'deny'
                                }
                            ]
                        };

                        callback(null, policy);
                    }
                }
            }
        });

        server.inject({
            method: 'GET',
            url: '/access-denied',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1001:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(403);

            done();
        });
    });


    test('The access should be denied (request do not apply to the target)', (done) => {

        server.route({
            method: 'GET',
            path: '/access-undetermined',
            handler: (request, reply) => reply({ ok: true }),
            config: {
                plugins: {

                    rbac: (request, callback) => {

                        /* Usually retrieved from a DB... */
                        const policy = {
                            target: { 'credentials:username': 'sg1001' },
                            apply: 'permit-overrides',
                            rules: [
                                {
                                    'effect': 'deny'
                                }
                            ]
                        };

                        callback(null, policy);
                    }
                }
            }
        });

        server.inject({
            method: 'GET',
            url: '/access-undetermined',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(403);

            done();
        });
    });
});

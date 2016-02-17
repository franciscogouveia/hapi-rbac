'use strict';

const Hapi = require('hapi');
const Boom = require('boom');
const Joi = require('joi');
const Code = require('code');
const Lab = require('lab');

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

        users.sg1002 = {
            'scope': 'admin',
            'firstName': 'Some',
            'lastName': 'Other Guy',
            'username': 'sg1002',
            'password': 'pwtest',
            'group': ['reader']
        };

        server.register([
            {
                register: require('hapi-auth-basic')
            },
            {
                register: require('../'),
                options: {
                    policy: {
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

            // No policy configured -> use global configuration
            server.route({
                method: 'GET',
                path: '/endpoint',
                handler: (request, reply) => reply({ ok: true })
            });

            // Policy configured -> use route configuration (ignore global configuration)
            server.route({
                method: 'GET',
                path: '/overriden-policy',
                handler: (request, reply) => reply({ ok: true }),
                config: {
                    plugins: {
                        rbac: {
                            target: { 'credentials:username': 'sg1002' },
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
                handler: (request, reply) => reply({ ok: true }),
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
                handler: (request, reply) => reply({ ok: true }),
                config: {
                    plugins: {
                        rbac: {
                            apply: 'deny-overrides',
                            rules: [
                                {
                                    target: { 'params:param1': 'forbiddenParam' },
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
                handler: (request, reply) => reply({ ok: true }),
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
                                    target: { 'query:param1': 'forbiddenParam' },
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
                handler: (request, reply) => reply({ ok: true }),
                config: {
                    plugins: {
                        rbac: {
                            apply: 'deny-overrides',
                            rules: [
                                {
                                    target: { 'request:method': 'get' },
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
                handler: (request, reply) => reply({ ok: true }),
                config: {
                    plugins: {
                        rbac: {
                            apply: 'deny-overrides',
                            rules: [
                                {
                                    target: { 'request:method': 'post' },
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
                handler: (request, reply) => reply({ ok: true }),
                config: {
                    plugins: {
                        rbac: {
                            apply: 'permit-overrides',
                            rules: [
                                {   // Invalid field
                                    target: { 'request:somefield': 'test' },
                                    'effect': 'permit'
                                },
                                {   // Invalid data source
                                    target: { 'somesource:somefield': 'test' },
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

            done();

        });

    });

    test('Should have access to the route, with policy targeting the username', (done) => {

        server.inject({
            method: 'GET',
            url: '/endpoint',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1001:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(200);

            done();
        });
    });

    test('Should not have access to the route, with policy targeting the username', (done) => {

        server.inject({
            method: 'GET',
            url: '/endpoint',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(401);

            done();
        });
    });

    test('Should not have access to the route, with overriden policy targeting the username', (done) => {

        server.inject({
            method: 'GET',
            url: '/overriden-policy',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1001:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(401);

            done();
        });
    });

    test('Should have access to the route, with overriden policy targeting the username', (done) => {

        server.inject({
            method: 'GET',
            url: '/overriden-policy',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(200);

            done();
        });
    });


    test('Should allow access to the route with params', (done) => {

        server.inject({
            method: 'GET',
            url: '/route-params/validParam',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(200);

            done();
        });
    });

    test('Should deny access to the route with denied param', (done) => {

        server.inject({
            method: 'GET',
            url: '/route-params/forbiddenParam',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(401);

            done();
        });
    });


    test('Should allow access to the route with query param', (done) => {

        server.inject({
            method: 'GET',
            url: '/route-query-params?param1=validParam',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(200);

            done();
        });
    });

    test('Should deny access to the route with denied query param', (done) => {

        server.inject({
            method: 'GET',
            url: '/route-query-params?param1=forbiddenParam',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(401);

            done();
        });
    });

    test('Should deny access to the route with get request method', (done) => {

        server.inject({
            method: 'GET',
            url: '/route-request-get-deny',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(401);

            done();
        });
    });

    test('Should allow access to the route with get request method', (done) => {

        server.inject({
            method: 'GET',
            url: '/route-request-get-allow',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(200);

            done();
        });
    });

    test('Should deny access to the route with get request method', (done) => {

        server.inject({
            method: 'GET',
            url: '/route-non-existing-field',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
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
experiment('Global dynamic RBAC policy with callback function', () => {

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

        users.sg1002 = {
            'scope': 'admin',
            'firstName': 'Some',
            'lastName': 'Other Guy',
            'username': 'sg1002',
            'password': 'pwtest',
            'group': ['reader']
        };

        server.register([
            {
                register: require('hapi-auth-basic')
            },
            {
                register: require('../'),
                options: {
                    policy: (request, callback) => {

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

            // No policy configured -> use global configuration
            server.route({
                method: 'GET',
                path: '/endpoint',
                handler: (request, reply) => reply({ ok: true })
            });

            // Policy configured -> use route configuration (ignore global configuration)
            server.route({
                method: 'GET',
                path: '/overriden-policy',
                handler: (request, reply) => reply({ ok: true }),
                config: {
                    plugins: {
                        rbac: (request, callback) => {

                            /* Usually retrieved from a DB... */
                            const policy = {
                                target: { 'credentials:username': 'sg1002' },
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


            // Policy disabled -> do not use access control (ignore global configuration)
            server.route({
                method: 'GET',
                path: '/disabled-ac',
                handler: (request, reply) => reply({ ok: true }),
                config: {
                    plugins: {
                        rbac: 'none'
                    }
                }
            });


            done();

        });

    });

    test('Should have access to the route, with policy targeting the username', (done) => {

        server.inject({
            method: 'GET',
            url: '/endpoint',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1001:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(200);

            done();
        });
    });

    test('Should not have access to the route, with policy targeting the username', (done) => {

        server.inject({
            method: 'GET',
            url: '/endpoint',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(401);

            done();
        });
    });

    test('Should not have access to the route, with overriden policy targeting the username', (done) => {

        server.inject({
            method: 'GET',
            url: '/overriden-policy',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1001:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(401);

            done();
        });
    });

    test('Should have access to the route, with overriden policy targeting the username', (done) => {

        server.inject({
            method: 'GET',
            url: '/overriden-policy',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(200);

            done();
        });
    });

    test('Should have access to the route, with disabled ac', (done) => {

        server.inject({
            method: 'GET',
            url: '/disabled-ac',
            headers: {
                authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(200);

            done();
        });
    });
});

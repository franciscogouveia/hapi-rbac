'use strict';

const Hapi = require('hapi');
const Boom = require('boom');
const Joi = require('joi');
const Code = require('code');
const Lab = require('lab');
const Hoek = require('hoek');

const lab = exports.lab = Lab.script();
const experiment = lab.experiment;
const test = lab.test;
const before = lab.before;

const expect = Code.expect;

/**
 * Rule based access control policy tests, based on username
 **/
experiment('User defined data retrievers', () => {

    let server;

    before((done) => {
        // Set up the hapi server route
        server = new Hapi.Server();

        server.connection();

        const users = { };

        users.user1 = {
            'scope': 'admin',
            'username': 'user1',
            'password': 'pwtest',
            'group': ['reader']
        };

        users.user2 = {
            'scope': 'admin',
            'username': 'user2',
            'password': 'pwtest',
            'group': ['reader']
        };

        // Can be in an external source (remote API, remote DB, etc)
        const configurations = { };
        configurations.user1 = {
            'username': 'user1',
            'blocked': false
        };
        configurations.user2 = {
            'username': 'user2',
            'blocked': true
        };

        server.register([
            {
                register: require('hapi-auth-basic')
            },
            {
                register: require('../'),
                options: {
                    dataRetrievers: [
                        {
                            handles: [
                                'configuration',
                                // Alias
                                'config'
                            ],
                            handler: (source, key, context, callback) => {

                                // In hapi-rbac, the context is always the Request object

                                // Can use the context to get info, such as current user's username
                                const username = Hoek.reach(context, 'auth.credentials.username');

                                const configuration = configurations[username];

                                if (!configuration) {
                                    // Configuration not found or invalid, pass nothing in callback
                                    return callback();
                                }

                                // Pass field value in the callback
                                callback(null, configuration[key]);
                            }
                        }
                    ]
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
                handler: (request, reply) => reply({ ok: true }),
                config: {
                    plugins: {
                        rbac: {
                            apply: 'permit-overrides',
                            rules: [
                                {
                                    target: { 'config:blocked': false },
                                    'effect': 'permit'
                                },
                                // By default deny
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

    test('should have access to the route', (done) => {

        server.inject({
            method: 'GET',
            url: '/endpoint',
            headers: {
                authorization: 'Basic ' + (new Buffer('user1:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(200);

            done();
        });
    });

    test('should not have access to the route', (done) => {

        server.inject({
            method: 'GET',
            url: '/endpoint',
            headers: {
                authorization: 'Basic ' + (new Buffer('user2:pwtest', 'utf8')).toString('base64')
            }
        }, (response) => {

            expect(response.statusCode).to.equal(401);

            done();
        });
    });
});

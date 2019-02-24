'use strict';

const Code = require('code');
const Lab = require('lab');
const Hoek = require('hoek');
const {createServer} = require('./helpers/server');

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

    before(async () => {
        const users = {};

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
        const configurations = {};
        configurations.user1 = {
            'username': 'user1',
            'blocked': false
        };
        configurations.user2 = {
            'username': 'user2',
            'blocked': true
        };

        // Set up the hapi server route
        server = await createServer(users, {
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
        });

        // No policy configured -> use global configuration
        server.route({
            method: 'GET',
            path: '/endpoint',
            handler: (request, h) => h.response({ok: true}),
            config: {
                plugins: {
                    rbac: {
                        apply: 'permit-overrides',
                        rules: [
                            {
                                target: {'config:blocked': false},
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
    });

    test('should have access to the route', async () => {
        const response = await server.inject({
            method: 'GET',
            url: '/endpoint',
            headers: {
                authorization: 'Basic ' + (new Buffer('user1:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(200);
    });

    test('should not have access to the route', async () => {

        const response = await server.inject({
            method: 'GET',
            url: '/endpoint',
            headers: {
                authorization: 'Basic ' + (new Buffer('user2:pwtest', 'utf8')).toString('base64')
            }
        });

        expect(response.statusCode).to.equal(401);
    });
});

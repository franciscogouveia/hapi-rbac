'use strict';

var Code = require('code');
var Lab = require('lab');

var lab = exports.lab = Lab.script();
var experiment = lab.experiment;
var test = lab.test;

var expect = Code.expect;

var Rbac = require('../');


experiment('Policy set unit tests', () => {

    var policySet = {
        target: ['any-of', { type: 'group', value: 'writer' }, { type: 'group', value: 'publisher' }], // writer OR publisher
        apply: 'permit-overrides', // deny, unless one permits
        policies: [
            {
                target: ['all-of', { type: 'group', value: 'writer' }, { type: 'premium', value: true }], // if writer AND premium account
                apply: 'deny-overrides', // permit, unless one denies
                rules: [
                    {
                        target: ['any-of', { type: 'username', value: 'bad_user' }], // if the username is bad_user
                        effect: 'deny'  // then deny
                    },
                    {
                        target: ['any-of', { type: 'blocked', value: true }], // if the user is blocked
                        effect: 'deny'  // then deny
                    },
                    {
                        effect: 'permit' // else permit
                    }
                ]
            },
            {
                target: ['all-of', { type: 'premium', value: false }], // if (writer OR publisher) AND no premium account
                apply: 'permit-overrides', // deny, unless one permits
                rules: [
                    {
                        target: ['any-of', { type: 'username', value: 'special_user' }], // if the username is special_user
                        effect: 'permit'  // then permit
                    },
                    {
                        effect: 'deny' // else deny
                    }
                ]
            }
        ]
    };

    test('should permit premium writer', (done) => {

        var information = {
            username: 'user00001',
            group: ['writer'],
            premium: true,
            blocked: false
        };

        Rbac.evaluatePolicy(policySet, information, (err, applies) => {

            expect(err).to.not.exist();

            expect(applies).to.exist().and.to.equal(Rbac.PERMIT);

            done();
        });
    });

    test('should deny blocked premium writer', (done) => {

        var information = {
            username: 'bad_user',
            group: ['writer'],
            premium: true,
            blocked: false
        };

        Rbac.evaluatePolicy(policySet, information, (err, applies) => {

            expect(err).to.not.exist();

            expect(applies).to.exist().and.to.equal(Rbac.DENY);

            done();
        });
    });

    test('should deny publisher without premium', (done) => {

        var information = {
            username: 'user00002',
            group: ['publisher'],
            premium: false,
            blocked: false
        };

        Rbac.evaluatePolicy(policySet, information, (err, applies) => {

            expect(err).to.not.exist();

            expect(applies).to.exist().and.to.equal(Rbac.DENY);

            done();
        });
    });

    test('should permit special publisher without premium', (done) => {

        var information = {
            username: 'special_user',
            group: ['publisher'],
            premium: false,
            blocked: false
        };

        Rbac.evaluatePolicy(policySet, information, (err, applies) => {

            expect(err).to.not.exist();

            expect(applies).to.exist().and.to.equal(Rbac.PERMIT);

            done();
        });
    });

    test('should permit special writer without premium', (done) => {

        var information = {
            username: 'special_user',
            group: ['writer'],
            premium: false,
            blocked: false
        };

        Rbac.evaluatePolicy(policySet, information, (err, applies) => {

            expect(err).to.not.exist();

            expect(applies).to.exist().and.to.equal(Rbac.PERMIT);

            done();
        });
    });

    test('should permit special publisher and writer without premium', (done) => {

        var information = {
            username: 'special_user',
            group: ['writer', 'publisher'],
            premium: false,
            blocked: false
        };

        Rbac.evaluatePolicy(policySet, information, (err, applies) => {

            expect(err).to.not.exist();

            expect(applies).to.exist().and.to.equal(Rbac.PERMIT);

            done();
        });
    });

    test('should deny publisher with premium', (done) => {

        var information = {
            username: 'user00003',
            group: ['publisher'],
            premium: true,
            blocked: false
        };

        Rbac.evaluatePolicy(policySet, information, (err, applies) => {

            expect(err).to.not.exist();

            expect(applies).to.exist().and.to.equal(Rbac.DENY);

            done();
        });
    });

});

'use strict';

const Code = require('code');
const Lab = require('lab');

const lab = exports.lab = Lab.script();
const experiment = lab.experiment;
const test = lab.test;

const expect = Code.expect;

const Rbac = require('../');


experiment('Rule unit tests (permit)', () => {

    const rule = {
        target: ['all-of', { type: 'group', value: 'administrator' }, { type: 'group', value: 'publisher' }],
        effect: 'permit'
    };

    test('should permit publisher administrator', (done) => {

        const information = {
            username: 'user00001',
            group: ['administrator', 'publisher']
        };

        Rbac.evaluatePolicy(rule, information, (err, result) => {

            expect(err).to.not.exist();

            expect(result).to.exist().and.to.equal(Rbac.PERMIT);

            done();
        });
    });

    test('should be undetermined access to publisher', (done) => {

        const information = {
            username: 'user00002',
            group: ['publisher']
        };

        Rbac.evaluatePolicy(rule, information, (err, result) => {

            expect(err).to.not.exist();

            expect(result).to.exist().and.to.equal(Rbac.UNDETERMINED);

            done();
        });
    });

    test('should be undetermined access to administrator', (done) => {

        const information = {
            username: 'user00003',
            group: ['administrator']
        };

        Rbac.evaluatePolicy(rule, information, (err, result) => {

            expect(err).to.not.exist();

            expect(result).to.exist().and.to.equal(Rbac.UNDETERMINED);

            done();
        });
    });

});

experiment('Rule unit tests (deny)', () => {

    const rule = {
        target: ['any-of', { type: 'group', value: 'blacklist' }, { type: 'group', value: 'anonymous' }, {
            type: 'verified',
            value: false
        }],
        effect: 'deny'
    };

    test('should deny user in blacklist group', (done) => {

        const information = {
            username: 'user00001',
            group: ['blacklist', 'publisher'],
            verified: true
        };

        Rbac.evaluatePolicy(rule, information, (err, result) => {

            expect(err).to.not.exist();

            expect(result).to.exist().and.to.equal(Rbac.DENY);

            done();
        });
    });

    test('should deny user in anonymous group', (done) => {

        const information = {
            username: 'user00001',
            group: ['anonymous'],
            verified: true
        };

        Rbac.evaluatePolicy(rule, information, (err, result) => {

            expect(err).to.not.exist();

            expect(result).to.exist().and.to.equal(Rbac.DENY);

            done();
        });
    });

    test('should deny not verified user', (done) => {

        const information = {
            username: 'user00001',
            group: ['administrator', 'publisher'],
            verified: false
        };

        Rbac.evaluatePolicy(rule, information, (err, result) => {

            expect(err).to.not.exist();

            expect(result).to.exist().and.to.equal(Rbac.DENY);

            done();
        });
    });

    test('should be undetermined', (done) => {

        const information = {
            username: 'user00001',
            group: ['administrator', 'publisher'],
            verified: true
        };

        Rbac.evaluatePolicy(rule, information, (err, result) => {

            expect(err).to.not.exist();

            expect(result).to.exist().and.to.equal(Rbac.UNDETERMINED);

            done();
        });
    });

});

'use strict';

var Code = require('code');
var Lab = require('lab');

var lab = exports.lab = Lab.script();
var experiment = lab.experiment;
var test = lab.test;

var expect = Code.expect;

var Rbac = require('../');


experiment('Target unit tests (all-of)', function () {

    var target = ['all-of', { type: 'group', value: 'writer' }, { type: 'premium', value: true }];

    test('should apply (full match)', function (done) {

        var information = {
            username: 'user00001',
            group: ['writer'],
            premium: true
        };

        Rbac.evaluateTarget(target, information, function (err, applies) {

            expect(err).to.not.exist();

            expect(applies).to.exist().and.to.equal(true);

            done();
        });
    });

    test('should not apply (partial match)', function (done) {

        var information = {
            username: 'user00002',
            group: ['writer'],
            premium: false
        };

        Rbac.evaluateTarget(target, information, function (err, applies) {

            expect(err).to.not.exist();

            expect(applies).to.exist().and.to.equal(false);

            done();
        });
    });

    test('should not apply (no match)', function (done) {

        var information = {
            username: 'user00003',
            group: ['reader'],
            premium: false
        };

        Rbac.evaluateTarget(target, information, function (err, applies) {

            expect(err).to.not.exist();

            expect(applies).to.exist().and.to.equal(false);

            done();
        });
    });

});

experiment('Target unit tests (any-of)', function () {

    var target = ['any-of', { type: 'group', value: 'writer' }, { type: 'premium', value: true }, {
        type: 'username',
        value: 'user00002'
    }];

    test('should apply (partial match)', function (done) {

        var information = {
            username: 'user00001', // do not match
            group: ['writer'],
            premium: true
        };

        Rbac.evaluateTarget(target, information, function (err, applies) {

            expect(err).to.not.exist();

            expect(applies).to.exist().and.to.equal(true);

            done();
        });
    });

    test('should apply (full match)', function (done) {

        var information = {
            username: 'user00002',
            group: ['writer'],
            premium: true
        };

        Rbac.evaluateTarget(target, information, function (err, applies) {

            expect(err).to.not.exist();

            expect(applies).to.exist().and.to.equal(true);

            done();
        });
    });

    test('should not apply (no match)', function (done) {

        var information = {
            username: 'user00003',
            group: ['reader'],
            premium: false
        };

        Rbac.evaluateTarget(target, information, function (err, applies) {

            expect(err).to.not.exist();

            expect(applies).to.exist().and.to.equal(false);

            done();
        });
    });

});

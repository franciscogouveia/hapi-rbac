'use strict';

const Hapi = require('hapi');
const Boom = require('boom');
const Code = require('code');
const Lab = require('lab');
const Rbac = require('../');

const lab = exports.lab = Lab.script();
const experiment = lab.experiment;
const test = lab.test;
const before = lab.before;

const expect = Code.expect;

/**
 * Rule based access control policy tests, based on username
 **/
experiment('RBAC internal modular information retrieval', () => {

    test('should register a valid retriever', (done) => {

        const retriever = (source, key, request) => {
            return 'key-' + key;
        };

        Rbac.registerDataRetriever('test', retriever);

        expect(Rbac.retrieveData('test:x', {})).to.equal('key-x');

        done();
    });

    test('should override a valid retriever (single handler)', (done) => {

        const retriever1 = (source, key, request) => {
            return key + '-1';
        };

        const retriever2 = (source, key, request) => {
            return key + '-2';
        };

        Rbac.registerDataRetriever('test-override', retriever1);
        Rbac.registerDataRetriever('test-override', retriever2, {override: true});

        expect(Rbac.retrieveData('test-override:test', {})).to.equal('test-2');

        done();
    });

    test('should not override a valid retriever (single handler)', (done) => {

        const retriever1 = (source, key, request) => {
            return key + '-1';
        };

        const retriever2 = (source, key, request) => {
            return key + '-2';
        };

        Rbac.registerDataRetriever('test-override-error', retriever1);

        expect(Rbac.registerDataRetriever.bind(null, 'test-override-error', retriever2)).to.throw();

        done();
    });

    test('should override a valid retriever (multiple handlers)', (done) => {

        const retriever1 = (source, key, request) => {
            return key + '-1';
        };

        const retriever2 = (source, key, request) => {
            return key + '-2';
        };

        Rbac.registerDataRetriever(['test-override-multiple-1', 'test-override-multiple-2', 'test-override-multiple-3'], retriever1);
        Rbac.registerDataRetriever(['test-override-multiple-2', 'test-override-multiple-4'], retriever2, {override: true}); // test-override-multiple-2 collides

        expect(Rbac.retrieveData('test-override-multiple-1:test', {})).to.equal('test-1');
        expect(Rbac.retrieveData('test-override-multiple-2:test', {})).to.equal('test-2');
        expect(Rbac.retrieveData('test-override-multiple-3:test', {})).to.equal('test-1');
        expect(Rbac.retrieveData('test-override-multiple-4:test', {})).to.equal('test-2');

        done();
    });

    test('should not override a valid retriever (multiple handlers)', (done) => {

        const retriever1 = (source, key, request) => {
            return key + '-1';
        };

        const retriever2 = (source, key, request) => {
            return key + '-2';
        };

        Rbac.registerDataRetriever(['test-override-error-multiple-1', 'test-override-error-multiple-2', 'test-override-error-multiple-3'], retriever1);
        expect(Rbac.registerDataRetriever.bind(null, ['test-override-error-multiple-2', 'test-override-error-multiple-4'], retriever2)).to.throw(Error, 'There is a data retriever already registered for the source: test-override-error-multiple-2');

        done();
    });

});

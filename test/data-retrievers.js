'use strict';

const Hapi = require('hapi');
const Boom = require('boom');
const Code = require('code');
const Lab = require('lab');
const Rbac = require('../');
const DataRetrievalRouter = Rbac.DataRetrievalRouter;

const lab = exports.lab = Lab.script();
const experiment = lab.experiment;
const test = lab.test;
const before = lab.before;

const expect = Code.expect;

/**
 * Rule based access control policy tests, based on username
 **/
experiment('RBAC internal modular information retrieval', () => {

    const dataRetriever = new DataRetrievalRouter();

    test('should register a valid retriever', (done) => {

        const retriever = (source, key, context) => {
            return 'key-' + key;
        };

        dataRetriever.register('test', retriever);

        expect(dataRetriever.get('test:x')).to.equal('key-x');

        done();
    });

    test('should override a valid retriever (single handler)', (done) => {

        const retriever1 = (source, key, context) => {
            return key + '-1';
        };

        const retriever2 = (source, key, context) => {
            return key + '-2';
        };

        dataRetriever.register('test-override', retriever1);
        dataRetriever.register('test-override', retriever2, {override: true});

        expect(dataRetriever.get('test-override:test', {})).to.equal('test-2');

        done();
    });

    test('should not override a valid retriever (single handler)', (done) => {

        const retriever1 = (source, key, context) => {
            return key + '-1';
        };

        const retriever2 = (source, key, context) => {
            return key + '-2';
        };

        dataRetriever.register('test-override-error', retriever1);

        expect(dataRetriever.register.bind(dataRetriever, 'test-override-error', retriever2)).to.throw();

        done();
    });

    test('should override a valid retriever (multiple handlers)', (done) => {

        const retriever1 = (source, key, context) => {
            return key + '-1';
        };

        const retriever2 = (source, key, context) => {
            return key + '-2';
        };

        dataRetriever.register(['test-override-multiple-1', 'test-override-multiple-2', 'test-override-multiple-3'], retriever1);
        dataRetriever.register(['test-override-multiple-2', 'test-override-multiple-4'], retriever2, {override: true}); // test-override-multiple-2 collides

        expect(dataRetriever.get('test-override-multiple-1:test', {})).to.equal('test-1');
        expect(dataRetriever.get('test-override-multiple-2:test', {})).to.equal('test-2');
        expect(dataRetriever.get('test-override-multiple-3:test', {})).to.equal('test-1');
        expect(dataRetriever.get('test-override-multiple-4:test', {})).to.equal('test-2');

        done();
    });

    test('should not override a valid retriever (multiple handlers)', (done) => {

        const retriever1 = (source, key, context) => {
            return key + '-1';
        };

        const retriever2 = (source, key, context) => {
            return key + '-2';
        };

        dataRetriever.register(['test-override-error-multiple-1', 'test-override-error-multiple-2', 'test-override-error-multiple-3'], retriever1);
        expect(dataRetriever.register.bind(dataRetriever, ['test-override-error-multiple-2', 'test-override-error-multiple-4'], retriever2)).to.throw(Error, 'There is a data retriever already registered for the source: test-override-error-multiple-2');

        done();
    });

});

'use strict';

var Code = require('code');
var Lab = require('lab');

var lab = exports.lab = Lab.script();
var experiment = lab.experiment;
var test = lab.test;

var expect = Code.expect;

var rbac = require('../');


experiment("Rule unit tests (permit)", function() {

  var rule = {
    target: ['all-of', {type: 'group', value: 'administrator'}, {type: 'group', value: 'publisher'}],
    effect: 'permit'
  };

  test("should permit publisher administrator", function(done) {

    var information = {
      username: 'user00001',
      group: ['administrator', 'publisher']
    };

    rbac.evaluatePolicy(rule, information, function(err, result) {

      expect(err).to.not.exist();

      expect(result).to.exist().and.to.equal(rbac.PERMIT);

      done();
    });
  });

  test("should be undetermined access to publisher", function(done) {

    var information = {
      username: 'user00002',
      group: ['publisher']
    };

    rbac.evaluatePolicy(rule, information, function(err, result) {

      expect(err).to.not.exist();

      expect(result).to.exist().and.to.equal(rbac.UNDETERMINED);

      done();
    });
  });

  test("should be undetermined access to administrator", function(done) {

    var information = {
      username: 'user00003',
      group: ['administrator']
    };

    rbac.evaluatePolicy(rule, information, function(err, result) {

      expect(err).to.not.exist();

      expect(result).to.exist().and.to.equal(rbac.UNDETERMINED);

      done();
    });
  });

});

experiment("Rule unit tests (deny)", function() {

  var rule = {
    target: ['any-of', {type: 'group', value: 'blacklist'}, {type: 'group', value: 'anonymous'}, {type: 'verified', value: false}],
    effect: 'deny'
  };

  test("should deny user in blacklist group", function(done) {

    var information = {
      username: 'user00001',
      group: ['blacklist', 'publisher'],
      verified: true
    };

    rbac.evaluatePolicy(rule, information, function(err, result) {

      expect(err).to.not.exist();

      expect(result).to.exist().and.to.equal(rbac.DENY);

      done();
    });
  });

  test("should deny user in anonymous group", function(done) {

    var information = {
      username: 'user00001',
      group: ['anonymous'],
      verified: true
    };

    rbac.evaluatePolicy(rule, information, function(err, result) {

      expect(err).to.not.exist();

      expect(result).to.exist().and.to.equal(rbac.DENY);

      done();
    });
  });

  test("should deny not verified user", function(done) {

    var information = {
      username: 'user00001',
      group: ['administrator', 'publisher'],
      verified: false
    };

    rbac.evaluatePolicy(rule, information, function(err, result) {

      expect(err).to.not.exist();

      expect(result).to.exist().and.to.equal(rbac.DENY);

      done();
    });
  });

  test("should be undetermined", function(done) {

    var information = {
      username: 'user00001',
      group: ['administrator', 'publisher'],
      verified: true
    };

    rbac.evaluatePolicy(rule, information, function(err, result) {

      expect(err).to.not.exist();

      expect(result).to.exist().and.to.equal(rbac.UNDETERMINED);

      done();
    });
  });

});

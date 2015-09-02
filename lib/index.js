'use strict';

var async = require('async');
var Boom = require('boom');

var
  DENY = 0,
  PERMIT = 1,
  UNDETERMINED = 3;

var internals = {};

exports.register = function(server, options, next) {

  server.ext('onPostAuth', function(request, reply) {

    if(request.route.settings.plugins.rbac) {
      return internals.evaluatePolicy(request.route.settings.plugins.rbac, request.auth.credentials, function(err, result) {

        if(err) {
          return reply(err);
        }

        if(result === DENY) {
          return reply(Boom.unauthorized('No permissions to access this resource'));
        }

        if(result === UNDETERMINED) {
          return reply(Boom.unauthorized('Could not evaluate access rights to resource'));
        }

        reply.continue();
      });
    }

    reply.continue();
  });

  next();
};

exports.register.attributes = {
  pkg: require('../package.json')
};


/**
 * Evaluate a single Policy of PolicySet
 *
 **/
internals.evaluatePolicy = function(item, information, callback) {
  if(!item) {
    return callback(Boom.badImplementation('RBAC configuration error: null item'));
  }

  if(!item.apply) {
    item.apply = 'permit-overrides';
  }

  if(!(item.apply instanceof Function)) {
    if(!internals.combineAlg[item.apply]) {
      return callback(Boom.badImplementation('RBAC error: combinatory algorithm does not exist: ' + item.apply));
    }

    item.apply = internals.combineAlg[item.apply];
  }

  internals.evaluateTarget(item.target, information, function(err, applies) {

    if(err) {
      return callback(err);
    }

    if(!applies) {
      return callback(null, UNDETERMINED);
    }

    // Policy set
    if(item.policies) {

      return  item.apply(item.policies, information, internals.evaluatePolicy, callback);
    }

    // Policy
    if(item.rules) {

      return item.apply(item.rules, information, internals.evaluateRule, callback);
    }

    // Rule
    internals.evaluateRule(item, information, callback);
  });
};


/**
 * Evaluate a single rule.
 *
 * {
 *    'target': ['any-of', item1, ..., itemN],
 *    'effect': PERMIT, DENY
 * }
 **/
internals.evaluateRule = function(rule, information, callback) {
  if(!rule) {
    return callback(Boom.badImplementation('RBAC rule is missing'));
  }

  internals.evaluateTarget(rule.target, information, function(err, applies) {

    if(err) {
      return callback(err);
    }

    if(!applies) {
      return callback(null, UNDETERMINED);
    }

    switch(rule.effect) {
      case 'permit':
      case PERMIT:
        return callback(null, PERMIT);
      case 'deny':
      case DENY:
        return callback(null, DENY);
      default:
        return callback(Boom.badImplementation('RBAC rule error: invalid effect ' + rule.effect));
    }
  });
};

/**
 * Evaluate a target
 * ['any-of', {type: 'username', value:'francisco'}, {type: 'group', value:'admin'}]
 * ['all-of', {type: 'username', value:'francisco'}, {type: 'group', value:'admin'}]
 **/
internals.evaluateTarget = function(target, information, callback) {

  if(!target) {
    // Applies by default, when no target is defined
    return callback(null, true);
  }

  if( !(target instanceof Array) || target.length < 2) {
    return callback(Boom.badImplementation('RBAC target error: invalid format. Should be an array with match type and items ["all-of", item1, item2, ..., itemN]'));
  }

  for(var i = 1; i < target.length; i++) {
    var result = _targetApplies(target[i].value, information[target[i].type]);

    if(result && target[0] === 'any-of') {
      return callback(null, true);
    }

    if(!result && target[0] === 'all-of') {
      return callback(null, false);
    }
  }

  return callback(null, target[0] === 'all-of');
};

function _targetApplies(target, value) {
  if(target === value) {
    return true;
  }

  if(value instanceof Array) {
    if(value.indexOf(target) !== -1) {
      return true;
    }
  }

  return false;
}

/**
 * Combinator algorithms:
 *
 *   - permit-overrides - If at least one permit is evaluated, then permit
 *   - deny-overrides - If at least one deny is evaluated, then deny
 *   - only-one-applicable -
 *   - first-applicable - Only evaluate the first applicable rule
 **/
internals.combineAlg = {};

internals.combineAlg['permit-overrides'] = function(items, information, fn, callback) {
  if(!items || items.length === 0) {
    return callback(null, UNDETERMINED);
  }

  var tasks = [];

  for(var i = 0; i <  items.length; i++) {
    tasks.push(fn.bind(null, items[i], information));
  }

  async.parallel(tasks, function(err, results) {

    if(err) {
      return callback(err);
    }

    for(var i = 0; i < results.length; i++) {
      if(results[i] === PERMIT) {
        return callback(null, PERMIT);
      }
    }

    callback(null, DENY);
  });
};

internals.combineAlg['deny-overrides'] = function(items, information, fn, callback) {
  if(!items || items.length === 0) {
    return callback(null, UNDETERMINED);
  }

  var tasks = [];

  for(var i = 0; i <  items.length; i++) {
    tasks.push(fn.bind(null, items[i], information));
  }

  async.parallel(tasks, function(err, results) {

    if(err) {
      return callback(err);
    }

    for(var i = 0; i < results.length; i++) {
      if(results[i] === DENY) {
        return callback(null, DENY);
      }
    }

    callback(null, PERMIT);
  });
};

if(['test', 'development'].indexOf(process.env.NODE_ENV) !== -1) {

  // To run the lab tests
  exports.evaluateTarget = internals.evaluateTarget;
  exports.evaluatePolicy = internals.evaluatePolicy;
  exports.evaluateRule = internals.evaluateRule;

  exports.PERMIT = PERMIT;
  exports.DENY = DENY;
  exports.UNDETERMINED = UNDETERMINED;
}

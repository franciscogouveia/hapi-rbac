'use strict';

const Async = require('async');
const Boom = require('boom');
const Joi = require('joi');
const Hoek = require('hoek');

const DENY = 0;
const PERMIT = 1;
const UNDETERMINED = 3;

const CONFIG_NONE = 'none';

const internals = {};
const schemas = {};
const defaults = {};

schemas.policyRetriever = Joi.func();
schemas.policy = Joi.object();

/**
 * Data retriever router object constructor.
 *
 * This object allows to register data retrieval handlers to obtain data form different sources.
 **/
const DataRetrievalRouter = function(options) {
    options = options || {};
    Joi.assert(options, schemas.DataRetrievalRouter_options);

    this.options = options;
    this.retrievers = {};
    this.parent = options.parent;
    this.context = options.context;
};
schemas.DataRetrievalRouter_options = Joi.object({
    override: Joi.boolean().optional(),
    parent: Joi.object().type(DataRetrievalRouter).optional(),
    context: Joi.object().optional()
}).unknown(false);

DataRetrievalRouter.prototype.createChild = function(context) {
    const options = Hoek.applyToDefaults(this.options, {
        parent: this,
        context: context
    });
    return new DataRetrievalRouter(options);
};

/**
 * Register a data retriever.
 *
 * * handles - A string or array of strings specifying what this component retrieves (source of data, e.g. 'credentials')
 * * retriever - A function which returns data, according to a key. Function signature is (source:string, key:string, context:object) => String
 * * options - (optional) A JSON with the following options:
 *   * override - When true, overrides existent handler if exists. When false, throws an error when a repeated handler is used. (default: false)
 **/
DataRetrievalRouter.prototype.register = function (handles, retriever, options) {
    Joi.assert(handles, schemas.DataRetrievalRouter_register_handles);
    Joi.assert(retriever, schemas.DataRetrievalRouter_register_retriever);
    options = options || {};
    Joi.assert(options, schemas.DataRetrievalRouter_register_options);
    options = Hoek.applyToDefaults(defaults.DataRetrievalRouter_register_options, options);

    if(handles instanceof Array) {
        handles.forEach((source) => this._register(source, retriever, options));
    } else {
        this._register(handles, retriever, options);
    }

    return this;
};
schemas.DataRetrievalRouter_register_handles = Joi.alternatives().try(
    Joi.string().min(1),
    Joi.array().items(Joi.string().min(1))
);
schemas.DataRetrievalRouter_register_retriever = Joi.func().arity(3);
schemas.DataRetrievalRouter_register_options = Joi.object({
    override: Joi.boolean().optional()
}).unknown(false);

defaults.DataRetrievalRouter_register_options = {
    override: false
};

DataRetrievalRouter.prototype._register = function (handles, retriever, options) {
    if(this.retrievers[handles] && !options.override) {
        throw new Error('There is a data retriever already registered for the source: ' + handles);
    }

    this.retrievers[handles] = retriever;
};

/**
 * Obtain data from a retriever.
 *
 * * source - E.g. 'credentials' to obtain data from credentials document
 * * key - Key value from the source (e.g. 'username')
 * * context - Context object. Contains the request object.
 **/
DataRetrievalRouter.prototype.get = function (key, context) {
    Joi.assert(key, schemas.DataRetrievalRouter_get_key);
    let source;

    if(key.indexOf(':') === -1) {
        source = 'credentials'; // keep it backwards compatible
    } else {
        const split_key = key.split(':');
        source = split_key[0];
        key = split_key[1];
    }

    Joi.assert(key, schemas.DataRetrievalRouter_get_key);
    Joi.assert(source, schemas.DataRetrievalRouter_get_source);

    if(!this.retrievers[source]) {
        if(!this.parent) {
            return null;
        }
        return this.parent.get(key, context || this.context);
    }

    return this.retrievers[source](source, key, context || this.context);
};
schemas.DataRetrievalRouter_get_source = Joi.string().min(1);
schemas.DataRetrievalRouter_get_key = Joi.string().min(1);


// Default data retrievers
defaults.credentialsRetriever = function (source, key, context) {
    if(!context || !context.auth || !context.auth.credentials) {
        return null;
    }

    return context.auth.credentials[key];
};


/**
 * Hapi register function
 **/
schemas.register_options = Joi.object({
    policy: Joi.alternatives().try(
            schemas.policyRetriever,
            schemas.policy
        ).optional(),
    dataRetrievers: Joi.array().items(
        Joi.object({
            handles: schemas.DataRetrievalRouter_register_handles.required()
        })
    ).optional()
});

exports.register = (server, options, next) => {

    Joi.assert(options, schemas.register_options);

    const dataRetriever = new DataRetrievalRouter();
    dataRetriever.register('credentials', defaults.credentialsRetriever);

    server.ext('onPostAuth', (request, reply) => {

        let config = request.route.settings.plugins.rbac || options.policy;

        if (config && config !== CONFIG_NONE) {

            return internals.retrievePolicy(config, request, (err, policy) => {

                if (err) {
                    return reply(err);
                }

                if (!policy || policy === CONFIG_NONE) {
                    return reply.continue();
                }

                // Add context to data retriever's child
                const wrappedDataRetriever = dataRetriever.createChild(request);

                internals.evaluatePolicy(policy, wrappedDataRetriever, (err, result) => {

                    if (err) {
                        return reply(err);
                    }

                    if (result === DENY) {
                        return reply(Boom.unauthorized('No permissions to access this resource'));
                    }

                    if (result === UNDETERMINED) {
                        return reply(Boom.unauthorized('Could not evaluate access rights to resource'));
                    }

                    reply.continue();
                });
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
 * If the configuration is a function, then this function should retrieve the access policy (e.g.: from a database).
 * Otherwise, it is assumed that the configuration is the access policy itself.
 *
 * The callback signature is function (err, policy) {}
 **/
internals.retrievePolicy = (config, request, callback) => {

    if (config instanceof Function) {
        config(request, callback);
    }
    else {
        callback(null, config);
    }
};

/**
 * Evaluate a single Policy of PolicySet
 *
 **/
internals.evaluatePolicy = (item, dataRetriever, callback) => {

    if (!item) {
        return callback(Boom.badImplementation('RBAC configuration error: null item'));
    }

    if (!item.apply) {
        item.apply = 'permit-overrides';
    }

    if (!(item.apply instanceof Function)) {
        if (!internals.combineAlg[item.apply]) {
            return callback(Boom.badImplementation('RBAC error: combinatory algorithm does not exist: ' + item.apply));
        }

        item.apply = internals.combineAlg[item.apply];
    }

    internals.evaluateTarget(item.target, dataRetriever, (err, applies) => {

        if (err) {
            return callback(err);
        }

        if (!applies) {
            return callback(null, UNDETERMINED);
        }

        // Policy set
        if (item.policies) {

            return item.apply(item.policies, dataRetriever, internals.evaluatePolicy, callback);
        }

        // Policy
        if (item.rules) {

            return item.apply(item.rules, dataRetriever, internals.evaluateRule, callback);
        }

        // Rule
        internals.evaluateRule(item, dataRetriever, callback);
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
internals.evaluateRule = (rule, dataRetriever, callback) => {

    if (!rule) {
        return callback(Boom.badImplementation('RBAC rule is missing'));
    }

    internals.evaluateTarget(rule.target, dataRetriever, (err, applies) => {

        if (err) {
            return callback(err);
        }

        if (!applies) {
            return callback(null, UNDETERMINED);
        }

        switch (rule.effect) {
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
internals.evaluateTarget = (target, dataRetriever, callback) => {

    if (!target) {
        // Applies by default, when no target is defined
        return callback(null, true);
    }

    if (!(target instanceof Array) || target.length < 2) {
        return callback(Boom.badImplementation('RBAC target error: invalid format. Should be an array with match type and items ["all-of", item1, item2, ..., itemN]'));
    }

    for (let i = 1; i < target.length; ++i) {
        const value = dataRetriever.get(target[i].type);

        const result = internals._targetApplies(target[i].value, value);

        if (result && target[0] === 'any-of') {
            return callback(null, true);
        }

        if (!result && target[0] === 'all-of') {
            return callback(null, false);
        }
    }

    return callback(null, target[0] === 'all-of');
};

internals._targetApplies = (target, value) => {

    if (target === value) {
        return true;
    }

    if (value instanceof Array) {
        if (value.indexOf(target) !== -1) {
            return true;
        }
    }

    return false;
};

/**
 * Combinator algorithms:
 *
 *   - permit-overrides - If at least one permit is evaluated, then permit
 *   - deny-overrides - If at least one deny is evaluated, then deny
 *   - only-one-applicable -
 *   - first-applicable - Only evaluate the first applicable rule
 **/
internals.combineAlg = {};

internals.combineAlg['permit-overrides'] = (items, information, fn, callback) => {

    if (!items || items.length === 0) {
        return callback(null, UNDETERMINED);
    }

    const tasks = [];

    for (let i = 0; i < items.length; ++i) {
        tasks.push(fn.bind(null, items[i], information));
    }

    Async.parallel(tasks, (err, results) => {

        if (err) {
            return callback(err);
        }

        for (let i = 0; i < results.length; ++i) {
            if (results[i] === PERMIT) {
                return callback(null, PERMIT);
            }
        }

        callback(null, DENY);
    });
};

internals.combineAlg['deny-overrides'] = (items, information, fn, callback) => {

    if (!items || items.length === 0) {
        return callback(null, UNDETERMINED);
    }

    const tasks = [];

    for (let i = 0; i < items.length; ++i) {
        tasks.push(fn.bind(null, items[i], information));
    }

    Async.parallel(tasks, (err, results) => {

        if (err) {
            return callback(err);
        }

        for (let i = 0; i < results.length; ++i) {
            if (results[i] === DENY) {
                return callback(null, DENY);
            }
        }

        callback(null, PERMIT);
    });
};

if (['test', 'development'].indexOf(process.env.NODE_ENV) !== -1) {

    // To run the lab tests
    exports.evaluateTarget = internals.evaluateTarget;
    exports.evaluatePolicy = internals.evaluatePolicy;
    exports.evaluateRule = internals.evaluateRule;

    exports.PERMIT = PERMIT;
    exports.DENY = DENY;
    exports.UNDETERMINED = UNDETERMINED;

    exports.DataRetrievalRouter = DataRetrievalRouter;
}

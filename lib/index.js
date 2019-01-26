'use strict';

const Boom = require('boom');
const Joi = require('joi');
const Hoek = require('hoek');
const RbacCore = require('rbac-core');
const Pack = require('../package.json');

const DataRetrievalRouter = RbacCore.DataRetrievalRouter;

const CONFIG_NONE = 'none';

const internals = {};
const schemas = {};
const defaults = {};

schemas.policyRetriever = Joi.func();
schemas.policy = Joi.object();
schemas.DataRetrievalRouter_register_handles = Joi.alternatives().try(
    Joi.string().min(1),
    Joi.array().items(Joi.string().min(1))
);

/**
 * If the configuration is a function, then this function should retrieve the access policy (e.g.: from a database).
 * Otherwise, it is assumed that the configuration is the access policy itself.
 *
 * The callback signature is function (err, policy) {}
 **/
internals.retrievePolicy = async (config, request) => {
    if (config instanceof Function) {
        return config(request);
    }

    return config;
};

internals.evaluatePolicy = (policy, wrappedDataRetriever) =>
    new Promise((resolve, reject) => {
        RbacCore.evaluatePolicy(policy, wrappedDataRetriever, (err, result) => {
            if (err) {
                reject(err);
            } else {
                resolve(result);
            }
        });
    });


/**
 * Hapi register function
 **/
schemas.register_options = Joi.object({
    onError: Joi.func().optional(),
    responseCode: Joi.object({
        onDeny: Joi.number().optional(),
        onUndetermined: Joi.number().optional()
    }).optional(),
    policy: Joi.alternatives().try(
        schemas.policyRetriever,
        schemas.policy
    ).optional(),
    dataRetrievers: Joi.array().items(
        Joi.object({
            handles: schemas.DataRetrievalRouter_register_handles.required(),
            handler: Joi.func().required()
        })
    ).optional()
});

defaults.options = {
    onError: (request, h, err) => {
        throw err.isBoom ? err : Boom.boomify(err, 401);
    },
    responseCode: {
        onDeny: 401,
        onUndetermined: 401
    },
    dataRetrievers: []
};

internals.retrievePolicyHandler = (dataRetriever, options) =>
    async (request, h) => {
        const config = request.route.settings.plugins.rbac || options.policy;
        if (config && config !== CONFIG_NONE) {
            try {
                const policy = await internals.retrievePolicy(config, request);

                if (!policy || policy === CONFIG_NONE) {
                    return h.continue;
                }

                // Add context to data retriever's child
                const result = await internals.evaluatePolicy(policy, dataRetriever.createChild(request));
                if (result === RbacCore.DENY) {
                    return options.onError(request, h, new Boom('No permissions to access this resource', {
                        statusCode: options.responseCode.onDeny
                    }));
                }

                if (result === RbacCore.UNDETERMINED) {
                    return options.onError(request, h, new Boom('Could not evaluate access rights to resource', {
                        statusCode: options.responseCode.onUndetermined
                    }));
                }

            } catch (err) {
                return options.onError(request, h, err);
            }
        }

        return h.continue;
    };

exports.plugin = {
    name: Pack.name,
    version: Pack.version,
    once: true,
    multiple: false,

    register: (server, options) => {
        Joi.assert(options, schemas.register_options);

        options = Hoek.applyToDefaults(defaults.options, options);

        // Register default data retrievers
        const dataRetriever = new DataRetrievalRouter();
        dataRetriever.register('credentials', require('./dataRetrievers/credentials'));
        dataRetriever.register('connection', require('./dataRetrievers/connection'));
        dataRetriever.register('query', require('./dataRetrievers/query-params'));
        dataRetriever.register(['param', 'params'], require('./dataRetrievers/url-params'));
        dataRetriever.register('request', require('./dataRetrievers/request'));

        // Load user defined data retrievers
        options.dataRetrievers.forEach((dataRetrieverItem) => {
            dataRetriever.register(dataRetrieverItem.handles, dataRetrieverItem.handler);
        });

        server.ext('onPostAuth', internals.retrievePolicyHandler(dataRetriever, options));
    }
};


exports.plugin.register.attributes = {
    pkg: require('../package.json')
};

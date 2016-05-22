'use strict';

const Hoek = require('hoek');

exports = module.exports = (source, key, context, callback) => {

    if(!context) {
        // Return nothing
        return callback();
    }

    // Check allowed keys
    if(['method', 'path'].indexOf(key) === -1) {
        return callback();
    }

    callback(null, Hoek.reach(context, key));
};

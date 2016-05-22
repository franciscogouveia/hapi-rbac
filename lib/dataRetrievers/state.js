'use strict';

const Hoek = require('hoek');

exports = module.exports = (source, key, context, callback) => {

    if(!context) {
        // Return nothing
        return callback();
    }

    callback(null, Hoek.reach(context, 'state.' + key));
};

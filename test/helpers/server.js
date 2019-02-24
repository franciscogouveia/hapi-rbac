const Hapi = require('hapi');


exports.createServer = async (users, options) => {
    try {
        const server = new Hapi.Server();

        await server.register([
            require('hapi-auth-basic'),
            {
                plugin: require('../../lib'),
                options
            }
        ]);

        server.auth.strategy('simple', 'basic', {
            validate: (request, username, password, h) => {
                if (!users[username] || users[username].password !== password) {
                    return {isValid: false, credentials: null};
                }

                return {isValid: true, credentials: users[username]};
            }
        });
        server.auth.default('simple');

        return server;
    } catch (er) {
        console.error(er);
        process.exit(-1);
    }
};


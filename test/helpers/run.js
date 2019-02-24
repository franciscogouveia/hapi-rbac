const {createServer} = require('./server');

async function run() {
    try {
        const users = {};

        users.sg1000 = {
            'scope': 'admin',
            'firstName': 'Some',
            'lastName': 'Guy',
            'username': 'sg1000',
            'password': 'pwtest',
            'group': ['admin']
        };

        // Set up the hapi server route
        const server = await createServer(users, {});

        server.route({
            method: 'GET',
            path: '/wrong-credentials',
            handler: (request, h) => h.response({ok: true})
        });

        server.route({
            method: 'GET',
            path: '/user',
            handler: (request, h) => h.response({ok: true})
        });
    } catch (er) {
        console.error(er);
    }

}

run();

'use strict';

var Hapi = require('hapi');
var Boom = require('boom');
var Code = require('code');
var Lab = require('lab');

var lab = exports.lab = Lab.script();
var experiment = lab.experiment;
var test = lab.test;
var before = lab.before;

var expect = Code.expect;


experiment("Generic tests, with RBAC plugin configured", function() {

  var server;

  before(function(done) {
    // Set up the hapi server route
    server = new Hapi.Server();

    server.connection();

    var users = {};

    users.sg1000 = {
      'scope': 'admin',
      'firstName': 'Some',
      'lastName': 'Guy',
      'username': 'sg1000',
      'password': 'pwtest',
      'group': ['admin']
    };

    server.register([
      {
        register: require('hapi-auth-basic')
      },
      {
        register: require('../')
      }
    ], function(err) {

      if(err) {
        return done(err);
      }

      server.auth.strategy('default', 'basic', 'required', {
        validateFunc: function(request, username, password, callback) {

          if(!users[username] || users[username].password !== password) {
            return callback(Boom.unauthorized('Wrong credentials') , false);
          }

          callback(null, true, users[username]);
        }
      });

      done();

    });

  });

  test("Should not have access with wrong credentials", function(done) {

      server.route({
        method: 'GET',
        path: '/wrong-credentials',
        handler: function(request, reply) {
          reply({
            ok: true
          });
        }
      });

      server.inject({
        method: 'GET',
        url: '/wrong-credentials',
        headers: {
          authorization: 'Basic ' + (new Buffer('xpto:pw-123456', 'utf8')).toString('base64')
        }
      }, function(response) {

        expect(response.statusCode).to.equal(401);

        expect(response.result.error).to.equal('Unauthorized');
        expect(response.result.message).to.equal('Wrong credentials');

        done();
      });
  });

  test("Should have access on route without ac rules", function(done) {

      server.route({
        method: 'GET',
        path: '/user',
        handler: function(request, reply) {
          reply({
            ok: true
          });
        }
      });

      server.inject({
        method: 'GET',
        url: '/user',
        headers: {
          authorization: 'Basic ' + (new Buffer('sg1000:pwtest', 'utf8')).toString('base64')
        }
      }, function(response) {

        expect(response.statusCode).to.equal(200);

        done();
      });
  });

});


/**
 * Rule based access control policy tests, based on username
 **/
experiment("RBAC policy, based on username", function() {

  var server;

  before(function(done) {
    // Set up the hapi server route
    server = new Hapi.Server();

    server.connection();

    var users = {};

    users.sg1001 = {
      'scope': 'admin',
      'firstName': 'Some',
      'lastName': 'Guy',
      'username': 'sg1001',
      'password': 'pwtest',
      'group': ['reader']
    };

    server.register([
      {
        register: require('hapi-auth-basic')
      },
      {
        register: require('../')
      }
    ], function(err) {

      if(err) {
        return done(err);
      }

      server.auth.strategy('default', 'basic', 'required', {
        validateFunc: function(request, username, password, callback) {

          if(!users[username] || users[username].password !== password) {
            return callback(Boom.unauthorized('Wrong credentials') , false);
          }

          callback(null, true, users[username]);
        }
      });

      done();

    });

  });

  test("Should have access to the route, with policy targeting the username", function(done) {

      server.route({
        method: 'GET',
        path: '/allow-username',
        handler: function(request, reply) {
          reply({
            ok: true
          });
        },
        config: {
          plugins: {
            rbac: {
              target: ['any-of', {type: 'username', value: 'sg1001'}],
              apply: 'permit-overrides',
              rules: [
                  {
                      'effect': 'permit'
                  }
              ]
            }
          }
        }
      });

      server.inject({
        method: 'GET',
        url: '/allow-username',
        headers: {
          authorization: 'Basic ' + (new Buffer('sg1001:pwtest', 'utf8')).toString('base64')
        }
      }, function(response) {

        expect(response.statusCode).to.equal(200);

        done();
      });
  });

  test("Should not have access to the route, with policy targeting the username", function(done) {

      server.route({
        method: 'GET',
        path: '/disallow-username',
        handler: function(request, reply) {
          reply({
            ok: true
          });
        },
        config: {
          plugins: {
            rbac: {
              target: ['any-of', {type: 'username', value: 'sg1001'}],
              apply: 'permit-overrides',
              rules: [
                  {
                      'effect': 'deny'
                  }
              ]
            }
          }
        }
      });

      server.inject({
        method: 'GET',
        url: '/disallow-username',
        headers: {
          authorization: 'Basic ' + (new Buffer('sg1001:pwtest', 'utf8')).toString('base64')
        }
      }, function(response) {

        expect(response.statusCode).to.equal(401);

        done();
      });
  });

});

/**
 * Rule based access control policy tests, based on group membership
 **/
experiment("RBAC policy, based on group membership", function() {

  var server;

  before(function(done) {
    // Set up the hapi server route
    server = new Hapi.Server();

    server.connection();

    var users = {};

    users.sg1002 = {
      'scope': 'admin',
      'firstName': 'Some',
      'lastName': 'Otherguy',
      'username': 'sg1002',
      'password': 'pwtest',
      'group': ['admin', 'publisher']
    };

    users.sg1003 = {
      'scope': 'admin',
      'firstName': 'Another',
      'lastName': 'Guy',
      'username': 'sg1003',
      'password': 'pwtest',
      'group': ['admin', 'reader']
    };

    server.register([
      {
        register: require('hapi-auth-basic')
      },
      {
        register: require('../')
      }
    ], function(err) {

      if(err) {
        return done(err);
      }

      server.auth.strategy('default', 'basic', 'required', {
        validateFunc: function(request, username, password, callback) {

          if(!users[username] || users[username].password !== password) {
            return callback(Boom.unauthorized('Wrong credentials') , false);
          }

          callback(null, true, users[username]);
        }
      });

      done();

    });

  });

  test("Should have access to the route, with policy targeting a group inside user membership", function(done) {

      server.route({
        method: 'GET',
        path: '/permit-with-group-membership',
        handler: function(request, reply) {
          reply({
            ok: true
          });
        },
        config: {
          plugins: {
            rbac: {
              target: ['any-of', {type: 'group', value: 'admin'}],
              apply: 'permit-overrides',
              rules: [
                  {
                      'effect': 'permit'
                  }
              ]
            }
          }
        }
      });

      server.inject({
        method: 'GET',
        url: '/permit-with-group-membership',
        headers: {
          authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
        }
      }, function(response) {

        expect(response.statusCode).to.equal(200);

        done();
      });
  });

  test("Should not have access to the route, with policy targeting a group outside user membership", function(done) {

      server.route({
        method: 'GET',
        path: '/deny-without-group-membership',
        handler: function(request, reply) {
          reply({
            ok: true
          });
        },
        config: {
          plugins: {
            rbac: {
              target: ['any-of', {type: 'group', value: 'reader'}],
              apply: 'permit-overrides',
              rules: [
                  {
                      'effect': 'permit'
                  }
              ]
            }
          }
        }
      });

      server.inject({
        method: 'GET',
        url: '/deny-without-group-membership',
        headers: {
          authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
        }
      }, function(response) {

        expect(response.statusCode).to.equal(401);

        done();
      });
  });

  test("Should have access to the route, with policy targeting one group inside OR one group outside user membership", function(done) {

      server.route({
        method: 'GET',
        path: '/permit-if-at-least-one-group-membership',
        handler: function(request, reply) {
          reply({
            ok: true
          });
        },
        config: {
          plugins: {
            rbac: {
              target: ['any-of', {type: 'group', value: 'reader'}, {type: 'group', value: 'admin'}],
              apply: 'permit-overrides',
              rules: [
                  {
                      'effect': 'permit'
                  }
              ]
            }
          }
        }
      });

      server.inject({
        method: 'GET',
        url: '/permit-if-at-least-one-group-membership',
        headers: {
          authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
        }
      }, function(response) {

        expect(response.statusCode).to.equal(200);

        done();
      });
  });


  test("Should have access to the route, with policy targeting two groups outside user membership", function(done) {

      server.route({
        method: 'GET',
        path: '/deny-if-none-group-membership',
        handler: function(request, reply) {
          reply({
            ok: true
          });
        },
        config: {
          plugins: {
            rbac: {
              target: ['any-of', {type: 'group', value: 'reader'}, {type: 'group', value: 'watcher'}],
              apply: 'permit-overrides',
              rules: [
                  {
                      'effect': 'permit'
                  }
              ]
            }
          }
        }
      });

      server.inject({
        method: 'GET',
        url: '/deny-if-none-group-membership',
        headers: {
          authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
        }
      }, function(response) {

        expect(response.statusCode).to.equal(401);

        done();
      });
  });

  test("Should not have access to the route, with policy targeting one group inside AND one group outside user membership", function(done) {

      server.route({
        method: 'GET',
        path: '/deny-if-not-all-group-membership',
        handler: function(request, reply) {
          reply({
            ok: true
          });
        },
        config: {
          plugins: {
            rbac: {
              target: ['all-of', {type: 'group', value: 'reader'}, {type: 'group', value: 'admin'}],
              apply: 'permit-overrides',
              rules: [
                  {
                      'effect': 'permit'
                  }
              ]
            }
          }
        }
      });

      server.inject({
        method: 'GET',
        url: '/deny-if-not-all-group-membership',
        headers: {
          authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
        }
      }, function(response) {

        expect(response.statusCode).to.equal(401);

        done();
      });
  });

  test("Should have access to the route, with policy targeting two groups inside user membership", function(done) {

      server.route({
        method: 'GET',
        path: '/permit-if-all-group-membership',
        handler: function(request, reply) {
          reply({
            ok: true
          });
        },
        config: {
          plugins: {
            rbac: {
              target: ['all-of', {type: 'group', value: 'publisher'}, {type: 'group', value: 'admin'}],
              apply: 'permit-overrides',
              rules: [
                  {
                      'effect': 'permit'
                  }
              ]
            }
          }
        }
      });

      server.inject({
        method: 'GET',
        url: '/permit-if-all-group-membership',
        headers: {
          authorization: 'Basic ' + (new Buffer('sg1002:pwtest', 'utf8')).toString('base64')
        }
      }, function(response) {

        expect(response.statusCode).to.equal(200);

        done();
      });
  });
});





/**
 * Rule based access control policy tests, based on username
 **/
experiment("RBAC rule, based on username", function() {

  var server;

  before(function(done) {
    // Set up the hapi server route
    server = new Hapi.Server();

    server.connection();

    var users = {};

    users.sg1004 = {
      'scope': 'admin',
      'firstName': 'Some',
      'lastName': 'Guy',
      'username': 'sg1004',
      'password': 'pwtest',
      'group': ['reader']
    };

    server.register([
      {
        register: require('hapi-auth-basic')
      },
      {
        register: require('../')
      }
    ], function(err) {

      if(err) {
        return done(err);
      }

      server.auth.strategy('default', 'basic', 'required', {
        validateFunc: function(request, username, password, callback) {

          if(!users[username] || users[username].password !== password) {
            return callback(Boom.unauthorized('Wrong credentials') , false);
          }

          callback(null, true, users[username]);
        }
      });

      done();

    });

  });

  test("Should have access to the route, with policy targeting the username", function(done) {

      server.route({
        method: 'GET',
        path: '/allow-username',
        handler: function(request, reply) {
          reply({
            ok: true
          });
        },
        config: {
          plugins: {
            rbac: {
              apply: 'permit-overrides',
              rules: [
                  {
                      target: ['any-of', {type: 'username', value: 'sg1004'}],
                      effect: 'permit'
                  }
              ]
            }
          }
        }
      });

      server.inject({
        method: 'GET',
        url: '/allow-username',
        headers: {
          authorization: 'Basic ' + (new Buffer('sg1004:pwtest', 'utf8')).toString('base64')
        }
      }, function(response) {

        expect(response.statusCode).to.equal(200);

        done();
      });
  });

  test("Should not have access to the route, with policy targeting the username", function(done) {

      server.route({
        method: 'GET',
        path: '/disallow-username',
        handler: function(request, reply) {
          reply({
            ok: true
          });
        },
        config: {
          plugins: {
            rbac: {
              apply: 'permit-overrides',
              rules: [
                  {
                      target: ['any-of', {type: 'username', value: 'sg1004'}],
                      effect: 'deny'
                  }
              ]
            }
          }
        }
      });

      server.inject({
        method: 'GET',
        url: '/disallow-username',
        headers: {
          authorization: 'Basic ' + (new Buffer('sg1004:pwtest', 'utf8')).toString('base64')
        }
      }, function(response) {

        expect(response.statusCode).to.equal(401);

        done();
      });
  });

});

/**
 * Rule based access control rule tests, based on group membership
 **/
experiment("RBAC rule, based on group membership", function() {

  var server;

  before(function(done) {
    // Set up the hapi server route
    server = new Hapi.Server();

    server.connection();

    var users = {};

    users.sg1005 = {
      'scope': 'admin',
      'firstName': 'Some',
      'lastName': 'Otherguy',
      'username': 'sg1005',
      'password': 'pwtest',
      'group': ['admin', 'publisher']
    };

    users.sg1006 = {
      'scope': 'admin',
      'firstName': 'Another',
      'lastName': 'Guy',
      'username': 'sg1006',
      'password': 'pwtest',
      'group': ['admin', 'reader']
    };

    server.register([
      {
        register: require('hapi-auth-basic')
      },
      {
        register: require('../')
      }
    ], function(err) {

      if(err) {
        return done(err);
      }

      server.auth.strategy('default', 'basic', 'required', {
        validateFunc: function(request, username, password, callback) {

          if(!users[username] || users[username].password !== password) {
            return callback(Boom.unauthorized('Wrong credentials') , false);
          }

          callback(null, true, users[username]);
        }
      });

      done();

    });

  });

  test("Should have access to the route, with policy targeting a group inside user membership", function(done) {

      server.route({
        method: 'GET',
        path: '/permit-with-group-membership',
        handler: function(request, reply) {
          reply({
            ok: true
          });
        },
        config: {
          plugins: {
            rbac: {
              apply: 'permit-overrides',
              rules: [
                  {
                      target: ['any-of', {type: 'group', value: 'admin'}],
                      effect: 'permit'
                  }
              ]
            }
          }
        }
      });

      server.inject({
        method: 'GET',
        url: '/permit-with-group-membership',
        headers: {
          authorization: 'Basic ' + (new Buffer('sg1005:pwtest', 'utf8')).toString('base64')
        }
      }, function(response) {

        expect(response.statusCode).to.equal(200);

        done();
      });
  });

  test("Should not have access to the route, with policy targeting a group outside user membership", function(done) {

      server.route({
        method: 'GET',
        path: '/deny-without-group-membership',
        handler: function(request, reply) {
          reply({
            ok: true
          });
        },
        config: {
          plugins: {
            rbac: {
              apply: 'permit-overrides',
              rules: [
                {
                  target: ['any-of', {type: 'group', value: 'reader'}],
                  effect: 'permit'
                }
              ]
            }
          }
        }
      });

      server.inject({
        method: 'GET',
        url: '/deny-without-group-membership',
        headers: {
          authorization: 'Basic ' + (new Buffer('sg1005:pwtest', 'utf8')).toString('base64')
        }
      }, function(response) {

        expect(response.statusCode).to.equal(401);

        done();
      });
  });

  test("Should have access to the route, with policy targeting one group inside OR one group outside user membership", function(done) {

      server.route({
        method: 'GET',
        path: '/permit-if-at-least-one-group-membership',
        handler: function(request, reply) {
          reply({
            ok: true
          });
        },
        config: {
          plugins: {
            rbac: {
              apply: 'permit-overrides',
              rules: [
                {
                  target: ['any-of', {type: 'group', value: 'reader'}, {type: 'group', value: 'admin'}],
                  effect: 'permit'
                }
              ]
            }
          }
        }
      });

      server.inject({
        method: 'GET',
        url: '/permit-if-at-least-one-group-membership',
        headers: {
          authorization: 'Basic ' + (new Buffer('sg1005:pwtest', 'utf8')).toString('base64')
        }
      }, function(response) {

        expect(response.statusCode).to.equal(200);

        done();
      });
  });


  test("Should have access to the route, with policy targeting two groups outside user membership", function(done) {

      server.route({
        method: 'GET',
        path: '/deny-if-none-group-membership',
        handler: function(request, reply) {
          reply({
            ok: true
          });
        },
        config: {
          plugins: {
            rbac: {
              apply: 'permit-overrides',
              rules: [
                {
                  target: ['any-of', {type: 'group', value: 'reader'}, {type: 'group', value: 'watcher'}],
                  effect: 'permit'
                }
              ]
            }
          }
        }
      });

      server.inject({
        method: 'GET',
        url: '/deny-if-none-group-membership',
        headers: {
          authorization: 'Basic ' + (new Buffer('sg1005:pwtest', 'utf8')).toString('base64')
        }
      }, function(response) {

        expect(response.statusCode).to.equal(401);

        done();
      });
  });

  test("Should not have access to the route, with policy targeting one group inside AND one group outside user membership", function(done) {

      server.route({
        method: 'GET',
        path: '/deny-if-not-all-group-membership',
        handler: function(request, reply) {
          reply({
            ok: true
          });
        },
        config: {
          plugins: {
            rbac: {
              apply: 'permit-overrides',
              rules: [
                {
                  target: ['all-of', {type: 'group', value: 'reader'}, {type: 'group', value: 'admin'}],
                  effect: 'permit'
                }
              ]
            }
          }
        }
      });

      server.inject({
        method: 'GET',
        url: '/deny-if-not-all-group-membership',
        headers: {
          authorization: 'Basic ' + (new Buffer('sg1005:pwtest', 'utf8')).toString('base64')
        }
      }, function(response) {

        expect(response.statusCode).to.equal(401);

        done();
      });
  });

  test("Should have access to the route, with policy targeting two groups inside user membership", function(done) {

      server.route({
        method: 'GET',
        path: '/permit-if-all-group-membership',
        handler: function(request, reply) {
          reply({
            ok: true
          });
        },
        config: {
          plugins: {
            rbac: {
              apply: 'permit-overrides',
              rules: [
                {
                  target: ['all-of', {type: 'group', value: 'publisher'}, {type: 'group', value: 'admin'}],
                  effect: 'permit'
                }
              ]
            }
          }
        }
      });

      server.inject({
        method: 'GET',
        url: '/permit-if-all-group-membership',
        headers: {
          authorization: 'Basic ' + (new Buffer('sg1005:pwtest', 'utf8')).toString('base64')
        }
      }, function(response) {

        expect(response.statusCode).to.equal(200);

        done();
      });
  });
});

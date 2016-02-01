# 1.3.0 API Reference


* [`Terms`](#terms)
* [`Setting up a policy`](#setting-up-a-policy)
  * [`Target`](#target)
  * [`Policy Set`](#policy-set)
  * [`Policy`](#policy)
  * [`Rule`](#rule)
* [`Configuration`](#configuration)
  * [`Global policy`](#global-policy)
  * [`Route policy`](#route-policy)
  * [`Dynamic policy`](#dynamic-policy)

# hapi-rbac

This module is a **Rule** Based Access Control plugin for hapi.

It decides, based on a set of `rules` (a `policy`), if the access should be `allowed` or `denied` to a certain route in a request.

If there are rules configured, but no rules can applied to a certain case, the access decision is `undetermined`. When it happens, the access is also `denied`.

## Terms

* `Target` - A set of key-value pairs which are matched with the available information on a request. It is used to decide if a *Rule*, *Policy* or *Policy Set* apply to the request's case.
* `Rule` - A *Rule* specifies if a matched *Target* should have or not access to the route.
* `Policy` - A *Policy* is composed by a set of *Rules*. It specifies how the combination of the *Rules'* results should be considered.
* `Policy Set` - A *Policy Set* is composed by a set of *Policies*. It also specifies how the combination of the *Policies'* results should be considered.

## Setting up a policy

### Target matching

Targets are the conditions which will define if a policy set, policy or rule apply in a request.
If the policy set, policy or rule should always apply, you can simply omit the `target`.

When present, it should be an array, where the first element is a string.
This first element should specify how the multiple targets should be matched.

There are two possibilities:

* `any-of` - You can think of it as an __OR__ operator
* `all-of` - You can think of it as an __AND__ operator

The other elements of the array are the matching subjects.

Check the following examples:

#### all-of

```js
['all-of', {type: 'credentials:group', value: 'writer'}, {type: 'credentials:premium', value: true}]
```

With this target, only users in group `writer` **and** with `premium` account will match.

So, if the logged in user has the following `request.auth.credentials` document:

```js
{
  username: 'user00001',
  group: ['writer'], // match
  premium: true, // match
  ...
}
```

Then, the *rule* or *policy* with the configured *target* will be evaluated.

But, if the logged in user has one of the following `request.auth.credentials` documents:

```js
{
  username: 'user00002',
  group: ['writer'], // match
  premium: false, // do not match :-(
  ...
}
```

```js
{
  username: 'user00003',
  group: ['reader'], // do not match :-(
  premium: true, // match
  ...
}
```

Then, the rule or policy with the configured target will not be evaluated.
Since the match used is `all-of`, the user doesn't match the target.

#### any-of

```
['any-of', {type: 'credentials:group', value: 'writer'}, {type: 'credentials:premium', value: true}, {type: 'credentials:username', value: 'user00002'}]
```

With this target, any user in the group `writer` **or** with `premium` account **or** with username `user00002` will be matched.

So, users with the following `request.auth.credentials` documents will be matched:

```js
{
  username: 'user00001',
  group: ['writer'], // match
  premium: false,
  ...
}
```

```js
{
  username: 'user00002', // match
  group: ['reader'],
  premium: false,
  ...
}
```

```js
{
  username: 'user00003',
  group: ['reader'],
  premium: true, // match
  ...
}
```

```js
{
  username: 'user00004',
  group: ['writer'], // match
  premium: true, // match
  ...
}
```

But, not the one with the following document:

```js
{
  username: 'user00005',
  group: ['reader'],
  premium: false,
  ...
}
```

The following words are prefixes that can be used for matching information:

* `credentials` - Information from `request.auth.credentials` object. Information in this object depends on your authentication implementation.
* `connection` - Connection information, from `request.info`, as documented in [hapi](http://hapijs.com/api#request-object):
  * `connection:host` - Content of the HTTP 'Host' header (e.g. 'example.com:8080').
  * `connection:hostname` - The hostname part of the 'Host' header (e.g. 'example.com').
  * `connection:received` - Request reception timestamp.
  * `connection:referrer` - Content of the HTTP 'Referrer' (or 'Referer') header.
  * `connection:remoteAddress` - Remote client IP address.
  * `connection:remotePort` - Remote client port.
* `query` - Query parameters, as in `request.query`.
* `param` - URL parameters, as in `request.params`.
* `request` - Other request information:
  * `request:path` - Requested path.
  * `request.method` - Requested method (e.g. `post`).


### Policy and Rules combinatory algorithms

When there is more than one policy inside a policy set or more than one rule inside a policy,
the combinatory algorithm will decide the final result from the multiple results.

There are, at the moment, two possibilities:

* `permit-overrides` - If at least one policy/rule permits, then the final decision
     for that policy set/policy should be `PERMIT` (deny, unless one permits)
* `deny-overrides` - If at least one policy/rule denies, then the final decision
     for that policy set/policy should be `DENY` (permit, unless one denies)

### Rule effects

If a rule applies (target match), the `effect` is the access decision for that rule. It can be:

* `permit` - If rule apply, decision is to allow access
* `deny` - If rule apply, decision is to deny access

When a policy set, policy or rule do not apply (the target don't match), then the decision is `undetermined`.
If all the policy sets, policies and rules have the `undetermined` result, then the access is denied,
 since it is not clear if the user can access or not the route.


### Rule

A __Rule__ defines a decision to _allow_ or _deny_ access. It contains:

* `target` (optional) - The target (default: matches with any)
* `effect` - The decision if the target matches. Can be `permit` or `deny`

Example

```
{
  target: ['any-of', {type: 'blocked', value: true}], // if the user is blocked
  effect: 'deny'  // then deny
}
```


### Policy

A __Policy__ is a _set of rules_. It contains:

* `target` (*optional*) - The target (*default*: matches with any)
* `apply` - The combinatory algorithm for the rules
* `rules` - An array of rules

Example

```js
{
  target: ['all-of', {type: 'group', value: 'writer'}, {type: 'premium', value: true}], // if writer AND premium account
  apply: 'deny-overrides', // permit, unless one denies
  rules: [
    {
      target: ['any-of', {type: 'username', value: 'bad_user'}], // if the username is bad_user
      effect: 'deny'  // then deny
    },
    {
      target: ['any-of', {type: 'blocked', value: true}], // if the user is blocked
      effect: 'deny'  // then deny
    },
    {
      effect: 'permit' // else permit
    }
  ]
}
```


### Policy Set

A __Policy Set__ is a set of __Policies__. It contains:

* `target` (_optional_) - The target (_default_: matches with any)
* `apply` - The combinatory algorithm for the policies
* `policies` - An array of policies

Example

```js
{
  target: ['any-of', {type: 'group', value: 'writer'}, {type: 'group', value: 'publisher'}], // writer OR publisher
  apply: 'permit-overrides', // deny, unless one permits
  policies: [
    {
      target: ['all-of', {type: 'group', value: 'writer'}, {type: 'premium', value: true}], // if writer AND premium account
      apply: 'deny-overrides', // permit, unless one denies
      rules: [
        {
          target: ['any-of', {type: 'username', value: 'bad_user'}], // if the username is bad_user
          effect: 'deny'  // then deny
        },
        {
          target: ['any-of', {type: 'blocked', value: true}], // if the user is blocked
          effect: 'deny'  // then deny
        },
        {
          effect: 'permit' // else permit
        }
      ]
    },
    {
      target: ['all-of', {type: 'premium', value: false}], // if (writer OR publisher) AND no premium account
      apply: 'permit-overrides', // deny, unless one permits
      rules: [
        {
          target: ['any-of', {type: 'username', value: 'special_user'}], // if the username is special_user
          effect: 'permit'  // then permit
        },
        {
          effect: 'deny' // else deny
        }
      ]
    }
  ]
}
```

## Configuration

### Global Policy

If you wish to define a default access control policy for the routes, you can do it with `policy` key inside the `options`, when you register the `hapi-rbac` in hapi.

```js
server.register({
  register: require('hapi-rbac'),
  options: {
    policy: {
      target: ['any-of', {type: 'group', value: 'readers'}],
      apply: 'deny-overrides', // Combinatory algorithm
      rules: [
        {
          target: ['any-of', {type: 'username', value: 'bad_guy'}],
          effect: 'deny'
        },
        {
          effect: 'permit'
        }
      ]
    }
  }
}, function(err) {
  ...
});
```

This configuration will allow access to all the routes to all the users in the `readers` group, except to the user `bad_guy`.


### Route Policy

If you wish to define access control policies for a single route, you can do it at the route level configuration:

```js
server.route({
  method: 'GET',
  path: '/example',
  handler: function(request, reply) {
    reply({
      ok: true
    });
  },
  config: {
    plugins: {
      rbac: {
        target: ['any-of', {type: 'group', value: 'readers'}],
        apply: 'deny-overrides', // Combinatory algorithm
        rules: [
          {
            target: ['any-of', {type: 'username', value: 'bad_guy'}],
            effect: 'deny'
          },
          {
            effect: 'permit'
          }
        ]
      }
    }
  }
});
```

If you have access control policies configured globally, this configuration overrides them.


You can disable a global access control policy at the route level, by using the string `none`:

```js
server.route({
  method: 'GET',
  path: '/example',
  handler: function(request, reply) {
    reply({
      ok: true
    });
  },
  config: {
    plugins: {
      rbac: 'none'
    }
  }
});
```

### Dynamic Policy

It is also possible to retrieve the policies dynamically (e.g.: from a database). Instead of defining them directly, use a callback function instead.

```js
server.register({
  register: require('hapi-rbac'),
  options: {
    policy: function(request, callback) {

      /* Retrieve your policies from a database */
      const query = {
        resource: { // Use the path and method as a resource identifier
          path: request.route.path,
          method: request.route.method
        }
      };

      db.collection('policies').findOne(query, function(err, policy) {

        if(err) {
          return callback(err);
        }

        // callback with the found policy
        // if policy is null, then hapi-rbac assumes that there is no policy configured for the route
        callback(null, policy);
      });
    }
  }
}, function(err) {
  ...
});
```

In this example, it is assumed that your policies have a `resource` key with `path` and `method` sub-keys.

```js
{
  resource: { // resource identifies what is being requested
    path: '/example',
    method: 'get'
  },
  target: ['any-of', {type: 'group', value: 'readers'}],
  apply: 'deny-overrides', // Combinatory algorithm
  rules: [
    {
      target: ['any-of', {type: 'username', value: 'bad_guy'}],
      effect: 'deny'
    },
    {
      effect: 'permit'
    }
  ]
}
```



You can also have dynamic access control policy retrieval at the route level:

```js
server.route({
  method: 'GET',
  path: '/example',
  handler: function(request, reply) {
    reply({
      ok: true
    });
  },
  config: {
    plugins: {
      rbac: function(request, callback) {

        /* Retrieve your policies from a database */
        const query = {
          resource: { // Use the path and method as a resource identifier
            path: request.route.path,
            method: request.route.method
          }
        };

        db.collection('policies').findOne(query, function(err, policy) {

          if(err) {
            return callback(err);
          }

          // callback with the found policy
          // if policy is null, then hapi-rbac assumes that there is no policy configured for the route
          callback(null, policy);
        });
      }
    }
  }
});
```




























[npm-badge]: https://img.shields.io/npm/v/hapi-rbac.svg
[npm-url]: https://npmjs.com/package/hapi-rbac
[travis-badge]: https://travis-ci.org/franciscogouveia/hapi-rbac.svg?branch=master
[travis-url]: https://travis-ci.org/franciscogouveia/hapi-rbac
[coveralls-badge]:https://coveralls.io/repos/franciscogouveia/hapi-rbac/badge.svg?branch=master&service=github
[coveralls-url]: https://coveralls.io/github/franciscogouveia/hapi-rbac?branch=master
[david-badge]: https://david-dm.org/franciscogouveia/hapi-rbac.svg
[david-url]: https://david-dm.org/franciscogouveia/hapi-rbac

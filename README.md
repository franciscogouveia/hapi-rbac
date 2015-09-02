# hapi-rbac [![Build Status](https://travis-ci.org/franciscogouveia/hapi-rbac.svg?branch=master)](https://travis-ci.org/franciscogouveia/hapi-rbac)

A Rule Based Access Control module for hapi. This is inspired by the XACML policies.

## How to use it

First, install

```
npm install --save hapi-rbac
```

Then, import the module in your hapi server instance

```
server.register({
  register: require('hapi-rbac')
}, function(err) {
  ...
});
```

Then, define the rules in your routes

```
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

This configuration will allow all the users in the `readers` group to access the route, except user `bad_guy`.

## Requirement

The `type` defined in the target should be a key in your `credentials` document. In the example above, the `credentials` document should contain `username` and `group`. For examples, check the test file.

## Configurations

### Target matching

Targets are the conditions which will define if a policy set, policy or rule apply in a request. If the policy set, policy or rule should always apply, you can simply omit the `target`.

When present, it should be an array, where the first element is a string. This first element should specify how the multiple targets should be matched. There are two possibilities:

* `any-of` - You can think of it as an OR operator
* `all-of` - You can think of it as an AND operator

The other elements of the array are the matching subjects.

Check the following examples:

#### all-of

```
['all-of', {type: 'group', value: 'writer'}, {type: 'premium', value: true}]
```

With this rule, only users in group `writer` **and** with `premium` account can access.

So, if the logged in user has the following `request.auth.credentials` document:

```
{
  username: 'user00001',
  group: ['writer'], // match
  premium: true, // match
  ...
}
```

Then, this user meets all the target requirements and can access the route.

But, if the logged in user has one of the following `request.auth.credentials` documents:

```
{
  username: 'user00002',
  group: ['writer'], // match
  premium: false, // do not match :-(
  ...
}
```

```
{
  username: 'user00003',
  group: ['reader'], // do not match :-(
  premium: true, // match
  ...
}
```

Then, this user meets only one of the requirements. Since the match used is `all-of`, the user cannot access the route.

#### any-of

```
['any-of', {type: 'group', value: 'writer'}, {type: 'premium', value: true}, {type: 'username', value: 'user00002'}]
```

With this rule, any user in the group `writer` **or** with `premium` account **or** with username `user00002` can access the route.

So, users with the following `request.auth.credentials` documents can access the route:

```
{
  username: 'user00001',
  group: ['writer'], // match
  premium: false,
  ...
}
```

```
{
  username: 'user00002', // match
  group: ['reader'],
  premium: false,
  ...
}
```

```
{
  username: 'user00003',
  group: ['reader'],
  premium: true, // match
  ...
}
```

```
{
  username: 'user00004',
  group: ['writer'], // match
  premium: true, // match
  ...
}
```

But, not the one with the following document:

```
{
  username: 'user00005',
  group: ['reader'],
  premium: false,
  ...
}
```

### Policy and Rules combinatory algorithms

When there is more than one policy inside a policy set or more than one rule inside a policy, the combinatory algorithm will decide the final result from the multiple results. There are, at the moment, two possibilities:

* `permit-overrides` - If at least one policy/rule permits, then the final decision for that policy set/policy should be PERMIT (deny, unless one permits)
* `deny-overrides` - If at least one policy/rule denies, then the final decision for that policy set/policy should be DENY (permit, unless one denies)

### Rule effects

If a rule applies, the `effect` is the access decision for that rule. It can be:

* `permit` - If rule apply, decision is to allow access
* `deny` - If rule apply, decision is to deny access

When a policy set, policy or rule do not apply (the target don't match), then the decision is `undetermined`. If all the policy sets, policies and rules have the `undetermined` result, then the access is denied, since it is not clear if the user can access or not the route.

## Learn more

To have a better idea of how this works, you can check my Bachelor's project presentation about XACML [here](http://helios.av.it.pt/attachments/download/559/_en_XACML.PAPOX.Presentation.pdf) (english), or [here](http://helios.av.it.pt/attachments/download/557/_pt_XACML.PAPOX.Presentation.pdf) (portuguese). Even though this plugin doesn't implement the XACML specification, it was based on its policies.

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

Targets are the conditions which will define if a policy set, policy or rule apply in a request. Target should be an array, where the first element is a string. This first element should specify how the multiple targets should be matched. There are two possibilities:

* `any-of` - You can think of it as an OR operator
* `all-of` - You can think of it as an AND operator

The other elements of the array are the matching subjects.

If the policy set, policy or rule should always apply, you can simply omit the `target`.

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

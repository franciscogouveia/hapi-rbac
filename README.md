# hapi-rbac

[![npm version][npm-badge]][npm-url]
[![Build Status][travis-badge]][travis-url]
[![Coverage Status][coveralls-badge]][coveralls-url]
[![Dependency Status][david-badge]][david-url]

> A **Rule Based Access Control** module for [hapi](https://github.com/hapijs/hapi).

> This is inspired by the [XACML](https://en.wikipedia.org/wiki/XACML) policies.

## Versions

* `2.0.0` - Simplified target (updated [rbac-core](https://github.com/franciscogouveia/rbac-core) to `2.0.0`)
* `1.3.0` - Use more data for target matching
* `1.2.0` - Global default configuration is now possible
* `1.1.0` - Added ability to dynamically retrieve policies for the route
* `1.0.0` - Since this version, only node `^4.0` and hapi `^12.0.0` is supported.
   All the functionality and syntax remains the same.

## How to use it

First, install

```
npm install --save hapi-rbac
```

Then, import the module in your hapi server instance.

```js
server.register({
  register: require('hapi-rbac')
}, function(err) {
  ...
});
```

Then, configure your policies. Check the [API Reference](https://github.com/franciscogouveia/hapi-rbac/blob/master/API.md).


## Learn more about _Rule Based Access Control_

To have a better idea of how this works, you can check my Bachelor's project presentation about XACML
[here](http://helios.av.it.pt/attachments/download/559/_en_XACML.PAPOX.Presentation.pdf) (english),
or [here](http://helios.av.it.pt/attachments/download/557/_pt_XACML.PAPOX.Presentation.pdf) (portuguese).

Even though this plugin doesn't implement the XACML specification, it was based on its policies.

[npm-badge]: https://img.shields.io/npm/v/hapi-rbac.svg
[npm-url]: https://npmjs.com/package/hapi-rbac
[travis-badge]: https://travis-ci.org/franciscogouveia/hapi-rbac.svg?branch=master
[travis-url]: https://travis-ci.org/franciscogouveia/hapi-rbac
[coveralls-badge]:https://coveralls.io/repos/franciscogouveia/hapi-rbac/badge.svg?branch=master&service=github
[coveralls-url]: https://coveralls.io/github/franciscogouveia/hapi-rbac?branch=master
[david-badge]: https://david-dm.org/franciscogouveia/hapi-rbac.svg
[david-url]: https://david-dm.org/franciscogouveia/hapi-rbac

const template = require('lodash-vulnerable/template');
console.log(template('hello <%= name %>')({name: 'SBOM'}));

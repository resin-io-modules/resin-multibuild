/* eslint-disable @typescript-eslint/no-var-requires */
/*
 * Adapted from code found in https://github.com/joyent/node-docker-registry-client
*/

const util = require('util'),
    format = util.format;
const assert = require('assert-plus');
const verror = require('verror'),
    VError = verror.VError;

// ---- error classes

function _DockerRegistryClientBaseError() {
    const ctor = this.constructor;
    assert.string(ctor.prototype.code, ctor.name + '.prototype.code');

    const vargs = [];
    let fields;
    let msgArgs;
    if (arguments[0] instanceof Error) {
        // `new <Error>(<err>, ...)`
        vargs.push(arguments[0]); // cause
        if (arguments.length === 1) {
            msgArgs = ['error'];
        } else {
            msgArgs = Array.prototype.slice.call(arguments, 1);
        }
    } else if (typeof (arguments[0]) !== 'object' && arguments[0] !== null ||
            Array.isArray(arguments[0])) {
        // `new <Error>(msg, ...)`
        fields = null;
        msgArgs = Array.prototype.slice.call(arguments);
    } else if (Buffer.isBuffer(arguments[0])) {
        // `new <Error>(buf, ...)`
        // Almost certainly an error, show `inspect(buf)`. See bunyan#35.
        fields = null;
        msgArgs = Array.prototype.slice.call(arguments);
        msgArgs[0] = util.inspect(msgArgs[0]);
    } else {
        // `new <Error>(fields, msg, ...)`
        fields = arguments[0];
        if (fields.err) {
            vargs.push(fields.err); // cause
            delete fields.err;
        }
        msgArgs = Array.prototype.slice.call(arguments, 1);
    }

    // HACK: Workaround silly printf-handling in verror s.t. a message with
    // content that looks like a printf code breaks its rendering.
    vargs.push('%s');
    vargs.push(format.apply(null, msgArgs));
    VError.apply(this, vargs);

    if (fields) {
        Object.keys(fields).forEach((name) => {
            this[name] = fields[name];
        });
    }

}
util.inherits(_DockerRegistryClientBaseError, VError);


function InternalError() {
    _DockerRegistryClientBaseError.apply(this, arguments);
}
util.inherits(InternalError, _DockerRegistryClientBaseError);
InternalError.prototype.code = 'InternalError';


function ManifestVerificationError() {
    _DockerRegistryClientBaseError.apply(this, arguments);
}
util.inherits(ManifestVerificationError, _DockerRegistryClientBaseError);
ManifestVerificationError.prototype.code = 'ManifestVerificationError';


function DownloadError() {
    _DockerRegistryClientBaseError.apply(this, arguments);
}
util.inherits(DownloadError, _DockerRegistryClientBaseError);
DownloadError.prototype.code = 'DownloadError';


function UnauthorizedError() {
    _DockerRegistryClientBaseError.apply(this, arguments);
}
util.inherits(UnauthorizedError, _DockerRegistryClientBaseError);
UnauthorizedError.prototype.code = 'UnauthorizedError';
UnauthorizedError.prototype.statusCode = 401;


// ---- exports

module.exports = {
    InternalError: InternalError,
    ManifestVerificationError: ManifestVerificationError,
    DownloadError: DownloadError,
    UnauthorizedError: UnauthorizedError,
};

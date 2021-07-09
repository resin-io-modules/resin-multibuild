/* eslint-disable @typescript-eslint/no-var-requires */
/*
 * Adapted from code found in https://github.com/joyent/node-docker-registry-client
*/

'use strict';

const assert = require('assert-plus');
const crypto = require('crypto');
const restifyClients = require('restify-clients');
const restifyErrors = require('restify-errors');
const util = require('util');
const zlib = require('zlib');

const StringClient = restifyClients.StringClient;


// --- API

function DockerJsonClient(options) {
    assert.object(options, 'options');

    options.accept = 'application/json';
    options.name = options.name || 'DockerJsonClient';
    options.contentType = 'application/json';

    StringClient.call(this, options);

    this._super = StringClient.prototype;
}
util.inherits(DockerJsonClient, StringClient);


DockerJsonClient.prototype.write = function (options, body, callback) {
    assert.object(body, 'body');

    // This is change #3.
    const resBody = JSON.stringify(body);
    return (this._super.write.call(this, options, resBody, callback));
};


DockerJsonClient.prototype.parse = function (req, callback) {
    const parseResponse = (err, res) => {
        const chunks = []; // gunzipped response chunks (Buffer objects)
        let len = 0; // accumulated count of chunk lengths
        let contentMd5;
        let contentMd5Hash;
        let gz;
        let resErr = err;

        const finish = () => {
            const body = Buffer.concat(chunks, len);
            if (res.log?.trace()) {
                res.log?.trace({body: body.toString(), len: len, url: req.path},
                    'body received');
            }

            // Content-Length check
            const contentLength = Number(res.headers['content-length']);
            if (!isNaN(contentLength) && len !== contentLength) {
                resErr = new restifyErrors.InvalidContentError(util.format(
                    'Incomplete content: Content-Length:%s but got %s bytes',
                    contentLength, len));
                callback(resErr, req, res);
                return;
            }

            // Content-MD5 check.
            if (contentMd5Hash &&
                contentMd5 !== contentMd5Hash.digest('base64'))
            {
                resErr = new restifyErrors.BadDigestError('Content-MD5');
                callback(resErr, req, res);
                return;
            }

            // Parse the body as JSON, if we can.
            // Note: This regex-based trim works on a buffer. `trim()` doesn't.
            let obj;
            if (len && !/^\s*$/.test(body)) {  // Skip all-whitespace body.
                try {
                    obj = JSON.parse(body);
                } catch (jsonErr) {
                    res.log?.trace(jsonErr, 'Invalid JSON in response');
                    if (!resErr) {
                        resErr = new restifyErrors.InvalidContentError(
                            'Invalid JSON in response');
                    }
                }
            }

            // Special error handling.
            if (resErr) {
                resErr.message = body.toString('utf8');
            }
            if (res && res.statusCode >= 400) {
                // Upcast error to a RestError (if we can)
                // Be nice and handle errors like
                // { error: { code: '', message: '' } }
                // in addition to { code: '', message: '' }.
                if (obj && (obj.code || (obj.error && obj.error.code))) {
                    const _c = obj.code ||
                        (obj.error ? obj.error.code : '') ||
                        '';
                    const _m = obj.message ||
                        (obj.error ? obj.error.message : '') ||
                        '';

                    resErr = new restifyErrors.RestError({
                        message: _m,
                        restCode: _c,
                        statusCode: res.statusCode
                    });
                    resErr.name = resErr.restCode;

                    if (!/Error$/.test(resErr.name)) {
                        resErr.name += 'Error';
                    }
                } else if (!resErr) {
                    resErr = restifyErrors.makeErrFromCode(res.statusCode,
                        obj.message || '', body);
                }
            }
            if (resErr && obj) {
                resErr.body = obj;
            }

            callback(resErr, req, res, obj, body);
        }


        if (!res) {
            // Early out if we didn't even get a response.
            callback(resErr, req);
            return;
        }

        // Content-MD5 setup.
        contentMd5 = res.headers['content-md5'];
        if (contentMd5 && req.method !== 'HEAD' && res.statusCode !== 206) {
            contentMd5Hash = crypto.createHash('md5');
        }

        if (res.headers['content-encoding'] === 'gzip') {
            gz = zlib.createGunzip();
            gz.on('data', (chunk) => {
                chunks.push(chunk);
                len += chunk.length;
            });
            gz.once('end', finish);
            res.once('end', gz.end.bind(gz));
        } else {
            res.once('end', finish);
        }

        res.on('data', (chunk) => {
            if (contentMd5Hash) {
                contentMd5Hash.update(chunk.toString('utf8'));
            }

            if (gz) {
                gz.write(chunk);
            } else {
                chunks.push(chunk);
                len += chunk.length;
            }
        });
    }

    return (parseResponse);
};

// --- Exports

module.exports = DockerJsonClient;

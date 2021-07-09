/* eslint-disable @typescript-eslint/no-var-requires */
/*
 * Adapted from code found in https://github.com/joyent/node-docker-registry-client
*/

const assert = require('assert-plus');
const base64url = require('base64url');
const bunyan = require('bunyan');
const crypto = require('crypto');
const fmt = require('util').format;
const jwkToPem = require('jwk-to-pem');
const mod_jws = require('jws');
const querystring = require('querystring');
const restifyClients = require('restify-clients');
const restifyErrors = require('restify-errors');
const strsplit = require('strsplit');
const mod_url = require('url');
const vasync = require('vasync');

const common = require('./common');
const DockerJsonClient = require('./docker-json-client');
const errors = require('./errors');


// --- Globals

const DEFAULT_V2_REGISTRY = 'https://registry-1.docker.io';
const MEDIATYPE_MANIFEST_V2
    = 'application/vnd.docker.distribution.manifest.v2+json';
const MEDIATYPE_MANIFEST_LIST_V2
    = 'application/vnd.docker.distribution.manifest.list.v2+json';


// --- internal support functions

function ensureLogger(log) {
    assert.optionalObject(log, 'log');

    if (log) {
        return log.child({
            serializers: restifyClients.bunyan.serializers
        });
    } else {
        return bunyan.createLogger({
            name: 'registry',
            serializers: restifyClients.bunyan.serializers
        });
    }
}


function formatBasicAuthHeader(username, password) {
    const buffer = new Buffer(username + ':' + password, 'utf8');
    return 'Basic ' + buffer.toString('base64');
}


/*
 * Set the "Authorization" HTTP header into the headers object from the given
 * auth info.
 * - Bearer auth if `token`.
 * - Else, Basic auth if `username`.
 * - Else, if the authorization key exists, then it is removed from headers.
 */
function setAuthHeaderFromAuthInfo(headers, authInfo) {
    if (authInfo.token) {
        headers.authorization = 'Bearer ' + authInfo.token;
    } else if (authInfo.username) {
        headers.authorization = formatBasicAuthHeader(authInfo.username,
            authInfo.password);
    } else if (headers.authorization) {
        delete headers.authorization;
    }
}

function getRegistryErrorMessage(err) {
    if (err.body && Array.isArray(err.body.errors) && err.body.errors[0]) {
        return err.body.errors[0].message;
    } else if (err.body && err.body.details) {
        return err.body.details;
    } else if (Array.isArray(err.errors) && err.errors[0].message) {
        return err.errors[0].message;
    } else if (err.message) {
        return err.message;
    }
    return err.toString();
}

/**
 * Return a scope string to be used for an auth request. Example:
 *   repository:library/nginx:pull
 */
function makeAuthScope(resource, name, actions) {
    return fmt('%s:%s:%s', resource, name, actions.join(','));
}

function parseWWWAuthenticate(header) {
    const parsers = require('www-authenticate/lib/parsers');
    const parsed = new parsers.WWW_Authenticate(header);
    if (parsed.err) {
        throw new Error('could not parse WWW-Authenticate header "' + header
            + '": ' + parsed.err);
    }
    return parsed;
}


/**
 * Get an auth token.
 *
 * See: docker/docker.git:registry/token.go
 */
 function getRegistryAuthToken(opts, cb) {
    assert.string(opts.indexName, 'opts.indexName'); // used for error messages
    assert.string(opts.realm, 'opts.realm');
    assert.optionalString(opts.service, 'opts.service');
    assert.optionalArrayOfString(opts.scopes, 'opts.scopes');
    assert.optionalString(opts.username, 'opts.username');
    assert.optionalString(opts.password, 'opts.password');
    // HTTP client opts:
    //assert.object(opts.log, 'opts.log');
    assert.optionalObject(opts.agent, 'opts.agent');
    // assert.optional object or bool(opts.proxy, 'opts.proxy');
    assert.optionalBool(opts.insecure, 'opts.insecure');
    assert.optionalString(opts.userAgent, 'opts.userAgent');
    const log = opts.log;

    // - add https:// prefix (or http) if none on 'realm'
    let tokenUrl = opts.realm;
    const match = /^(\w+):\/\//.exec(tokenUrl);
    if (!match) {
        tokenUrl = (opts.insecure ? 'http' : 'https') + '://' + tokenUrl;
    } else if (['http', 'https'].indexOf(match[1]) === -1) {
        return cb(new Error(fmt('unsupported scheme for ' +
            'WWW-Authenticate realm "%s": "%s"', opts.realm, match[1])));
    }

    // - GET $realm
    //      ?service=$service
    //      (&scope=$scope)*
    //      (&account=$username)
    //   Authorization: Basic ...
    const headers = {};
    const query = {};
    if (opts.service) {
        query.service = opts.service;
    }
    if (opts.scopes && opts.scopes.length) {
        query.scope = opts.scopes;  // intentionally singular 'scope'
    }

    if (opts.username) {
        query.account = opts.username;
        setAuthHeaderFromAuthInfo(headers, {
            username: opts.username,
            password: opts.password
        });
    }
    if (Object.keys(query).length) {
        tokenUrl += '?' + querystring.stringify(query);
    }
    log.trace({tokenUrl: tokenUrl}, '_getToken: url');

    const parsedUrl = mod_url.parse(tokenUrl);
    const client = new DockerJsonClient({
        url: parsedUrl.protocol + '//' + parsedUrl.host,
        log: log,
        agent: opts.agent,
        proxy: opts.proxy,
        rejectUnauthorized: !opts.insecure,
        userAgent: opts.userAgent || common.DEFAULT_USERAGENT
    });
    client.get({
        path: parsedUrl.path,
        headers: headers
    }, (err, req, res, body) => {
        client.close();
        if (err) {
            if (err.statusCode === 401) {
                // Convert *all* 401 errors to use a generic error constructor
                // with a simple error message.
                const errMsg = getRegistryErrorMessage(err);
                return cb(new errors.UnauthorizedError(errMsg));
            }
            return cb(err);
        } else if (!body.token) {
            return cb(new errors.UnauthorizedError(err, 'authorization ' +
                'server did not include a token in the response'));
        }
        cb(null, body.token);
    });
}

function jwsFromManifest(manifest, body) {
    assert.object(manifest, 'manifest');
    assert.buffer(body, 'body');

    let formatLength;
    let formatTail;
    const jws = {
        signatures: []
    };

    for (let i = 0; i < manifest.signatures.length; i++) {
        const sig = manifest.signatures[i];

        let protectedHeader;
        try {
            protectedHeader = JSON.parse(
                base64url.decode(sig['protected']));
        } catch (protectedErr) {
            throw new restifyErrors.InvalidContentError(protectedErr, fmt(
                'could not parse manifest "signatures[%d].protected": %j',
                i, sig['protected']));
        }
        if (isNaN(protectedHeader.formatLength)) {
            throw new restifyErrors.InvalidContentError(fmt(
                'invalid "formatLength" in "signatures[%d].protected": %j',
                i, protectedHeader.formatLength));
        } else if (formatLength === undefined) {
            formatLength = protectedHeader.formatLength;
        } else if (protectedHeader.formatLength !== formatLength) {
            throw new restifyErrors.InvalidContentError(fmt(
                'conflicting "formatLength" in "signatures[%d].protected": %j',
                i, protectedHeader.formatLength));
        }

        if (!protectedHeader.formatTail ||
            typeof (protectedHeader.formatTail) !== 'string')
        {
            throw new restifyErrors.InvalidContentError(fmt(
                'missing "formatTail" in "signatures[%d].protected"', i));
        }
        const formatTail_ = base64url.decode(protectedHeader.formatTail);
        if (formatTail === undefined) {
            formatTail = formatTail_;
        } else if (formatTail_ !== formatTail) {
            throw new restifyErrors.InvalidContentError(fmt(
                'conflicting "formatTail" in "signatures[%d].protected": %j',
                i, formatTail_));
        }

        const jwsSig = {
            header: {
                alg: sig.header.alg,
                chain: sig.header.chain
            },
            signature: sig.signature,
            'protected': sig['protected']
        };
        if (sig.header.jwk) {
            try {
                jwsSig.header.jwk = jwkToPem(sig.header.jwk);
            } catch (jwkErr) {
                throw new restifyErrors.InvalidContentError(jwkErr, fmt(
                    'error in "signatures[%d].header.jwk": %s',
                    i, jwkErr.message));
            }
        }
        jws.signatures.push(jwsSig);
    }

    jws.payload = Buffer.concat([
        body.slice(0, formatLength),
        new Buffer(formatTail)
    ]);

    return jws;
}


/*
 * Parse the 'Docker-Content-Digest' header.
 *
 * @throws {BadDigestError} if the value is missing or malformed
 * @returns ...
 */
function parseDockerContentDigest(dcd) {
    if (!dcd) {
        throw new restifyErrors.BadDigestError(
            'missing "Docker-Content-Digest" header');
    }

    // E.g. docker-content-digest: sha256:887f7ecfd0bda3...
    const parts = strsplit(dcd, ':', 2);
    if (parts.length !== 2) {
        throw new restifyErrors.BadDigestError(
            'could not parse "Docker-Content-Digest" header: ' + dcd);
    }

    let hash;
    try {
        hash = crypto.createHash(parts[0]);
    } catch (hashErr) {
        throw new restifyErrors.BadDigestError(hashErr, fmt(
            '"Docker-Content-Digest" header error: %s: %s',
            hashErr.message, dcd));
    }
    const expectedDigest = parts[1];

    return {
        raw: dcd,
        hash: hash,
        algorithm: parts[0],
        expectedDigest: expectedDigest
    };
}

/*
 * Verify the 'Docker-Content-Digest' header for a getManifest response.
 *
 * @throws {BadDigestError} if the digest doesn't check out.
 */
function verifyManifestDockerContentDigest(res, jws) {
    const dcdInfo = parseDockerContentDigest(
        res.headers['docker-content-digest']);

    dcdInfo.hash.update(jws.payload);
    const digest = dcdInfo.hash.digest('hex');
    if (dcdInfo.expectedDigest !== digest) {
        res.log.trace({expectedDigest: dcdInfo.expectedDigest,
            header: dcdInfo.raw, digest: digest},
            'Docker-Content-Digest failure');
        throw new restifyErrors.BadDigestError('Docker-Content-Digest');
    }
}

function verifyJws(jws) {
    const encodedPayload = base64url(jws.payload);

    /*
     * Disallow the "none" algorithm because while the `jws` module might have
     * a guard against
     *      // JSSTYLED
     *      https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/
     * why bother allowing it?
     */
    const disallowedAlgs = ['none'];

    for (let i = 0; i < jws.signatures.length; i++) {
        const jwsSig = jws.signatures[i];
        const alg = jwsSig.header.alg;
        if (disallowedAlgs.indexOf(alg) !== -1) {
            throw new errors.ManifestVerificationError(
                {jws: jws, i: i}, 'disallowed JWS signature algorithm:', alg);
        }

        if (jwsSig.header.chain) {
            throw new errors.InternalError({jws: jws, i: i},
                'JWS verification with a cert "chain" is not implemented: %j',
                jwsSig.header.chain);
        }

        // `mod_jws.verify` takes the JWS compact representation.
        const jwsCompact = jwsSig['protected'] + '.' + encodedPayload +
            '.' + jwsSig.signature;
        const verified = mod_jws.verify(jwsCompact, alg, jwsSig.header.jwk);
        if (!verified) {
            throw new errors.ManifestVerificationError(
                {jws: jws, i: i}, 'JWS signature %d failed verification', i);
        }
    }
}


// --- other exports

/**
 * Ping the base URL.
 * See: <https://docs.docker.com/registry/spec/api/#base>
 *
 * @param opts {Object} Required members are listed first.
 *      - opts.index {String|Object} Required. One of an index *name* (e.g.
 *        "docker.io", "quay.io") that `parseIndex` will handle, an index
 *        *url* (e.g. the default from `docker login` is
 *        'https://index.docker.io/v1/'), or an index *object* as returned by
 *        `parseIndex`. For backward compatibility, `opts.indexName` may be
 *        used instead of `opts.index`.
 *      --
 *      - opts.log {Bunyan Logger} Optional.
 *      --
 * @param cb {Function} `function (err, body, res, req)`
 *      `err` is set if there was a problem getting a ping response. `res` is
 *      the response object. Use `res.statusCode` to infer information:
 *          404     This registry URL does not support the v2 API.
 *          401     Authentication is required (or failed). Use the
 *                  WWW-Authenticate header for the appropriate auth method.
 *                  This `res` can be passed to `login()` to handle
 *                  authenticating.
 *          200     Successful authentication. The response body is `body`
 *                  if wanted.
 */
 function ping(opts, cb) {
    assert.func(cb, 'cb');
    assert.object(opts, 'opts');
    assert.ok(opts.index || opts.indexName,
        'opts.index or opts.indexName is required');
    //assert.optionalObject(opts.log, 'opts.log');
    // HTTP client basic options:
    assert.optionalBool(opts.insecure, 'opts.insecure');
    assert.optionalBool(opts.rejectUnauthorized, 'opts.rejectUnauthorized');
    assert.optionalString(opts.userAgent, 'opts.userAgent');
    assert.optionalObject(opts.agent, 'opts.agent');
    // assert.optional object or bool(opts.proxy, 'opts.proxy');

    let index = opts.index || opts.indexName;
    if (typeof (index) === 'string') {
        try {
            index = common.parseIndex(index);
        } catch (indexNameErr) {
            cb(indexNameErr);
            return;
        }
    } else {
        assert.object(index, 'opts.index');
    }

    const log = ensureLogger(opts.log);
    log.trace({index: index, scope: opts.scope, insecure: opts.insecure},
        'ping');

    /*
     * We have to special case usage of the "official" docker.io to
     *      https://registry-1.docker.io
     * because:
     *      GET /v2/ HTTP/1.1
     *      Host: index.docker.io
     *
     *      HTTP/1.1 301 Moved Permanently
     *      location: https://registry.hub.docker.com/v2/
     * and:
     *      $ curl -i https://registry.hub.docker.com/v2/
     *      HTTP/1.1 404 NOT FOUND
     */
    let registryUrl;
    if (index.official) {
        registryUrl = DEFAULT_V2_REGISTRY;
    } else {
        registryUrl = common.urlFromIndex(index);
    }

    /*
     * We allow either opts.rejectUnauthorized (for passed in http client
     * options where `insecure` -> `rejectUnauthorized` translation has
     * already been done) or opts.insecure (this module's chosen name
     * for this thing).
     */
    let rejectUnauthorized;
    if (opts.insecure !== undefined && opts.rejectUnauthorized !== undefined) {
        throw new assert.AssertionError(
            'cannot set both opts.insecure and opts.rejectUnauthorized');
    } else if (opts.insecure !== undefined) {
        rejectUnauthorized = !opts.insecure;
    } else if (opts.rejectUnauthorized !== undefined) {
        rejectUnauthorized = opts.rejectUnauthorized;
    }

    const client = new DockerJsonClient({
        url: registryUrl,
        log: opts.log,
        userAgent: opts.userAgent || common.DEFAULT_USERAGENT,
        rejectUnauthorized: rejectUnauthorized,
        agent: opts.agent,
        proxy: opts.proxy
    });

    client.get({
        path: '/v2/',
        // Ping should be fast. We don't want 15s of retrying.
        retry: false,
        connectTimeout: 10000
    }, (err, req, res, body) => {
        client.close();
        cb(err, body, res, req);
    });
}


/**
 * Login V2
 *
 * Typically one does not need to call this function directly because most
 * methods of a `RegistryClientV2` will automatically login as necessary.
 * Once exception is the `ping` method, which intentionally does not login.
 * That is because the point of the ping is to determine quickly if the
 * registry supports v2, which doesn't require the extra work of logging in.
 *
 * This attempts to reproduce the logic of "docker.git:registry/auth.go#loginV2"
 *
 * @param opts {Object}
 *      - opts.index {String|Object} Required. One of an index *name* (e.g.
 *        "docker.io", "quay.io") that `parseIndex` will handle, an index
 *        *url* (e.g. the default from `docker login` is
 *        'https://index.docker.io/v1/'), or an index *object* as returned by
 *        `parseIndex`. For backward compatibility, `opts.indexName` may be
 *        used instead of `opts.index`.
 *      - opts.username {String} Optional. Username and password are optional
 *        to allow `RegistryClientV2` to use `login` in the common case when
 *        there may or may not be auth required.
 *      - opts.password {String} Optional, but required if `opts.username` is
 *        provided.
 *      - opts.scope {String} Optional. A scope string passed in for
 *        bearer/token auth. If this is just a login request where the token
 *        won't be used, then the empty string (the default) is sufficient.
 *        // JSSTYLED
 *        See <https://github.com/docker/distribution/blob/master/docs/spec/auth/token.md#requesting-a-token>
 *      - opts.pingRes {Object} Optional. The response object from an earlier
 *        `ping()` call. This can be used to save re-pinging.
 *      - opts.pingErr {Object} Required if `pingRes` given. The error
 *        object for `pingRes`.
 *      ...
 * @param cb {Function} `function (err, result)`
 *      On success, `result` is an object with:
 *          status      a string description of the login result status
 *          authInfo    an object with authentication info, examples:
 *                          {type: 'basic', username: '...', password: '...'}
 *                          {type: 'bearer', token: '...'}
 *                      which can be the empty object when no auth is needed:
 *                          {}
 */
 function login(opts, cb) {
    assert.object(opts, 'opts');
    assert.ok(opts.index || opts.indexName,
        'opts.index or opts.indexName is required');
    assert.optionalString(opts.username, 'opts.username');
    if (opts.username) {
        assert.string(opts.password,
            'opts.password required if username given');
    } else {
        assert.optionalString(opts.password, 'opts.password');
    }
    assert.optionalString(opts.scope, 'opts.scope');
    assert.optionalString(opts.userAgent, 'opts.userAgent');
    assert.optionalBool(opts.insecure, 'opts.insecure');
    assert.optionalObject(opts.pingRes, 'opts.pingRes');
    if (opts.pingRes && opts.pingRes.statusCode !== 200) {
        assert.object(opts.pingErr, 'opts.pingErr');
    } else {
        assert.optionalObject(opts.pingErr, 'opts.pingErr');
    }
    //assert.optionalObject(opts.log, 'opts.log');
    assert.optionalString(opts.userAgent, 'opts.userAgent');
    assert.optionalObject(opts.agent, 'opts.agent');
    // assert.optional object or bool(opts.proxy, 'opts.proxy');
    assert.func(cb, 'cb');

    let index = opts.index || opts.indexName;
    if (typeof (index) === 'string') {
        try {
            index = common.parseIndex(index);
        } catch (indexNameErr) {
            cb(indexNameErr);
            return;
        }
    } else {
        assert.object(index, 'opts.index');
    }

    const log = ensureLogger(opts.log);
    log.trace({index: index, username: opts.username,
        password: (opts.password ? '(censored)' : '(none)'),
        scope: opts.scope, insecure: opts.insecure}, 'login');

    const scope = opts.scope || '';
    let authInfo;
    const context = {
        pingErr: opts.pingErr
    };

    vasync.pipeline({arg: context, funcs: [
        // ensureChalHeader
        (ctx, next) => {
            if (opts.pingRes) {
                ctx.chalHeader = opts.pingRes.headers['www-authenticate'];
                if (ctx.chalHeader) {
                    return next();
                }
            }
            ping(opts, (err, _, res, req) => {
                if (!err) {
                    assert.equal(res.statusCode, 200,
                        'ping success without 200');
                    // No authorization is necessary.
                    authInfo = {};
                    next(true);  // early pipeline abort
                } else if (res && res.statusCode === 401) {
                    let chalHeader = res.headers['www-authenticate'];

                    // DOCKER-627 hack for quay.io
                    if (!chalHeader && req._headers.host === 'quay.io') {
                        /* JSSTYLED */
                        chalHeader = 'Bearer realm="https://quay.io/v2/auth",service="quay.io"';
                    }

                    if (!chalHeader) {
                        next(new errors.UnauthorizedError(
                            'missing WWW-Authenticate header in 401 ' +
                            'response to "GET /v2/" (see ' +
                            /* JSSTYLED */
                            'https://docs.docker.com/registry/spec/api/#api-version-check)'));
                        return;
                    }

                    ctx.pingErr = err;
                    ctx.chalHeader = chalHeader;
                    next();
                } else {
                    next(err);
                }
            });
        },

        // parseAuthChallenge
        (ctx, next) => {
            try {
                ctx.authChallenge = parseWWWAuthenticate(ctx.chalHeader);
            } catch (chalErr) {
                return next(new errors.UnauthorizedError(chalErr));
            }
            next();
        },

        // basicAuth
        (ctx, next) => {
            if (ctx.authChallenge.scheme.toLowerCase() !== 'basic') {
                return next();
            }

            authInfo = {
                type: 'basic',
                username: opts.username,
                password: opts.password
            };
            next(true);
        },

        // bearerAuth
        (ctx, next) => {
            if (ctx.authChallenge.scheme.toLowerCase() !== 'bearer') {
                return next();
            }
            log.debug({challenge: ctx.authChallenge},
                'login: get Bearer auth token');

            getRegistryAuthToken({
                indexName: index.name,
                realm: ctx.authChallenge.parms.realm,
                service: ctx.authChallenge.parms.service,
                scopes: scope ? [scope] : [],
                username: opts.username,
                password: opts.password,
                // HTTP client opts:
                log: log,
                agent: opts.agent,
                proxy: opts.proxy,
                userAgent: opts.userAgent,
                insecure: opts.insecure
            }, (err, token) => {
                if (err) {
                    return next(err);
                }
                log.debug({token: token}, 'login: Bearer auth token');
                authInfo = {
                    type: 'bearer',
                    token: token
                };
                next(true); // early pipeline abort
            });
        },

        // unknownAuthScheme
        (ctx, next) => {
            next(new errors.UnauthorizedError('unsupported auth scheme: "%s"',
                ctx.authChallenge.scheme));
        }

    ]}, (err) => {
        if (err === true) { // early abort
            err = null;
        }
        log.trace({err: err, success: !err}, 'login: done');
        if (err) {
            cb(err);
        } else {
            assert.object(authInfo, 'authInfo');
            cb(null, {
                status: 'Login Succeeded',
                authInfo: authInfo
            });
        }
    });
}


// --- RegistryClientV2

function RegistryClientV2(opts) {

    assert.object(opts, 'opts');
    // One of `opts.name` or `opts.repo`.
    assert.ok((opts.name || opts.repo) && !(opts.name && opts.repo),
        'exactly one of opts.name or opts.repo must be given');
    if (opts.name) {
        assert.string(opts.name, 'opts.name');
    } else {
        assert.object(opts.repo, 'opts.repo');
    }
    //assert.optionalObject(opts.log, 'opts.log');
    assert.optionalString(opts.username, 'opts.username');
    if (opts.username) {
        assert.string(opts.password,
            'opts.password required if username given');
    } else {
        assert.optionalString(opts.password, 'opts.password');
    }
    assert.optionalString(opts.token, 'opts.token');  // for Bearer auth
    assert.optionalBool(opts.insecure, 'opts.insecure');
    assert.optionalString(opts.scheme, 'opts.scheme');
    assert.optionalBool(opts.acceptManifestLists, 'opts.acceptManifestLists');
    assert.optionalNumber(opts.maxSchemaVersion, 'opts.maxSchemaVersion');
    assert.optionalBool(opts.agent, 'opts.agent');
    assert.optionalString(opts.userAgent, 'opts.userAgent');

    this.log = ensureLogger(opts.log);

    this.insecure = Boolean(opts.insecure);
    if (opts.name) {
        this.repo = common.parseRepo(opts.name);
    } else {
        this.repo = common.deepObjCopy(opts.repo);
    }
    if (opts.scheme) {
        this.repo.index.scheme = opts.scheme;
    } else if (!this.repo.index.scheme &&
        common.isLocalhost(this.repo.index.name))
    {
        // Per docker.git:registry/config.go#NewServiceConfig we special
        // case localhost to allow HTTP. Note that this lib doesn't do
        // the "try HTTPS, then fallback to HTTP if allowed" thing that
        // Docker-docker does, we'll just prefer HTTP for localhost.
        this.repo.index.scheme = 'http';
    }

    this.acceptManifestLists = opts.acceptManifestLists || false;
    this.maxSchemaVersion = opts.maxSchemaVersion || 1;
    this.username = opts.username;
    this.password = opts.password;
    this._loggedIn = false;
    this._loggedInScope = null; // Keeps track of the login type.
    this._authInfo = null;
    this._headers = {};

    setAuthHeaderFromAuthInfo(this._headers, {
        token: opts.token,
        username: opts.username,
        password: opts.password
    });

    // XXX relevant for v2?
    //this._cookieJar = new tough.CookieJar();

    if (this.repo.index.official) {  // v1
        this._url = DEFAULT_V2_REGISTRY;
    } else {
        this._url = common.urlFromIndex(this.repo.index);
    }
    this.log.trace({url: this._url}, 'RegistryClientV2 url');

    this._commonHttpClientOpts = {
        log: this.log,
        agent: opts.agent,
        proxy: opts.proxy,
        rejectUnauthorized: !this.insecure,
        userAgent: opts.userAgent || common.DEFAULT_USERAGENT
    };
    this._clientsToClose = [];

    Object.defineProperty(this, '_api', {
        get: () => {
            if (this.__api === undefined) {
                this.__api = new DockerJsonClient(common.objMerge({
                    url: this._url
                }, this._commonHttpClientOpts));
                this._clientsToClose.push(this.__api);
            }
            return this.__api;
        }
    });

    Object.defineProperty(this, '_httpapi', {
        get: () => {
            if (this.__httpapi === undefined) {
                this.__httpapi = new restifyClients.HttpClient(common.objMerge({
                    url: this._url
                }, this._commonHttpClientOpts));
                this._clientsToClose.push(this.__httpapi);
            }
            return this.__httpapi;
        }
    });
}


RegistryClientV2.prototype.version = 2;


RegistryClientV2.prototype.close = function close() {
    for (let i = 0; i < this._clientsToClose.length; i++) {
        const client = this._clientsToClose[i];
        this.log.trace({host: client.url && client.url.host},
            'close http client');
        client.close();
    }
    this._clientsToClose = [];
};


/**
 * Ping the base URL.
 * https://docs.docker.com/registry/spec/api/#base
 */
RegistryClientV2.prototype.ping = function regPing(cb) {
    ping(common.objMerge({
        index: this.repo.index,
        username: this.username,
        password: this.password,
        authInfo: this._authInfo
    }, this._commonHttpClientOpts), cb);
};


/**
 * Get a registry session (i.e. login to the registry).
 *
 * Typically one does not need to call this method directly because most
 * methods of a client will automatically login as necessary.
 * Once exception is the `ping` method, which intentionally does not login.
 * That is because the point of the ping is to determine quickly if the
 * registry supports v2, which doesn't require the extra work of logging in.
 * See <https://github.com/joyent/node-docker-registry-client/pull/6> for
 * an example of the latter.
 *
 * This attempts to reproduce the logic of "docker.git:registry/auth.go#loginV2"
 *
 * @param opts {Object} Optional.
 *      - opts.pingRes {Object} Optional. The response object from an earlier
 *        `ping()` call. This can be used to save re-pinging.
 *      - opts.pingErr {Object} Required if `pingRes` given. The error
 *        object for `pingRes`.
 *      - opts.scope {String} Optional. Scope to use in the auth Bearer token.
 * @param cb {Function} `function (err)`
 *
 * Side-effects:
 * - On success, all of `this._loggedIn*`, `this._authInfo`, and
 *   `this._headers.authorization` are set.
 */
RegistryClientV2.prototype.login = function regLogin(opts, cb) {
    if (cb === undefined) {
        cb = opts;
        opts = {};
    }
    assert.object(opts, 'opts');
    assert.func(cb, 'cb');

    let scope = opts.scope;
    if (!scope) {
        const resource = 'repository';
        const actions = ['pull'];
        scope = makeAuthScope(resource, this.repo.remoteName, actions);
    }

    if (this._loggedIn && this._loggedInScope === scope) {
        return cb();
    }

    login(common.objMerge({
        index: this.repo.index,
        username: this.username,
        password: this.password,
        pingRes: opts.pingRes,
        pingErr: opts.pingErr,
        scope: scope
    }, this._commonHttpClientOpts), (err, result) => {
        if (!err) {
            assert.ok(result);
            this._loggedIn = true;
            this._loggedInScope = scope;
            this._authInfo = result.authInfo;
            setAuthHeaderFromAuthInfo(this._headers, this._authInfo);
        }
        this.log.trace({err: err, loggedIn: this._loggedIn}, 'login: done');
        cb(err);
    });
};

/**
 * Determine if this registry supports the v2 API.
 * https://docs.docker.com/registry/spec/api/#api-version-check
 *
 * Note that, at least, currently we are presuming things are fine with a 401.
 * I.e. defering auth to later calls.
 *
 * @param cb {Function} `function (err, supportsV2)`
 *      where `supportsV2` is a boolean indicating if V2 API is supported.
 */
RegistryClientV2.prototype.supportsV2 = function supportsV2(cb) {

    this.ping((err, body, res) => {
        if (res && (res.statusCode === 200 || res.statusCode === 401)) {
            const header = res.headers['docker-distribution-api-version'];
            if (header) {
                /*
                 * Space- or comma-separated. The latter occurs if there are
                 * two separate headers, e.g.:
                 *      $ curl -i https://registry.example.com/v2/
                 *      HTTP/1.1 200 OK
                 *      ...
                 *      Docker-Distribution-Api-Version: registry/2.0
                 *      ...
                 *      Docker-Distribution-Api-Version: \
                 */
                // JSSTYLED
                const versions = header.split(/[\s,]+/g);
                if (versions.indexOf('registry/2.0') !== -1) {
                    return cb(null, true);
                }
            }
            cb(null, true);
            return;
        }
        this.log.trace({err: err, res: res}, 'supportsV2 response');
        cb(err, false);
    });
};

/*
 * Get an image manifest. `ref` is either a tag or a digest.
 * <https://docs.docker.com/registry/spec/api/#pulling-an-image-manifest>
 *
 *   client.getManifest({ref: <tag or digest>}, function (err, manifest, res,
 *      manifestStr) {
 *      // Use `manifest` and digest is `res.headers['docker-content-digest']`.
 *      // Note that docker-content-digest header can be undefined, so if you
 *      // need a manifest digest, use the `digestFromManifestStr` function.
 *   });
 */
RegistryClientV2.prototype.getManifest = function getManifest(opts, cb) {

    assert.object(opts, 'opts');
    assert.string(opts.ref, 'opts.ref');
    assert.optionalBool(opts.acceptManifestLists, 'opts.acceptManifestLists');
    assert.optionalNumber(opts.maxSchemaVersion, 'opts.maxSchemaVersion');
    assert.optionalBool(opts.followRedirects, 'opts.followRedirects');
    assert.func(cb, 'cb');

    let acceptManifestLists = opts.acceptManifestLists;
    if (typeof (acceptManifestLists) === 'undefined') {
        acceptManifestLists = this.acceptManifestLists;
    }
    const maxSchemaVersion = (opts.maxSchemaVersion || this.maxSchemaVersion);
    let res, manifest, manifestStr;

    vasync.pipeline({arg: this, funcs: [
        // doLogin
        (_, next) => {
            this.login(next);
        },
        // call
        (_, next) => {
            let headers = this._headers;
            if (maxSchemaVersion === 2) {
                let accept = [];
                if (this._headers.accept) {
                    // Accept may be a string or an array - we want an array.
                    if (Array.isArray(this._headers.accept)) {
                        accept = this._headers.accept.slice(); // a copy
                    } else {
                        accept = [this._headers.accept];
                    }
                }
                accept.push(MEDIATYPE_MANIFEST_V2);
                if (acceptManifestLists) {
                    accept.push(MEDIATYPE_MANIFEST_LIST_V2);
                }
                headers = common.objMerge({}, this._headers, {accept: accept});
            }
            const requestOpts = {
                method: 'get',
                url: this._url,
                path: fmt('/v2/%s/manifests/%s',
                    encodeURI(this.repo.remoteName),
                    encodeURI(opts.ref)),
                headers: headers
            };
            if (Object.prototype.hasOwnProperty.call(opts, 'followRedirects')) {
                requestOpts.followRedirects = opts.followRedirects;
            }
            this._makeJsonRequest(requestOpts,
                (err, req, res_, manifest_, body) => {
                res = res_;
                if (err) {
                    if (err.statusCode === 401) {
                        // Convert into a 404 error.
                        // If we get an Unauthorized error here, it actually
                        // means the repo does not exist, otherwise we should
                        // have received an unauthorized error during the
                        // doLogin step and this code path would not be taken.
                        const errMsg = getRegistryErrorMessage(err);
                        return next(new restifyErrors.makeErrFromCode(404,
                            {message: errMsg}));
                    }

                    return next(err);
                }

                manifest = manifest_;
                manifestStr = String(body);

                if (manifest.schemaVersion === 1) {
                    try {
                        const jws = jwsFromManifest(manifest, body);
                        // Some v2 registries (Amazon ECR) do not provide the
                        // 'docker-content-digest' header.
                        if (res_.headers['docker-content-digest']) {
                            verifyManifestDockerContentDigest(res_, jws);
                        } else {
                            this.log.debug({headers: res_.headers},
                                'no Docker-Content-Digest header on ' +
                                'getManifest response');
                        }
                        verifyJws(jws);
                    } catch (verifyErr) {
                        return next(verifyErr);
                    }
                }

                if (manifest.schemaVersion > maxSchemaVersion) {
                    cb(new restifyErrors.InvalidContentError(fmt(
                        'unsupported schema version %s in %s:%s manifest',
                        manifest.schemaVersion, this.repo.localName,
                        opts.ref)));
                    return;
                }

                // Verify the manifest contents.
                if (manifest.mediaType === MEDIATYPE_MANIFEST_LIST_V2) {
                    if (!Array.isArray(manifest.manifests) ||
                            manifest.manifests.length === 0) {
                        cb(new restifyErrors.InvalidContentError(fmt(
                            'no manifests in %s:%s manifest list',
                            this.repo.localName, opts.ref)));
                        return;
                    }
                } else {
                    let layers = manifest.fsLayers;
                    if (manifest.schemaVersion === 1) {
                        if (layers.length !== manifest.history.length) {
                            cb(new restifyErrors.InvalidContentError(fmt(
                                'history length not equal to layers length in '
                                + '%s:%s manifest',
                                this.repo.localName, opts.ref)));
                            return;
                        }
                    } else if (manifest.schemaVersion === 2) {
                        layers = manifest.layers;
                    }
                    if (!layers || layers.length === 0) {
                        cb(new restifyErrors.InvalidContentError(fmt(
                            'no layers in %s:%s manifest', this.repo.localName,
                            opts.ref)));
                        return;
                    }
                }

                res = res_;
                next();
            });
        }
    ]}, (err) => {
        cb(err, manifest, res, manifestStr);
    });
};


/**
 * Makes a http request to the given url, following any redirects, then fires
 * the callback(err, req, responses) with the result.
 *
 * Note that 'responses' is an *array* of restify http response objects, with
 * the last response being at the end of the array. When there is more than
 * one response, it means a redirect has been followed.
 */
RegistryClientV2.prototype._makeHttpRequest = function _makeHttpRequest(opts, cb) {

    assert.object(opts, 'opts');
    assert.string(opts.method, 'opts.method');
    assert.string(opts.path, 'opts.path');
    assert.string(opts.url, 'opts.url');
    assert.optionalObject(opts.headers, 'opts.headers');
    assert.optionalBool(opts.followRedirects, 'opts.followRedirects');
    assert.optionalNumber(opts.maxRedirects, 'opts.maxRedirects');
    assert.func(cb, 'cb');

    let followRedirects = true;
    if (Object.prototype.hasOwnProperty.call(opts, 'followRedirects')) {
        followRedirects = opts.followRedirects;
    }
    const maxRedirects = opts.maxRedirects || 3;
    let numRedirs = 0;
    let req;
    let ress = [];

    const makeReq = (reqOpts) => {
        if (numRedirs >= maxRedirects) {
            cb(new errors.DownloadError(fmt(
                'maximum number of redirects (%s) hit',
                maxRedirects)), req, ress);
            return;
        }
        numRedirs += 1;

        const client = restifyClients.createHttpClient(common.objMerge({
            url: reqOpts.url
        }, this._commonHttpClientOpts));
        this._clientsToClose.push(client);

        client[opts.method](reqOpts, (connErr, req_) => {
            if (connErr) {
                cb(connErr, req, ress);
                return;
            }
            req = req_;
            req.on('result', (err, res) => {
                ress.push(res);
                if (err) {
                    cb(err, req, ress);
                    return;
                }
                if (followRedirects &&
                    (res.statusCode === 302 || res.statusCode === 307)) {
                    const loc = mod_url.parse(res.headers.location);
                    this.log.trace({numRedirs: numRedirs, loc: loc},
                        'got redir response');
                    makeReq({
                        url: loc.protocol + '//' + loc.host,
                        path: loc.path
                    });
                } else {
                    this.log.trace({res: res}, 'got a non-redir response');
                    cb(null, req, ress);
                }
            });
        });
    }

    makeReq({
        url: opts.url,
        path: opts.path,
        headers: opts.headers
    });
};

/**
 * Makes a http request to the given url, following any redirects, then parses
 * the (JSON) response and fires the callback(err, req, res, obj, body) with
 * the result. Note that 'obj' is the parsed JSON response object, 'body' is
 * the raw response body string.
 */
RegistryClientV2.prototype._makeJsonRequest =
function _makeJsonRequest(opts, cb) {

    assert.object(opts, 'opts');
    assert.func(cb, 'cb');

    this._makeHttpRequest(opts, (err, req, responses) => {
        const res = responses ? responses[responses.length - 1] : null;
        if (err) {
            cb(err, req, res);
            return;
        }
        // Parse the response body using the JSON client parser.
        const parseFn = DockerJsonClient.prototype.parse.call(this._api, req, cb);
        parseFn(err, res);
        // Release the bulls!
        res.resume();
    });
};

// --- Exports

function createClient(opts) {
    return new RegistryClientV2(opts);
}

module.exports = {
    createClient: createClient,
    ping: ping,
    login: login,
    MEDIATYPE_MANIFEST_V2: MEDIATYPE_MANIFEST_V2,
    MEDIATYPE_MANIFEST_LIST_V2: MEDIATYPE_MANIFEST_LIST_V2
};

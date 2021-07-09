
import * as base64url from 'base64url';
import * as bunyan from 'bunyan';
import * as crypto from 'crypto';
import { format } from 'util';
import * as jwkToPem from 'jwk-to-pem';
import * as mod_jws from 'jws';
import * as querystring from 'querystring';
import * as restifyClients from 'restify-clients';
import * as restifyErrors from 'restify-errors';
import * as strsplit from 'strsplit';
import * as mod_url from 'url';
import * as vasync from 'vasync';

import * as parsers from './www-parsers';
import * as common from './common';
import DockerJsonClient = require('./docker-json-client');
import * as errors from './errors';
import assert = require('assert');

// Globals
const DEFAULT_V2_REGISTRY = 'https://registry-1.docker.io';
const MEDIATYPE_MANIFEST_V2
    = 'application/vnd.docker.distribution.manifest.v2+json';
const MEDIATYPE_MANIFEST_LIST_V2
    = 'application/vnd.docker.distribution.manifest.list.v2+json';

export interface Logger {

    trace(arg0?: unknown, arg1?: unknown): void;
    info(arg0?: unknown, arg1?: unknown): void;
    debug(arg0?: unknown, arg1?: unknown): void;
}

export interface RegistryClientOptions {
//    index?: string; // TODO: ??
    realm?: string;
    service?: string;
    scopes?: string[];
    username?: string;
    password?: string;
    agent?: any; // TODO:  Boolean?
    insecure?: boolean;
    userAgent?: string;
    log?: Logger;
    proxy?: any;
    rejectUnauthorized?: boolean;
    pingRes?: any;
    pingErr?: boolean;
    repo?: string;
    name?: string;
    token?: string;
    acceptManifestLists?: boolean;
    maxSchemaVersion?: number;
    scope?: string;
    ref?: string;
    followRedirects?: boolean;
    method?: string; // TODO:
    path?: string;
    url?: string;
    headers?: any;
}

export interface RegistryRepo {
    //scheme?: 'http'|'https',
    indexUrl?: string,
    remoteName?: string,
    localName?: string,
    canonicalName?: string
}

interface RegistryLoginAuthInfo {
    type?: "basic" | "bearer" | "none",
    token?: string,
    username?: string,
    password?: string,
    scope?: string,
}

interface RegistryLoginConfiguration {
    insecure?: boolean;
    // realm?: string;
    // service?: string;
    scope?: string;
    username?: string;
    password?: string;
    authToken?: string;
}

interface RegistryConnectionConfiguration {
    agent?: any,
    proxy?: string,
    userAgent?: string
}

export class RegistryClient {

    //private opts: RegistryClientOptions;
    private log: Logger;
    //private indexName?: string;
    private repo: RegistryRepo;
    // private username?: string;
    // private password?: string;
    // private authToken?: string;
    private loginConfig: RegistryLoginConfiguration = {};
    private connectionConfig: RegistryConnectionConfiguration = {};
    private currentAuth?: RegistryLoginAuthInfo;

    public constructor(opts: RegistryClientOptions) {
        assert.ok(opts.name || opts.repo);

        this.log = this.ensureLogger(opts.log);
        if (opts.repo) {
            this.repo = common.deepObjCopy(opts.repo);
        } else {
            this.repo = {};
        }
        if (opts.name) {
            const parsed = common.parseRepo(opts.name, undefined);
            this.repo.canonicalName = parsed.canonicalName;
            this.repo.localName = parsed.localName;
            this.repo.remoteName = parsed.remoteName;
            if (parsed.official) {
                this.repo.indexUrl = DEFAULT_V2_REGISTRY;
            } else {
                this.repo.indexUrl = common.urlFromIndex(parsed.index);
            }
        }

        this.loginConfig.authToken = opts.token;
        this.loginConfig.username = opts.username;
        this.loginConfig.password = opts.password;
        this.loginConfig.scope = opts.scope;
        this.loginConfig.insecure = opts.insecure;

        this.connectionConfig.agent = opts.agent;
        this.connectionConfig.userAgent = opts.userAgent;
        this.connectionConfig.proxy = opts.proxy;
    }

    private ensureLogger(log?: Logger) {
    
        if (log) {
            return log;
        } else {
            return bunyan.createLogger({
                name: 'registry',
                serializers: restifyClients.bunyan.serializers
            });
        }
    }

    private formatBasicAuthHeader(username: string, password?: string) {
        const buffer = new Buffer(username + ':' + (password ?? ''), 'utf8');
        return 'Basic ' + buffer.toString('base64');
    }

    private getAuthHeader() {
        if (this.loginConfig.authToken) {
            return { authorization: 'Bearer ' + this.loginConfig.authToken };
        } else if (this.loginConfig.username) {
            return { 
                authorization: this.formatBasicAuthHeader(
                    this.loginConfig.username,
                    this.loginConfig.password
                )};
        } else {
            return undefined;
        }
    }

    private getRegistryErrorMessage(err: any) {
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

    private makeAuthScope(resource: string, name: string, actions: string[]) {
        return format('%s:%s:%s', resource, name, actions.join(','));
    }

    private parseWWWAuthenticate(header) {
        const parsed = new parsers.WWW_Authenticate(header);
        if (parsed.err) {
            throw new Error('could not parse WWW-Authenticate header "' + header
                + '": ' + parsed.err);
        }
        return parsed;
    }

    private getRegistryAuthToken(
        realm: string,
        service: string,
        scope: string,
        cb: any
    ) {

        assert.ok(realm, 'realm');
        assert.ok(realm, 'service');
        assert.ok(this.repo.remoteName, 'repo.remoteName');

        const log = this.log;

        // - add https:// prefix (or http) if none on 'realm'
        let tokenUrl = realm;
        const match = /^(\w+):\/\//.exec(tokenUrl);
        if (!match) {
            tokenUrl = (this.loginConfig.insecure ? 'http' : 'https') + '://' + tokenUrl;
        } else if (['http', 'https'].indexOf(match[1]) === -1) {
            return cb(new Error(format('unsupported scheme for ' +
                'WWW-Authenticate realm "%s": "%s"', realm, match[1])));
        }
    
        // - GET $realm
        //      ?service=$service
        //      (&scope=$scope)*
        //      (&account=$username)
        //   Authorization: Basic ...

        const query = {
            service: service,
            scope: [scope]
        } as {
            service?: string,
            scope?: string[],
            account?: string,
        };
    
        if (this.loginConfig.username) {
            query.account = this.loginConfig.username;
        }

        if (Object.keys(query).length) {
            tokenUrl += '?' + querystring.stringify(query);
        }
        // log.trace({tokenUrl: tokenUrl}, '_getToken: url');  TODO:
    
        const parsedUrl = mod_url.parse(tokenUrl);
        const client = new DockerJsonClient({
            url: parsedUrl.protocol + '//' + parsedUrl.host,
            log: log,
            agent: this.connectionConfig.agent,
            proxy: this.connectionConfig.proxy,
            rejectUnauthorized: !this.loginConfig.insecure,
            userAgent: this.connectionConfig.userAgent || common.DEFAULT_USERAGENT
        }) as any;  // TODO:
        client.get({
            path: parsedUrl.path,
            headers: this.getAuthHeader()
        }, (err, req, res, body) => {
            client.close();
            if (err) {
                if (err.statusCode === 401) {
                    // Convert *all* 401 errors to use a generic error constructor
                    // with a simple error message.
                    const errMsg = this.getRegistryErrorMessage(err);
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
    
    private jwsFromManifest(manifest: any, body: any) {
        //assert.object(manifest, 'manifest');
        //assert.buffer(body, 'body');
    
        let formatLength;
        let formatTail;
        const jws = {
            signatures: []
        } as any;
    
        for (let i = 0; i < manifest.signatures.length; i++) {
            const sig = manifest.signatures[i];
    
            let protectedHeader;
            try {
                protectedHeader = JSON.parse(
                    base64url.decode(sig['protected']));
            } catch (protectedErr) {
                throw new restifyErrors.InvalidContentError(protectedErr, format(
                    'could not parse manifest "signatures[%d].protected": %j',
                    i, sig['protected']));
            }
            if (isNaN(protectedHeader.formatLength)) {
                throw new restifyErrors.InvalidContentError(format(
                    'invalid "formatLength" in "signatures[%d].protected": %j',
                    i, protectedHeader.formatLength));
            } else if (formatLength === undefined) {
                formatLength = protectedHeader.formatLength;
            } else if (protectedHeader.formatLength !== formatLength) {
                throw new restifyErrors.InvalidContentError(format(
                    'conflicting "formatLength" in "signatures[%d].protected": %j',
                    i, protectedHeader.formatLength));
            }
    
            if (!protectedHeader.formatTail ||
                typeof (protectedHeader.formatTail) !== 'string')
            {
                throw new restifyErrors.InvalidContentError(format(
                    'missing "formatTail" in "signatures[%d].protected"', i));
            }
            const formatTail_ = base64url.decode(protectedHeader.formatTail);
            if (formatTail === undefined) {
                formatTail = formatTail_;
            } else if (formatTail_ !== formatTail) {
                throw new restifyErrors.InvalidContentError(format(
                    'conflicting "formatTail" in "signatures[%d].protected": %j',
                    i, formatTail_));
            }
    
            const jwsSig = {
                header: <any> {
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
                    throw new restifyErrors.InvalidContentError(jwkErr, format(
                        'error in "signatures[%d].header.jwk": %s',
                        i, jwkErr.message));
                }
            }
            jws.signatures.push(jwsSig as never);  // TODO:
        }
    
        jws.payload = Buffer.concat([
            body.slice(0, formatLength),
            new Buffer(formatTail)
        ]);
    
        return jws;
    }

    private parseDockerContentDigest(dcd: any) { // TODO:
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
            throw new restifyErrors.BadDigestError(hashErr, format(
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
    private verifyManifestDockerContentDigest(res: any, jws: any) {
        const dcdInfo = this.parseDockerContentDigest(
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

    private verifyJws(jws: any) {
        const encodedPayload = base64url(jws.payload);
    
        /*
         * Disallow the "none" algorithm because while the `jws` module might have
         * a guard against
         *      https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/
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

    private callPing(cb: (req: any, res: any, err: any) => void) {
        const rejectUnauthorized = !this.loginConfig.insecure;
    
        const client = new DockerJsonClient({
            url: this.repo.indexUrl,
            log: this.log,
            userAgent: this.connectionConfig.userAgent ?? common.DEFAULT_USERAGENT,
            rejectUnauthorized: rejectUnauthorized,
            agent: this.connectionConfig.agent,
            proxy: this.connectionConfig.proxy
        }) as any;
    
        // const promise = new Promise<number>((resolve, reject) => {
        //     client.get({
        //         path: '/v2/',
        //         // Ping should be fast. We don't want 15s of retrying.
        //         retry: false,
        //         connectTimeout: 10000
        //     }, (err, _, res, _req) => {
        //         client.close();
        //         if (err) { reject(err); }
        //         else { resolve(res.statusCode); }
        //     });
        // });

        client.get({
            path: '/v2/',
            // Ping should be fast. We don't want 15s of retrying.
            retry: false,
            connectTimeout: 10000
        }, (err, _, res, req) => {
            cb(req, res, err);
            client.close();
        });
    }

    public async login(): Promise<boolean> {
        // assert.object(opts, 'opts');
        // assert.ok(opts.index || opts.indexName,
        //     'opts.index or opts.indexName is required');
        // assert.optionalString(opts.username, 'opts.username');
        // if (opts.username) {
        //     assert.string(opts.password,
        //         'opts.password required if username given');
        // } else {
        //     assert.optionalString(opts.password, 'opts.password');
        // }
        // assert.optionalString(opts.scope, 'opts.scope');
        // assert.optionalString(opts.userAgent, 'opts.userAgent');
        // assert.optionalBool(opts.insecure, 'opts.insecure');
        // assert.optionalObject(opts.pingRes, 'opts.pingRes');
        // if (opts.pingRes && opts.pingRes.statusCode !== 200) {
        //     assert.object(opts.pingErr, 'opts.pingErr');
        // } else {
        //     assert.optionalObject(opts.pingErr, 'opts.pingErr');
        // }
        // //assert.optionalObject(opts.log, 'opts.log');
        // assert.optionalString(opts.userAgent, 'opts.userAgent');
        // assert.optionalObject(opts.agent, 'opts.agent');
        // // assert.optional object or bool(opts.proxy, 'opts.proxy');
        // assert.func(cb, 'cb');
    
        //const index = common.parseIndex(this.opts.index || this.opts.indexName);
    
        // log.trace({index: index, username: opts.username,
        //     password: (opts.password ? '(censored)' : '(none)'),
        //     scope: opts.scope, insecure: opts.insecure}, 'login');
    
        //const scope = this.opts.scope || '';
    
        assert.ok(this.repo.remoteName);


        // if (this.currentAuth?.scope === this.loginConfig.scope) {
        //     return true;
        // }

        this.currentAuth = undefined;

        try {

            this.currentAuth = await new Promise<RegistryLoginAuthInfo|undefined>((resolve, reject) => {
                let authInfo: RegistryLoginAuthInfo|undefined = undefined;

                const context = {} as any;

                vasync.pipeline({ arg: context, funcs: [
                    // ensureChalHeader
                    (ctx, next) => {
                        // if (this.opts.pingRes) {
                        //     ctx.chalHeader = this.opts.pingRes.headers['www-authenticate'];
                        //     if (ctx.chalHeader) {
                        //         return next();
                        //     }
                        // }
        
                        this.callPing((req, res, err) => {
                            if (!err) {
                                // assert.equal(res.statusCode, 200,
                                //     'ping success without 200');
                                // No authorization is necessary.
                                authInfo = { type: 'none' };
                                next(true);  // early pipeline abort
                            } else if (res.statusCode === 401) {
                                let chalHeader = res.headers['www-authenticate'] as string;
            
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
                            ctx.authChallenge = this.parseWWWAuthenticate(ctx.chalHeader);
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
                            username: this.loginConfig.username,
                            password: this.loginConfig.password
                        };
                        next(true);
                    },
            
                    // bearerAuth
                    (ctx, next) => {
                        if (ctx.authChallenge.scheme.toLowerCase() !== 'bearer') {
                            return next();
                        }
                        this.log.debug({challenge: ctx.authChallenge},
                            'login: get Bearer auth token');
            
                        const scope = this.loginConfig.scope ?? this.makeAuthScope('repository', this.repo.remoteName!, ['pull']);
                        this.getRegistryAuthToken(
                            ctx.authChallenge.parms.realm,  
                            ctx.authChallenge.parms.service,  
                            scope,
                            (err, token) => {
                            if (err) {
                                return next(err);
                            }
                            this.log.debug({token: token}, 'login: Bearer auth token');
                            authInfo = {
                                type: 'bearer',
                                token: token,
                                scope: scope
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
                        resolve(authInfo);
                        return;
                    }

                    this.log.trace({err: err, success: !err}, 'login: done');
                    
                    if (err) {
                        reject(err);
                        return;
                    } else {
                        //assert.object(authInfo, 'authInfo');  // TODO
                        resolve(authInfo);
                    }
                });
            });
        } catch {
            return false;
        }

        return this.currentAuth != undefined;
    }        
}

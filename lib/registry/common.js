/* eslint-disable @typescript-eslint/no-var-requires */
/*
 * Adapted from code found in https://github.com/joyent/node-docker-registry-client
*/

const assert = require('assert-plus');
const fmt = require('util').format;
const strsplit = require('strsplit');



// --- globals

const DEFAULT_USERAGENT = 'balena-multibuild';

// See `INDEXNAME` in docker/docker.git:registry/config.go.
const DEFAULT_INDEX_NAME = 'docker.io';
const DEFAULT_INDEX_URL = 'https://index.docker.io';

const DEFAULT_LOGIN_SERVERNAME = 'https://index.docker.io/v1/';


const DEFAULT_TAG = 'latest';

const VALID_NS = /^[a-z0-9._-]*$/;
const VALID_REPO = /^[a-z0-9_/.-]*$/;



// --- exports

/**
 * Parse a docker index name or index URL.
 *
 * Examples:
 *      docker.io               (no scheme implies 'https')
 *      index.docker.io         (normalized to docker.io)
 *      https://docker.io
 *      http://localhost:5000
 *      https://index.docker.io/v1/  (special case)
 *
 * Special case: By default `docker login` sends
 * "servername=https://index.docker.io/v1/". Let's not bork on that. It
 * simplifies `login()` and `ping()` argument handling in the clients to
 * handle this case here.
 *
 * @param {String} arg: Optional. Index name (optionally with leading scheme).
 */
function parseIndex(arg) {
    assert.optionalString(arg, 'arg');

    const index = {};

    if (!arg || arg === DEFAULT_LOGIN_SERVERNAME) {
        // Default index.
        index.name = DEFAULT_INDEX_NAME;
        index.official = true;
    } else {
        // Optional protocol/scheme.
        let indexName;
        const protoSepIdx = arg.indexOf('://');
        if (protoSepIdx !== -1) {
            const scheme = arg.slice(0, protoSepIdx);
            if (['http', 'https'].indexOf(scheme) === -1) {
                throw new Error('invalid index scheme, must be ' +
                    '"http" or "https": ' + arg);
            }
            index.scheme = scheme;
            indexName = arg.slice(protoSepIdx + 3);
        } else {
            indexName = arg;
        }

        if (!indexName) {
            throw new Error('invalid index, empty host: ' + arg);
        } else if (indexName.indexOf('.') === -1 &&
            indexName.indexOf(':') === -1 &&
            indexName !== 'localhost')
        {
            throw new Error(fmt('invalid index, "%s" does not look like a ' +
                'valid host: %s', indexName, arg));
        } else {
            // Allow a trailing '/' as from some URL builder functions that
            // add a default '/' path to a URL, e.g. 'https://docker.io/'.
            if (indexName[indexName.length - 1] === '/') {
                indexName = indexName.slice(0, indexName.length - 1);
            }

            // Ensure no trailing repo.
            if (indexName.indexOf('/') !== -1) {
                throw new Error('invalid index, trailing repo: ' + arg);
            }
        }

        // Per docker.git's `ValidateIndexName`.
        if (indexName === 'index.' + DEFAULT_INDEX_NAME) {
            indexName = DEFAULT_INDEX_NAME;
        }

        index.name = indexName;
        index.official = Boolean(indexName === DEFAULT_INDEX_NAME);
    }

    // Disallow official and 'http'.
    if (index.official && index.scheme === 'http') {
        throw new Error('invalid index, HTTP to official index ' +
            'is disallowed: ' + arg);
    }

    return index;
}


/**
 * Parse a docker repo and tag string: [INDEX/]REPO[:TAG|@DIGEST]
 *
 * Examples:
 *    busybox
 *    google/python
 *    docker.io/ubuntu
 *    localhost:5000/blarg
 *    http://localhost:5000/blarg
 *
 * Dev Notes:
 * - This is meant to mimic
 *   docker.git:registry/config.go#ServiceConfig.NewRepositoryInfo
 *   as much as reasonable -- with the addition that we maintain the
 *   'tag' field.  Also, that we accept the scheme on the "INDEX" is
 *   different than docker.git's parsing.
 *
 * @param arg {String} The docker repo string to parse. See examples above.
 * @param defaultIndex {Object|String} Optional. The default index to use
 *      if not specified with `arg`. If not given the default is 'docker.io'.
 *      If given it may either be a string, e.g. 'https://myreg.example.com',
 *      or parsed index object, as from `parseIndex()`.
 */
function parseRepo(arg, defaultIndex) {
    const info = {};

    // Strip off optional leading `INDEX/`, parse it to `info.index` and
    // leave the rest in `remoteName`.
    let remoteName;
    const protoSepIdx = arg.indexOf('://');
    if (protoSepIdx !== -1) {
        // (A) repo with a protocol, e.g. 'https://host/repo'.
        const slashIdx = arg.indexOf('/', protoSepIdx + 3);
        if (slashIdx === -1) {
            throw new Error('invalid repository name, no "/REPO" after ' +
                'hostame: ' + arg);
        }
        const indexName = arg.slice(0, slashIdx);
        remoteName = arg.slice(slashIdx + 1);
        info.index = parseIndex(indexName);
    } else {
        const parts = strsplit(arg, '/', 2);
        if (parts.length === 1 || (
            /* or if parts[0] doesn't look like a hostname or IP */
            parts[0].indexOf('.') === -1 &&
            parts[0].indexOf(':') === -1 &&
            parts[0] !== 'localhost'))
        {
            // (B) repo without leading 'INDEX/'.
            if (defaultIndex === undefined) {
                info.index = parseIndex();
            } else if (typeof (defaultIndex) === 'string') {
                info.index = parseIndex(defaultIndex);
            } else {
                info.index = defaultIndex;
            }
            remoteName = arg;
        } else {
            // (C) repo with leading 'INDEX/' (without protocol).
            info.index = parseIndex(parts[0]);
            remoteName = parts[1];
        }
    }

    // Validate remoteName (docker `validateRemoteName`).
    const nameParts = strsplit(remoteName, '/', 2);
    let ns, name;
    if (nameParts.length === 2) {
        name = nameParts[1];

        // Validate ns.
        ns = nameParts[0];
        if (ns.length < 2 || ns.length > 255) {
            throw new Error('invalid repository namespace, must be between ' +
                '2 and 255 characters: ' + ns);
        }
        if (! VALID_NS.test(ns)) {
            throw new Error('invalid repository namespace, may only contain ' +
                '[a-z0-9._-] characters: ' + ns);
        }
        if (ns[0] === '-' && ns[ns.length - 1] === '-') {
            throw new Error('invalid repository namespace, cannot start or ' +
                'end with a hypen: ' + ns);
        }
        if (ns.indexOf('--') !== -1) {
            throw new Error('invalid repository namespace, cannot contain ' +
                'consecutive hyphens: ' + ns);
        }
    } else {
        name = remoteName;
        if (info.index.official) {
            ns = 'library';
        }
    }

    // Validate name.
    if (! VALID_REPO.test(name)) {
        throw new Error('invalid repository name, may only contain ' +
            '[a-z0-9_/.-] characters: ' + name);
    }


    info.official = false;
    if (info.index.official) {
        info.remoteName = ns + '/' + name;
        if (ns === 'library') {
            info.official = true;
            info.localName = name;
        } else {
            info.localName = info.remoteName;
        }
        info.canonicalName = DEFAULT_INDEX_NAME + '/' + info.localName;
        info.official = true;
    } else {
        if (ns) {
            info.remoteName = ns + '/' + name;
        } else {
            info.remoteName = name;
        }
        info.localName = info.index.name + '/' + info.remoteName;
        info.canonicalName = info.localName;
    }

    return info;
}

/**
 * Similar in spirit to docker.git:registry/endpoint.go#NewEndpoint().
 */
 function urlFromIndex(index) {
    assert.bool(index.official, 'index.official');
    assert.optionalString(index.scheme, 'index.scheme');
    assert.string(index.name, 'index.name');

    if (index.official) {  // v1
        return DEFAULT_INDEX_URL;
    } else {
        return fmt('%s://%s', index.scheme || 'https', index.name);
    }
}


/**
 * Parse a docker repo and tag/digest string: [INDEX/]REPO[:TAG|@DIGEST]
 *
 * Examples:
 *    busybox
 *    busybox:latest
 *    google/python:3.3
 *    docker.io/ubuntu
 *    localhost:5000/blarg
 *    http://localhost:5000/blarg:latest
 *    alpine@sha256:fb9f16730ac6316afa4d97caa5130219927bfcecf0b0...
 *
 * @param arg {String} The docker repo:tag string to parse. See examples above.
 * @param defaultIndex {Object|String} Optional. The default index to use
 *      if not specified with `arg`. If not given the default is 'docker.io'.
 *      If given it may either be a string, e.g. 'https://myreg.example.com',
 *      or parsed index object, as from `parseIndex()`.
 */
function parseRepoAndRef(arg, defaultIndex) {
    // Parse off the tag/digest per
    // JSSTYLED
    // https://github.com/docker/docker/blob/0c7b51089c8cd7ef3510a9b40edaa139a7ca91aa/pkg/parsers/parsers.go#L69
    let repo, tag, digest;
    const atIdx = arg.lastIndexOf('@');
    if (atIdx !== -1) {
        repo = arg.slice(0, atIdx);
        digest = arg.slice(atIdx + 1);
    } else {
        const colonIdx = arg.lastIndexOf(':');
        const slashIdx = arg.lastIndexOf('/');
        if (colonIdx !== -1 && colonIdx > slashIdx) {
            repo = arg.slice(0, colonIdx);
            tag = arg.slice(colonIdx + 1);
        } else {
            repo = arg;
        }
    }

    const info = parseRepo(repo, defaultIndex);
    if (digest) {
        info.digest = digest;
    } else if (tag) {
        info.tag = tag;
    } else {
        info.tag = DEFAULT_TAG;
    }

    return info;
}

const parseRepoAndTag = parseRepoAndRef;


function deepObjCopy(obj) {
    // Obviously this is limited and not efficient.
    return JSON.parse(JSON.stringify(obj));
}


/*
 * Merge given objects into the given `target` object. Last one wins.
 * The `target` is modified in place.
 *
 *      const foo = {bar: 32};
 *      objMerge(foo, {bar: 42}, {bling: 'blam'});
 *
 * Adapted from tunnel-agent `mergeOptions`.
 */
function objMerge(target) {
    for (let i = 1, len = arguments.length; i < len; ++i) {
        const overrides = arguments[i];
        if (typeof (overrides) === 'object') {
            const keys = Object.keys(overrides);
            for (let j = 0, keyLen = keys.length; j < keyLen; ++j) {
                const k = keys[j];
                if (overrides[k] !== undefined) {
                    target[k] = overrides[k];
                }
            }
        }
    }
    return target;
}

function isLocalhost(host) {
    const lead = host.split(':')[0];
    if (lead === 'localhost' || lead === '127.0.0.1') {
        return true;
    } else {
        return false;
    }
}


function pauseStream(stream) {
    const _buffer = (chunk) => {
        stream.__buffered.push(chunk);
    }

    const _catchEnd = () => {
        stream.__dockerreg_ended = true;
    }

    stream.__dockerreg_ended = false;
    stream.__dockerreg_paused = true;
    stream.__buffered = [];
    stream.on('data', _buffer);
    stream.once('end', _catchEnd);
    stream.pause();

    stream._resume = stream.resume;
    stream.resume = function _dockerreg_resume() {
        if (!stream.__dockerreg_paused)
            return;

        stream.removeListener('data', _buffer);
        stream.removeListener('end', _catchEnd);

        stream.__buffered.forEach(stream.emit.bind(stream, 'data'));
        stream.__buffered.length = 0;

        stream._resume();
        stream.resume = stream._resume;

        if (stream.__dockerreg_ended)
            stream.emit('end');
    };
}

module.exports = {
    DEFAULT_USERAGENT: DEFAULT_USERAGENT,

    DEFAULT_INDEX_NAME: DEFAULT_INDEX_NAME,
    DEFAULT_TAG: DEFAULT_TAG,
    parseIndex: parseIndex,
    parseRepo: parseRepo,
    parseRepoAndRef: parseRepoAndRef,
    parseRepoAndTag: parseRepoAndTag,
    urlFromIndex: urlFromIndex,
    isLocalhost: isLocalhost,
    deepObjCopy: deepObjCopy,
    objMerge: objMerge,
    pauseStream: pauseStream
};

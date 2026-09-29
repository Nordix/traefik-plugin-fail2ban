# Fail2Ban middleware plugin for traefik reverse proxy

![Continuous Integration Status](https://github.com/juitde/traefik-plugin-fail2ban/actions/workflows/ci.yml/badge.svg?branch=main)

This plugin is a small but growing implementation of a fail2ban instance as a middleware plugin for traefik. It is
inspired by other implementations similar in the goal but is tailored to our needs.

Inspirations taken from:
- https://github.com/tomMoulard/fail2ban
- https://github.com/safing/scanblock

## Installation

Installation instructions are provided via the [traefik Plugin Catalog](https://plugins.traefik.io/plugins/).

### CAUTION: Breaking Changes

#### Version 0.2.0

- traefik v2.10+ is required due to now having a vendored dependency which results
  in go routine panics in previous traefik versions.

## Configuration

All configuration options may be specified either in config files or as CLI parameters.

### Always allowing or blocking certain IPs(/IP-ranges)

There can be configured certain ip addresses or ranges which are either always allowed or always denied access.
Blocking always takes precedence before allowing access and allowing access takes precedence before executing other
fail2ban rules.

```yaml
testData:
    alwaysAllowed:
        ip: "::1,127.0.0.1"
    alwaysDenied:
        ip: "192.168.0.0/24"
```

### Restricting logging messages

In order to help managing the use of this plugin the level of logged messages can be adjusted.

```yaml
testData:
    logLevel: "INFO"
```

### Fail2Ban rules

The ultimate goal is to support any rule matcher fail2ban supports themselves but implementation follows the direct
needs of our projects.

Currently the implemented settings consist of:

```yaml
testData:
    rules:
        banTime: "3h"
        findTime: "10m"
        maxRetries: 4
        response:
            statusCodes: "400,401,403-499"
            errorCode: "403"
```

### Allowing or blocking requests by URL pattern

Requests can be allowed or blocked based on regular expressions matched against the request URL. This is useful to
exempt specific paths from ban counting (for example endpoints that legitimately return error status codes) or to
block known-bad paths outright.

- `allow` patterns take precedence: a request whose URL matches an allow pattern is passed through immediately and is
  never counted towards the ban limit.
- `deny` patterns block the matching request with the configured `errorCode` and count as a strike towards the ban
  limit.

Patterns are [Go regular expressions](https://pkg.go.dev/regexp/syntax) matched against the request URL. Invalid
patterns are logged and skipped at startup.

```yaml
testData:
    urlRegexp:
        allow:
            - "^/computer/"
        deny:
            - "^/wp-login\\.php"
```

> **Note:** When configuring patterns via container labels or CLI parameters, traefik splits list values on commas.
> A regular expression containing a comma (e.g. `x{2,4}`) will therefore be misinterpreted. Use a config file for such
> patterns.

## Processing requests

Prior to executing the defined rules if the Remote IP is in the `alwaysDenied`-list the request will be immediately
denied. This applies for the `alwaysAllowed`-list accordingly.

After the IP lists are evaluated, `urlRegexp.allow` patterns are checked: a matching request is passed through
immediately, bypassing fail2ban entirely (it is neither tracked nor counted). `urlRegexp.deny` patterns are checked
once the request is known not to be banned: a match blocks the request with the configured `errorCode` and counts as a
strike towards the ban limit.

In the first request from an unknown IP address they are added to the pool starting the `findTime` timer:

In every subsequent request (while the findTime is not exceeded) the IP address counter in the pool is incremented
and the rules are checked.

# How to develop in this project

- First clean install vendor dependencies: `make clean vendor`

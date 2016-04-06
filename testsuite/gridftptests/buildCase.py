# regexps identifying the different tags. Each regexp may be
# associated to a function that takes as single parameter the
# replaced string and returns the tag to use. If None, the regexp
# will be replaced with the rule name
# Note that regexps must have exactly one group matching the part to
# be replaced
castorRegexps = {
    'fileName' : ('(?:[\s=]|\A|file:///)(/[^ \t\n\r\f\v:\)]*)', tagForFileName),
    'uuid'     : ('([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', None),
    'globus-url-copy' : ('((?:\S*/)?globus-url-copy)\s', None),
    'gsiftpURL': ('(?:\s|\A)(gsiftp://[^/]*/\S*)', None),
    }
tagRegexps.update(castorRegexps)

# regexps of parts of the output that should be dropped
# Note that regexps must have exactly one group matching the part to
# be dropped
castorSuppressRegExps = []
suppressRegExps = suppressRegExps + castorSuppressRegExps

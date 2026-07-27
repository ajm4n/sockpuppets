"""Default obfuscation patterns — extracted from the original agent.py hardcoded values."""

PATTERNS = {
    "var_prefixes": [
        "data", "temp", "buf", "ctx", "info", "val", "obj", "result",
        "handler", "proc", "mgr", "svc", "cfg", "opt", "ref", "item",
    ],
    "func_prefixes": [
        "init", "run", "check", "load", "parse", "handle",
        "process", "validate", "compute", "resolve",
    ],
    "junk_templates": [
        "def {func}():\n    {var} = {rand_int}\n    return {var}",
        "{var} = {rand_int}",
        "{var} = lambda x: x * {rand_int}",
    ],
    "string_encodings": ["base64", "hex", "reverse", "xor"],
    "padding_words": [
        "data", "result", "value", "info", "config", "option", "param", "item",
        "handler", "manager", "service", "process", "buffer", "context", "state",
        "import", "return", "class", "function", "method", "object", "string",
    ],
    "import_prefixes": ["_mod", "_lib", "_pkg"],
}

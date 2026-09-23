"""Error types for rule configuration / loading failures."""


class RuleConfigError(Exception):
    """Base class: a rule configuration is invalid or cannot be loaded."""


class RuleFileError(RuleConfigError):
    """Rule file missing / unreadable / not parseable as JSON."""


class RuleSyntaxError(RuleConfigError):
    """A rule entry has invalid shape, operator, or values."""


class RulesUnavailableError(RuleConfigError):
    """Rules have never been loaded successfully (no safe ruleset exists)."""

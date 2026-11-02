from dataclasses import dataclass, field


@dataclass(frozen=True)
class RuleHeader:
    action: str
    protocol: str
    src_ip: str
    src_port: tuple[int, int]
    direction: str
    dst_ip: str
    dst_port: tuple[int, int]


@dataclass
class ContentCondition:
    pattern: bytes
    nocase: bool = False
    offset: int | None = None
    depth: int | None = None
    distance: int | None = None
    within: int | None = None


@dataclass
class Rule:
    header: RuleHeader
    msg: str
    sid: int
    rev: int
    contents: list[ContentCondition] = field(default_factory=list)
    flow: tuple[str, ...] = ()
    flags: str | None = None
    dsize: tuple[str, int, int | None] | None = None
    classtype: str | None = None
    priority: int | None = None
    source: str | None = None
    line_number: int | None = None
    raw: str = ''


@dataclass
class RuleParseResult:
    status: str
    reasons: list[str]
    rule: Rule | None = None
    source: str | None = None
    line_number: int | None = None

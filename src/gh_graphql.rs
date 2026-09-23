//! `gh api graphql` allowlist for the gh guard (#414).
//!
//! GraphQL is one endpoint that can do anything, so the gh guard used to refuse
//! it outright. Two things a sandboxed agent routinely needs exist only there:
//! reading which review threads are still open, and resolving or replying to
//! one. This module lets exactly those through and nothing else.
//!
//! The request is parsed, not pattern-matched. Anything the strict parser here
//! does not understand is refused, so a parser gap fails closed:
//!
//! - **Queries** must have only `repository(owner: …, name: …)` (or
//!   `__typename`) at the root, naming a repository in the startup scope.
//! - **Mutations** may only be the fields in [`MUTATIONS`], each with an
//!   `input` object literal whose node IDs are then looked up with GitHub
//!   ([`verify_targets`]) before `gh` runs. A node whose repository is not in
//!   scope, or that cannot be looked up, is refused.
//! - **Below the root**, every field must be in [`FIELDS`] for the type it is
//!   selected on: pull requests, their review threads and comments, and a
//!   comment author's login. Nothing there leads to another repository, a
//!   user's or organization's data, or the viewer.
//! - **Subscriptions**, documents with more than one operation, and every
//!   fragment (definition, spread or inline) are refused.
//! - Only `-f`/`-F` fields carry the request. `--input`, headers, previews,
//!   `@file` values and `gh`'s `{owner}`/`:repo` placeholders are refused,
//!   because the guard would not be looking at what gets sent.

use std::collections::HashMap;
use std::path::Path;

/// What kind of node a mutation's ID must resolve to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    ReviewThread,
    Review,
}

impl NodeKind {
    fn typename(self) -> &'static str {
        match self {
            Self::ReviewThread => "PullRequestReviewThread",
            Self::Review => "PullRequestReview",
        }
    }
}

/// A node ID an allowed mutation writes to, still to be verified against scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub id: String,
    pub kind: NodeKind,
}

/// Allowed mutation fields: name, the `input` keys that are node IDs (with
/// whether each is required), the other `input` keys allowed, and the payload
/// type whose selection [`FIELDS`] then limits.
type IdKeys = &'static [(&'static str, NodeKind, bool)];
const MUTATIONS: &[(&str, IdKeys, &[&str], &str)] = &[
    (
        "resolveReviewThread",
        &[("threadId", NodeKind::ReviewThread, true)],
        &["clientMutationId"],
        "ThreadPayload",
    ),
    (
        "unresolveReviewThread",
        &[("threadId", NodeKind::ReviewThread, true)],
        &["clientMutationId"],
        "ThreadPayload",
    ),
    (
        "addPullRequestReviewThreadReply",
        &[
            ("pullRequestReviewThreadId", NodeKind::ReviewThread, true),
            ("pullRequestReviewId", NodeKind::Review, false),
        ],
        &["body", "clientMutationId"],
        "ReplyPayload",
    ),
];

const PR_LIST_ARGS: &[&str] = &[
    "first",
    "last",
    "after",
    "before",
    "states",
    "orderBy",
    "labels",
    "headRefName",
    "baseRefName",
];
const PAGE: &[&str] = &["first", "after"];

/// Every field a document may select below the root: (parent type, field,
/// allowed arguments, child type, or `None` for a scalar). Anything not here is
/// refused, so nothing can lead from a repository in scope to its owner, a
/// user, or another repository. `__typename` is allowed on every type. The
/// payload types (`ThreadPayload`, `PayloadThread`, …) are the guard's own
/// names for a restricted view of GitHub's types.
#[rustfmt::skip]
const FIELDS: &[(&str, &str, &[&str], Option<&str>)] = &[
    ("Repository", "pullRequest", &["number"], Some("PullRequest")),
    ("Repository", "pullRequests", PR_LIST_ARGS, Some("PullRequestConnection")),

    ("PullRequestConnection", "nodes", &[], Some("PullRequest")),
    ("PullRequestConnection", "edges", &[], Some("PullRequestEdge")),
    ("PullRequestConnection", "totalCount", &[], None),
    ("PullRequestConnection", "pageInfo", &[], Some("PageInfo")),
    ("PullRequestEdge", "cursor", &[], None),
    ("PullRequestEdge", "node", &[], Some("PullRequest")),

    ("PullRequest", "id", &[], None),
    ("PullRequest", "number", &[], None),
    ("PullRequest", "title", &[], None),
    ("PullRequest", "state", &[], None),
    ("PullRequest", "url", &[], None),
    ("PullRequest", "isDraft", &[], None),
    ("PullRequest", "headRefName", &[], None),
    ("PullRequest", "baseRefName", &[], None),
    ("PullRequest", "reviewThreads", PAGE, Some("PullRequestReviewThreadConnection")),

    ("PullRequestReviewThreadConnection", "nodes", &[], Some("PullRequestReviewThread")),
    ("PullRequestReviewThreadConnection", "edges", &[], Some("PullRequestReviewThreadEdge")),
    ("PullRequestReviewThreadConnection", "totalCount", &[], None),
    ("PullRequestReviewThreadConnection", "pageInfo", &[], Some("PageInfo")),
    ("PullRequestReviewThreadEdge", "cursor", &[], None),
    ("PullRequestReviewThreadEdge", "node", &[], Some("PullRequestReviewThread")),

    ("PullRequestReviewThread", "id", &[], None),
    ("PullRequestReviewThread", "isResolved", &[], None),
    ("PullRequestReviewThread", "isOutdated", &[], None),
    ("PullRequestReviewThread", "path", &[], None),
    ("PullRequestReviewThread", "line", &[], None),
    ("PullRequestReviewThread", "originalLine", &[], None),
    ("PullRequestReviewThread", "startLine", &[], None),
    ("PullRequestReviewThread", "diffSide", &[], None),
    ("PullRequestReviewThread", "comments", PAGE, Some("PullRequestReviewCommentConnection")),

    ("PullRequestReviewCommentConnection", "nodes", &[], Some("PullRequestReviewComment")),
    ("PullRequestReviewCommentConnection", "edges", &[], Some("PullRequestReviewCommentEdge")),
    ("PullRequestReviewCommentConnection", "totalCount", &[], None),
    ("PullRequestReviewCommentConnection", "pageInfo", &[], Some("PageInfo")),
    ("PullRequestReviewCommentEdge", "cursor", &[], None),
    ("PullRequestReviewCommentEdge", "node", &[], Some("PullRequestReviewComment")),

    ("PullRequestReviewComment", "id", &[], None),
    ("PullRequestReviewComment", "body", &[], None),
    ("PullRequestReviewComment", "url", &[], None),
    ("PullRequestReviewComment", "createdAt", &[], None),
    ("PullRequestReviewComment", "path", &[], None),
    // Only the login: an author is a User, Bot or Organization, and every
    // other field on those leads to their repositories.
    ("PullRequestReviewComment", "author", &[], Some("Author")),
    ("Author", "login", &[], None),

    ("PageInfo", "hasNextPage", &[], None),
    ("PageInfo", "hasPreviousPage", &[], None),
    ("PageInfo", "endCursor", &[], None),
    ("PageInfo", "startCursor", &[], None),

    ("ThreadPayload", "thread", &[], Some("PayloadThread")),
    ("ThreadPayload", "clientMutationId", &[], None),
    ("PayloadThread", "id", &[], None),
    ("PayloadThread", "isResolved", &[], None),
    ("ReplyPayload", "comment", &[], Some("PayloadComment")),
    ("ReplyPayload", "clientMutationId", &[], None),
    ("PayloadComment", "id", &[], None),
    ("PayloadComment", "url", &[], None),
];

const MAX_DEPTH: usize = 64;

/// Check a `gh api graphql …` argv (starting at `api`) against the allowlist.
///
/// Returns the node IDs an allowed mutation targets (empty for a query), or
/// the reason it is refused. Targets must still pass [`verify_targets`].
pub fn check(args: &[&str], scope: &[String]) -> Result<Vec<Target>, String> {
    let mut fields = parse_args(args)?;
    // `gh` sends `query` and `operationName` outside `variables`, and
    // `--paginate` overwrites `endCursor` with a value read from the response
    // (which an alias can choose). None of them may resolve a `$variable`.
    fields.remove("operationName");
    fields.remove("endCursor");
    let query = match fields.remove("query") {
        Some(Var::Str(q)) => q,
        Some(Var::Other) => return Err("the query must be a string".into()),
        None => return Err("no query was given (pass it with -f query='…')".into()),
    };
    let doc = Parser::new(&query)?.document()?;
    validate(&doc, &fields, scope)
}

// ── argv ────────────────────────────────────────────────────────────

/// A `gh api` field value as `gh` will send it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Var {
    Str(String),
    /// A number, boolean or null (`-F` typing): never a valid name or ID.
    Other,
}

fn parse_args(args: &[&str]) -> Result<HashMap<String, Var>, String> {
    if args.first() != Some(&"api") {
        return Err("flags before 'api' are not supported for gh api graphql".into());
    }
    let mut fields = HashMap::new();
    let mut endpoint = false;
    let mut i = 1;
    while i < args.len() {
        let arg = args[i];
        let (flag, attached) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f, Some(v)),
            _ => (arg, None),
        };
        let mut value = || -> Result<&str, String> {
            if let Some(v) = attached {
                return Ok(v);
            }
            i += 1;
            args.get(i)
                .copied()
                .ok_or_else(|| format!("{flag} needs a value"))
        };
        match flag {
            "graphql" if !endpoint => endpoint = true,
            "-f" | "--raw-field" => add_field(&mut fields, value()?, false)?,
            "-F" | "--field" => add_field(&mut fields, value()?, true)?,
            "-X" | "--method" => {
                if value()? != "POST" {
                    return Err("gh api graphql must use POST".into());
                }
            }
            "--hostname" => {
                if value()? != "github.com" {
                    return Err("gh api graphql must target github.com".into());
                }
            }
            "-q" | "--jq" | "-t" | "--template" | "--cache" => {
                value()?;
            }
            "--paginate" | "--slurp" | "--silent" | "-i" | "--include" | "--verbose"
                if attached.is_none() => {}
            _ => {
                return Err(format!(
                    "'{arg}' is not supported for gh api graphql (use -f/-F fields, \
                     with separate flag and value)"
                ));
            }
        }
        i += 1;
    }
    if !endpoint {
        return Err("the endpoint must be exactly 'graphql'".into());
    }
    Ok(fields)
}

/// Record one `key=value` field the way `gh api` would read it, refusing every
/// form where what `gh` sends could differ from what the guard sees.
fn add_field(fields: &mut HashMap<String, Var>, raw: &str, typed: bool) -> Result<(), String> {
    let Some((key, value)) = raw.split_once('=') else {
        return Err(format!("field '{raw}' has no '=value'"));
    };
    if key.is_empty() || key.contains(['[', ']']) {
        return Err(format!(
            "field key '{key}' is not supported (no nested or array fields)"
        ));
    }
    let var = if typed {
        // `gh` reads `@path` from a file or stdin, and expands `{owner}`,
        // `{repo}`, `{branch}`, `:owner`, `:repo`, `:branch` in -F values —
        // a branch name can contain any GraphQL punctuation.
        if value.starts_with('@') {
            return Err("-F values read from a file or stdin (@…) are not supported".into());
        }
        if [
            "{owner}", "{repo}", "{branch}", ":owner", ":repo", ":branch",
        ]
        .iter()
        .any(|p| value.contains(p))
        {
            return Err(
                "gh placeholders ({owner}, {repo}, {branch}) are not supported; \
                        pass literal values with -f"
                    .into(),
            );
        }
        if value.parse::<i64>().is_ok() || matches!(value, "true" | "false" | "null") {
            Var::Other
        } else {
            Var::Str(value.to_string())
        }
    } else {
        Var::Str(value.to_string())
    };
    if fields.insert(key.to_string(), var).is_some() {
        return Err(format!("field '{key}' is given twice"));
    }
    Ok(())
}

// ── lexer ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Punct(u8),
    Spread,
    Name(String),
    Num,
    /// A string literal: its value when it is a plain `"…"` string without
    /// escapes, `None` for escaped or block strings (usable as text, never as a
    /// name or ID the guard has to compare).
    Str(Option<String>),
}

fn lex(src: &str) -> Result<Vec<Tok>, String> {
    let b = src.as_bytes();
    let mut toks = Vec::new();
    let mut i = 0;
    let err = |what: &str, at: usize| Err(format!("query does not parse: {what} at byte {at}"));
    while i < b.len() {
        let c = b[i];
        match c {
            b' ' | b'\t' | b'\n' | b'\r' | b',' => i += 1,
            b'#' => {
                while i < b.len() && b[i] != b'\n' && b[i] != b'\r' {
                    i += 1;
                }
            }
            b'!' | b'$' | b'&' | b'(' | b')' | b':' | b'=' | b'@' | b'[' | b']' | b'{' | b'|'
            | b'}' => {
                toks.push(Tok::Punct(c));
                i += 1;
            }
            b'.' => {
                if b.get(i..i + 3) != Some(b"...") {
                    return err("stray '.'", i);
                }
                toks.push(Tok::Spread);
                i += 3;
            }
            b'_' | b'A'..=b'Z' | b'a'..=b'z' => {
                let start = i;
                while i < b.len() && (b[i] == b'_' || b[i].is_ascii_alphanumeric()) {
                    i += 1;
                }
                toks.push(Tok::Name(src[start..i].to_string()));
            }
            b'-' | b'0'..=b'9' => {
                if c == b'-' {
                    i += 1;
                }
                let digits = |i: &mut usize| {
                    let s = *i;
                    while *i < b.len() && b[*i].is_ascii_digit() {
                        *i += 1;
                    }
                    *i > s
                };
                if !digits(&mut i) {
                    return err("malformed number", i);
                }
                if b.get(i) == Some(&b'.') {
                    i += 1;
                    if !digits(&mut i) {
                        return err("malformed number", i);
                    }
                }
                if matches!(b.get(i), Some(b'e' | b'E')) {
                    i += 1;
                    if matches!(b.get(i), Some(b'+' | b'-')) {
                        i += 1;
                    }
                    if !digits(&mut i) {
                        return err("malformed number", i);
                    }
                }
                if matches!(b.get(i), Some(b'.' | b'_' | b'A'..=b'Z' | b'a'..=b'z')) {
                    return err("malformed number", i);
                }
                toks.push(Tok::Num);
            }
            b'"' if b.get(i..i + 3) == Some(b"\"\"\"") => {
                i += 3;
                loop {
                    match b.get(i) {
                        None => return err("unterminated block string", i),
                        Some(b'\\') if b.get(i + 1..i + 4) == Some(b"\"\"\"") => i += 4,
                        Some(b'"') if b.get(i..i + 3) == Some(b"\"\"\"") => {
                            i += 3;
                            break;
                        }
                        Some(_) => i += 1,
                    }
                }
                toks.push(Tok::Str(None));
            }
            b'"' => {
                i += 1;
                let start = i;
                let mut escaped = false;
                loop {
                    match b.get(i) {
                        None | Some(b'\n' | b'\r') => return err("unterminated string", i),
                        Some(b'\\') => {
                            escaped = true;
                            i += 2;
                        }
                        Some(b'"') => break,
                        Some(_) => i += 1,
                    }
                }
                let value = (!escaped).then(|| src[start..i].to_string());
                i += 1;
                toks.push(Tok::Str(value));
            }
            _ => return err("unexpected character", i),
        }
    }
    Ok(toks)
}

// ── parser ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    Var(String),
    Str(Option<String>),
    Object(Vec<(String, Value)>),
    Other,
}

#[derive(Debug)]
struct Field {
    name: String,
    args: Vec<(String, Value)>,
    selection: Vec<Selection>,
}

#[derive(Debug)]
enum Selection {
    Field(Field),
    /// A fragment spread or inline fragment: parsed only to be refused.
    Fragment,
}

#[derive(Debug, PartialEq, Eq)]
enum OpKind {
    Query,
    Mutation,
    Subscription,
}

#[derive(Debug)]
enum Definition {
    Operation(OpKind, Vec<Selection>),
    /// Parsed only to be refused.
    Fragment,
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
    depth: usize,
}

type PResult<T> = Result<T, String>;

impl Parser {
    fn new(src: &str) -> PResult<Self> {
        Ok(Self {
            toks: lex(src)?,
            pos: 0,
            depth: 0,
        })
    }

    fn fail<T>(&self, what: &str) -> PResult<T> {
        Err(format!(
            "query does not parse: {what} at token {}",
            self.pos
        ))
    }

    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn at(&self, p: u8) -> bool {
        self.peek() == Some(&Tok::Punct(p))
    }

    fn eat(&mut self, p: u8) -> bool {
        let hit = self.at(p);
        if hit {
            self.pos += 1;
        }
        hit
    }

    fn expect(&mut self, p: u8) -> PResult<()> {
        if self.eat(p) {
            Ok(())
        } else {
            self.fail(&format!("expected '{}'", p as char))
        }
    }

    fn name(&mut self) -> PResult<String> {
        if let Some(Tok::Name(n)) = self.peek() {
            let n = n.clone();
            self.pos += 1;
            Ok(n)
        } else {
            self.fail("expected a name")
        }
    }

    fn peek_name(&self) -> Option<&str> {
        match self.peek() {
            Some(Tok::Name(n)) => Some(n),
            _ => None,
        }
    }

    fn document(mut self) -> PResult<Vec<Definition>> {
        let mut defs = Vec::new();
        while self.peek().is_some() {
            defs.push(self.definition()?);
        }
        if defs.is_empty() {
            return self.fail("empty document");
        }
        Ok(defs)
    }

    fn definition(&mut self) -> PResult<Definition> {
        if self.at(b'{') {
            return Ok(Definition::Operation(OpKind::Query, self.selection_set()?));
        }
        let kind = match self.name()?.as_str() {
            "query" => OpKind::Query,
            "mutation" => OpKind::Mutation,
            "subscription" => OpKind::Subscription,
            "fragment" => {
                if self.name()? == "on" {
                    return self.fail("fragment named 'on'");
                }
                if self.name()? != "on" {
                    return self.fail("expected 'on'");
                }
                self.name()?;
                self.directives()?;
                self.selection_set()?;
                return Ok(Definition::Fragment);
            }
            _ => return self.fail("only operations and fragments are allowed"),
        };
        if self.peek_name().is_some() {
            self.name()?;
        }
        if self.eat(b'(') {
            loop {
                self.expect(b'$')?;
                self.name()?;
                self.expect(b':')?;
                self.type_ref()?;
                if self.eat(b'=') {
                    self.value()?;
                }
                self.directives()?;
                if self.eat(b')') {
                    break;
                }
            }
        }
        self.directives()?;
        Ok(Definition::Operation(kind, self.selection_set()?))
    }

    fn type_ref(&mut self) -> PResult<()> {
        self.enter()?;
        if self.eat(b'[') {
            self.type_ref()?;
            self.expect(b']')?;
        } else {
            self.name()?;
        }
        self.eat(b'!');
        self.depth -= 1;
        Ok(())
    }

    fn directives(&mut self) -> PResult<()> {
        while self.eat(b'@') {
            self.name()?;
            if self.at(b'(') {
                self.arguments()?;
            }
        }
        Ok(())
    }

    fn arguments(&mut self) -> PResult<Vec<(String, Value)>> {
        self.expect(b'(')?;
        let mut args = Vec::new();
        loop {
            let name = self.name()?;
            self.expect(b':')?;
            args.push((name, self.value()?));
            if self.eat(b')') {
                return Ok(args);
            }
        }
    }

    fn enter(&mut self) -> PResult<()> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return self.fail("nesting too deep");
        }
        Ok(())
    }

    fn value(&mut self) -> PResult<Value> {
        self.enter()?;
        let v = match self.peek().cloned() {
            Some(Tok::Punct(b'$')) => {
                self.pos += 1;
                Value::Var(self.name()?)
            }
            Some(Tok::Str(s)) => {
                self.pos += 1;
                Value::Str(s)
            }
            Some(Tok::Num | Tok::Name(_)) => {
                self.pos += 1;
                Value::Other
            }
            Some(Tok::Punct(b'[')) => {
                self.pos += 1;
                while !self.eat(b']') {
                    self.value()?;
                }
                Value::Other
            }
            Some(Tok::Punct(b'{')) => {
                self.pos += 1;
                let mut fields = Vec::new();
                while !self.eat(b'}') {
                    let name = self.name()?;
                    self.expect(b':')?;
                    fields.push((name, self.value()?));
                }
                Value::Object(fields)
            }
            _ => return self.fail("expected a value"),
        };
        self.depth -= 1;
        Ok(v)
    }

    fn selection_set(&mut self) -> PResult<Vec<Selection>> {
        self.enter()?;
        self.expect(b'{')?;
        let mut set = Vec::new();
        while !self.eat(b'}') {
            set.push(self.selection()?);
        }
        if set.is_empty() {
            return self.fail("empty selection set");
        }
        self.depth -= 1;
        Ok(set)
    }

    fn selection(&mut self) -> PResult<Selection> {
        if self.peek() == Some(&Tok::Spread) {
            self.pos += 1;
            if let Some(n) = self.peek_name()
                && n != "on"
            {
                self.name()?;
                self.directives()?;
                return Ok(Selection::Fragment);
            }
            if self.peek_name() == Some("on") {
                self.pos += 1;
                self.name()?;
            }
            self.directives()?;
            self.selection_set()?;
            return Ok(Selection::Fragment);
        }
        let mut name = self.name()?;
        if self.eat(b':') {
            name = self.name()?; // an alias never changes which field runs
        }
        let args = if self.at(b'(') {
            self.arguments()?
        } else {
            Vec::new()
        };
        self.directives()?;
        let selection = if self.at(b'{') {
            self.selection_set()?
        } else {
            Vec::new()
        };
        Ok(Selection::Field(Field {
            name,
            args,
            selection,
        }))
    }
}

// ── policy ──────────────────────────────────────────────────────────

fn validate(
    doc: &[Definition],
    vars: &HashMap<String, Var>,
    scope: &[String],
) -> Result<Vec<Target>, String> {
    let mut operation = None;
    for def in doc {
        match def {
            Definition::Operation(kind, set) => {
                if operation.replace((kind, set)).is_some() {
                    return Err("only one operation per request is allowed".into());
                }
            }
            Definition::Fragment => return Err(FRAGMENTS.into()),
        }
    }
    let Some((kind, root)) = operation else {
        return Err("the document has no operation".into());
    };
    if *kind == OpKind::Subscription {
        return Err("subscriptions are not allowed".into());
    }
    let mut targets = Vec::new();
    for sel in root {
        let Selection::Field(field) = sel else {
            return Err(FRAGMENTS.into());
        };
        if field.name == "__typename" {
            continue;
        }
        match kind {
            OpKind::Query => {
                check_query_root(field, vars, scope)?;
                check_selection("Repository", &field.selection)?;
            }
            OpKind::Mutation | OpKind::Subscription => {
                let (found, payload) = check_mutation_root(field, vars)?;
                targets.extend(found);
                check_selection(payload, &field.selection)?;
            }
        }
    }
    Ok(targets)
}

const FRAGMENTS: &str = "fragments (named, spread or inline) are not allowed";

/// Hold a selection set on `parent` to [`FIELDS`], recursively.
fn check_selection(parent: &str, set: &[Selection]) -> Result<(), String> {
    for sel in set {
        let Selection::Field(f) = sel else {
            return Err(FRAGMENTS.into());
        };
        if f.name == "__typename" {
            if !f.args.is_empty() || !f.selection.is_empty() {
                return Err("__typename takes no arguments or selection".into());
            }
            continue;
        }
        let Some((.., args, child)) = FIELDS
            .iter()
            .find(|(ty, name, ..)| *ty == parent && *name == f.name)
        else {
            return Err(format!(
                "field '{}' on {parent} is not allowed; only pull request and \
                 review-thread fields are",
                f.name
            ));
        };
        for (arg, _) in &f.args {
            if !args.contains(&arg.as_str()) {
                return Err(format!(
                    "argument '{arg}' on {parent}.{} is not allowed",
                    f.name
                ));
            }
        }
        unique(&f.args, "argument")?;
        match child {
            Some(child) => check_selection(child, &f.selection)?,
            None if f.selection.is_empty() => {}
            None => return Err(format!("{parent}.{} has no fields to select", f.name)),
        }
    }
    Ok(())
}

/// Arguments by name, refusing duplicates: a server that kept the last one
/// while the guard read the first would be a bypass.
fn unique<'a>(
    pairs: &'a [(String, Value)],
    what: &str,
) -> Result<HashMap<&'a str, &'a Value>, String> {
    let mut map = HashMap::new();
    for (k, v) in pairs {
        if map.insert(k.as_str(), v).is_some() {
            return Err(format!("{what} '{k}' is given twice"));
        }
    }
    Ok(map)
}

/// The string a value will have on the server, when the guard can know it.
fn resolve<'a>(value: &'a Value, vars: &'a HashMap<String, Var>) -> Option<&'a str> {
    match value {
        Value::Str(Some(s)) => Some(s),
        Value::Var(name) => match vars.get(name) {
            Some(Var::Str(s)) => Some(s),
            _ => None,
        },
        _ => None,
    }
}

fn check_query_root(
    field: &Field,
    vars: &HashMap<String, Var>,
    scope: &[String],
) -> Result<(), String> {
    if field.name != "repository" {
        return Err(format!(
            "query root field '{}' is not allowed; queries must start at repository(owner:, name:)",
            field.name
        ));
    }
    let args = unique(&field.args, "argument")?;
    if args.len() != 2 {
        return Err("repository() takes exactly owner: and name: here".into());
    }
    let (Some(owner), Some(name)) = (
        args.get("owner").and_then(|v| resolve(v, vars)),
        args.get("name").and_then(|v| resolve(v, vars)),
    ) else {
        return Err("repository(owner:, name:) must be plain strings or -f variables".into());
    };
    let repo = format!("{owner}/{name}");
    if !scope.iter().any(|m| crate::gh_proxy::repos_match(&repo, m)) {
        return Err(format!(
            "query reads repository '{repo}', outside the startup scope '{}'",
            scope.join(", ")
        ));
    }
    Ok(())
}

fn check_mutation_root(
    field: &Field,
    vars: &HashMap<String, Var>,
) -> Result<(Vec<Target>, &'static str), String> {
    let Some((_, id_keys, other_keys, payload)) = MUTATIONS.iter().find(|(n, ..)| *n == field.name)
    else {
        return Err(format!(
            "mutation '{}' is not allowed; only {} are",
            field.name,
            MUTATIONS.iter().map(|m| m.0).collect::<Vec<_>>().join(", ")
        ));
    };
    let args = unique(&field.args, "argument")?;
    let (1, Some(Value::Object(input))) = (args.len(), args.get("input")) else {
        return Err(format!(
            "{} must take a single input: {{…}} object literal",
            field.name
        ));
    };
    let input = unique(input, "input field")?;
    let mut targets = Vec::new();
    for key in input.keys() {
        if !other_keys.contains(key) && !id_keys.iter().any(|(k, ..)| k == key) {
            return Err(format!(
                "input field '{key}' is not allowed on {}",
                field.name
            ));
        }
    }
    for (key, kind, required) in *id_keys {
        match input.get(key) {
            None if *required => return Err(format!("{} needs {key}", field.name)),
            None => {}
            Some(v) => {
                let Some(id) = resolve(v, vars) else {
                    return Err(format!("{key} must be a plain string or -f variable"));
                };
                targets.push(Target {
                    id: id.to_string(),
                    kind: *kind,
                });
            }
        }
    }
    Ok((targets, payload))
}

// ── target verification ─────────────────────────────────────────────

const LOOKUP: &str = "query($id: ID!) { node(id: $id) { __typename \
    ... on PullRequestReviewThread { repository { url } } \
    ... on PullRequestReview { repository { url } } } }";

/// The `owner/name` a lookup response places `kind`'s node in, when it is a
/// github.com repository.
fn repo_from_lookup(json: &str, kind: NodeKind) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    if v.get("errors").is_some() {
        return None;
    }
    let node = v.get("data")?.get("node")?;
    if node.get("__typename")?.as_str()? != kind.typename() {
        return None;
    }
    let url = node.get("repository")?.get("url")?.as_str()?;
    let rest = url
        .get(..19)
        .filter(|p| p.eq_ignore_ascii_case("https://github.com/"))
        .map(|_| &url[19..])?;
    let (owner, name) = rest.split_once('/')?;
    (!owner.is_empty() && !name.is_empty() && !name.contains('/')).then(|| rest.to_string())
}

/// Look every target up with the real `gh` and require its repository to be in
/// scope. Runs with the same environment the approved command will, minus
/// `GH_HOST`/`GH_REPO` exactly as the exec scrubs them, so both reach the same
/// host.
#[allow(clippy::disallowed_methods)] // real_gh is the resolved path baked into the wrapper; this runs inside the sandbox
pub fn verify_targets(real_gh: &Path, targets: &[Target], scope: &[String]) -> Result<(), String> {
    for t in targets {
        let out = std::process::Command::new(real_gh)
            .args(["api", "graphql", "-f"])
            .arg(format!("query={LOOKUP}"))
            .arg("-f")
            .arg(format!("id={}", t.id))
            .env_remove("GH_HOST")
            .env_remove("GH_REPO")
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|e| format!("could not look up node '{}': {e}", t.id))?;
        let repo = out
            .status
            .success()
            .then(|| repo_from_lookup(&String::from_utf8_lossy(&out.stdout), t.kind))
            .flatten()
            .ok_or_else(|| {
                format!(
                    "could not verify that {} '{}' belongs to a github.com repository",
                    t.kind.typename(),
                    t.id
                )
            })?;
        if !scope.iter().any(|m| crate::gh_proxy::repos_match(&repo, m)) {
            return Err(format!(
                "{} '{}' belongs to '{repo}', outside the startup scope '{}'",
                t.kind.typename(),
                t.id,
                scope.join(", ")
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> Vec<String> {
        vec!["navikt/cplt".to_string()]
    }

    fn run(args: &[&str]) -> Result<Vec<Target>, String> {
        check(args, &scope())
    }

    fn q(query: &str) -> Result<Vec<Target>, String> {
        let field = format!("query={query}");
        run(&["api", "graphql", "-f", &field])
    }

    fn thread(id: &str) -> Vec<Target> {
        vec![Target {
            id: id.to_string(),
            kind: NodeKind::ReviewThread,
        }]
    }

    const READ_THREADS: &str = r#"query {
        repository(owner: "navikt", name: "cplt") {
          pullRequest(number: 414) {
            reviewThreads(first: 100) { nodes { id isResolved comments(first: 5) { nodes { body author { login } } } } }
          }
        }
      }"#;

    #[test]
    fn allows_a_read_of_the_scope_repository() {
        assert_eq!(q(READ_THREADS), Ok(vec![]));
        assert_eq!(
            q("{ repository(owner:\"NAVIKT\", name:\"cplt\") { __typename } }"),
            Ok(vec![])
        );
        assert_eq!(q("{ __typename }"), Ok(vec![]));
    }

    #[test]
    fn allows_query_variables_from_raw_fields() {
        let query = "query=query($o: String!, $n: String!) { repository(owner: $o, name: $n) { __typename } }";
        assert_eq!(
            run(&[
                "api",
                "graphql",
                "-f",
                query,
                "-f",
                "o=navikt",
                "--raw-field=n=cplt"
            ]),
            Ok(vec![])
        );
        let err = run(&[
            "api", "graphql", "-f", query, "-f", "o=evil", "-f", "n=cplt",
        ])
        .unwrap_err();
        assert!(err.contains("outside the startup scope"), "{err}");
        let err = run(&["api", "graphql", "-f", query, "-f", "o=navikt"]).unwrap_err();
        assert!(err.contains("plain strings"), "unbound variable: {err}");
    }

    #[test]
    fn refuses_reads_of_other_repositories_and_roots() {
        for (query, want) in [
            (
                "{ repository(owner:\"evil\", name:\"cplt\") { id } }",
                "outside the startup scope",
            ),
            ("{ viewer { login } }", "not allowed"),
            (
                "{ search(query:\"x\", type: REPOSITORY, first: 1) { repositoryCount } }",
                "not allowed",
            ),
            ("{ node(id:\"R_1\") { id } }", "not allowed"),
            (
                "{ a: repository(owner:\"navikt\", name:\"cplt\") { id } b: organization(login:\"x\") { id } }",
                "not allowed",
            ),
            (
                "{ repository(owner:\"navikt\", name:\"cplt\", owner:\"evil\") { id } }",
                "twice",
            ),
            (
                "{ repository(owner:\"navikt\", name:\"cplt\", followRenames: true) { id } }",
                "exactly",
            ),
            (
                "{ repository(owner:\"nav\\u0069kt\", name:\"cplt\") { id } }",
                "plain strings",
            ),
            (
                "{ repository(owner:\"navikt\", name:\"cplt\") { owner { login } } }",
                "field 'owner' on Repository is not allowed",
            ),
            (
                "{ repository(owner:\"navikt\", name:\"cplt\") { ...F } } fragment F on Repository { owner { login } }",
                "fragments",
            ),
            (
                "{ ...R } fragment R on Query { viewer { login } }",
                "fragments",
            ),
        ] {
            let err = q(query).unwrap_err();
            assert!(err.contains(want), "{query}: expected {want:?}, got {err}");
        }
    }

    #[test]
    fn top_level_keys_and_the_pagination_cursor_never_bind_variables() {
        // gh sends operationName outside `variables`, so the server would see
        // the default ("evil"), not the value the guard compared.
        let query = "query=query navikt($operationName: String = \"evil\") { repository(owner: $operationName, name: \"cplt\") { id } }";
        let err = run(&["api", "graphql", "-f", query, "-f", "operationName=navikt"]).unwrap_err();
        assert!(err.contains("plain strings"), "{err}");
        // --paginate replaces endCursor with a value from the response.
        let query = "query=mutation($endCursor: ID!) { resolveReviewThread(input: {threadId: $endCursor}) { clientMutationId } }";
        let err = run(&[
            "api",
            "graphql",
            "--paginate",
            "-f",
            query,
            "-f",
            "endCursor=PRRT_1",
        ])
        .unwrap_err();
        assert!(err.contains("plain string"), "{err}");
    }

    #[test]
    fn allows_an_allowlisted_mutation_and_returns_its_target() {
        assert_eq!(
            q(
                "mutation { resolveReviewThread(input: {threadId: \"PRRT_1\"}) { thread { isResolved } } }"
            ),
            Ok(thread("PRRT_1"))
        );
        assert_eq!(
            q(
                "mutation { unresolveReviewThread(input: {threadId: \"PRRT_1\"}) { clientMutationId } }"
            ),
            Ok(thread("PRRT_1"))
        );
        let query = "query=mutation($t: ID!, $b: String!) { addPullRequestReviewThreadReply(input: {pullRequestReviewThreadId: $t, body: $b, pullRequestReviewId: \"PRR_9\"}) { comment { id } } }";
        assert_eq!(
            run(&[
                "api", "graphql", "-f", query, "-F", "t=PRRT_2", "-f", "b=done"
            ]),
            Ok(vec![
                Target {
                    id: "PRRT_2".into(),
                    kind: NodeKind::ReviewThread
                },
                Target {
                    id: "PRR_9".into(),
                    kind: NodeKind::Review
                },
            ])
        );
    }

    #[test]
    fn every_aliased_mutation_target_is_returned() {
        assert_eq!(
            q("mutation { a: resolveReviewThread(input:{threadId:\"PRRT_1\"}) { clientMutationId } b: resolveReviewThread(input:{threadId:\"PRRT_2\"}) { clientMutationId } }")
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn refuses_non_allowlisted_and_smuggled_mutations() {
        for (query, want) in [
            (
                "mutation { deleteRepository(input:{repositoryId:\"R_1\"}) { clientMutationId } }",
                "not allowed",
            ),
            // Alias named like an allowed field: the field that runs is deleteIssue.
            (
                "mutation { resolveReviewThread: deleteIssue(input:{issueId:\"I_1\"}) { clientMutationId } }",
                "not allowed",
            ),
            (
                "mutation { resolveReviewThread(input:{threadId:\"PRRT_1\"}) { clientMutationId } mergePullRequest(input:{pullRequestId:\"PR_1\"}) { clientMutationId } }",
                "not allowed",
            ),
            (
                "mutation { ...M } fragment M on Mutation { deleteIssue(input:{issueId:\"I_1\"}) { clientMutationId } }",
                "fragments",
            ),
            (
                "mutation { ... on Mutation { deleteIssue(input:{issueId:\"I_1\"}) { clientMutationId } } }",
                "fragments",
            ),
            (
                "mutation { ... { deleteIssue(input:{issueId:\"I_1\"}) { clientMutationId } } }",
                "fragments",
            ),
            (
                "mutation { resolveReviewThread(input:{threadId:\"PRRT_1\", threadId:\"PRRT_2\"}) { clientMutationId } }",
                "twice",
            ),
            (
                "mutation { resolveReviewThread(input:{threadId:\"PRRT_1\", extra: 1}) { clientMutationId } }",
                "not allowed",
            ),
            (
                "mutation { resolveReviewThread(input: $in) { clientMutationId } }",
                "object literal",
            ),
            (
                "mutation { resolveReviewThread(input:{threadId:\"PRRT_\\u0031\"}) { clientMutationId } }",
                "plain string",
            ),
            (
                "mutation { resolveReviewThread(input:{}) { clientMutationId } }",
                "needs threadId",
            ),
            (
                "mutation { resolveReviewThread(input:{threadId:\"PRRT_1\"}) { thread { repository { owner { login } } } } }",
                "field 'repository' on PayloadThread is not allowed",
            ),
        ] {
            let err = q(query).unwrap_err();
            assert!(err.contains(want), "{query}: expected {want:?}, got {err}");
        }
    }

    #[test]
    fn refuses_multiple_operations_and_subscriptions() {
        let err = q("query A { __typename } mutation B { deleteIssue(input:{issueId:\"I\"}) { clientMutationId } }").unwrap_err();
        assert!(err.contains("only one operation"), "{err}");
        let err = run(&[
            "api",
            "graphql",
            "-f",
            "query=query A { __typename } query B { __typename }",
            "-f",
            "operationName=A",
        ])
        .unwrap_err();
        assert!(err.contains("only one operation"), "{err}");
        for query in ["subscription { __typename }", "subscription S { x }"] {
            let err = q(query).unwrap_err();
            assert!(err.contains("subscriptions"), "{err}");
        }
    }

    #[test]
    fn refuses_unparseable_input() {
        for query in [
            "",
            "{",
            "{ repository(owner:\"navikt\" name:\"cplt\") { id } ",
            "mutation { resolveReviewThread(input:{threadId:\"PRRT_1}) { id } }",
            "type Query { x: Int }",
            "{ a } }",
            "{ a(x: 1.) }",
            "{ a(x: 01a) }",
            "{ a..b }",
            "{ é }",
            "{ }",
            &format!("{}{}", "{ a ".repeat(100), "}".repeat(100)),
        ] {
            let err = q(query).unwrap_err();
            assert!(
                err.contains("does not parse") || err.contains("no operation"),
                "{query:?}: {err}"
            );
        }
    }

    #[test]
    fn comments_and_strings_do_not_hide_fields() {
        // An escaped quote does not end the string: all of this is the body.
        assert!(q(r#"mutation { addPullRequestReviewThreadReply(input:{pullRequestReviewThreadId:"PRRT_1", body:"\") { a } deleteIssue(input:{issueId:\"I\"}) { b } #"}) { clientMutationId } }"#).is_ok());
        // A '#' inside a string is not a comment; the brace after it is real.
        assert!(q("mutation { resolveReviewThread(input:{threadId:\"#\"}) { clientMutationId } deleteIssue(input:{issueId:\"I\"}) { clientMutationId } }").is_err());
        // A block string swallowing a quote does not end early.
        assert!(q("mutation { addPullRequestReviewThreadReply(input:{pullRequestReviewThreadId:\"PRRT_1\", body:\"\"\" \\\"\"\" } deleteIssue( \"\"\"}) { clientMutationId } }").is_ok());
        assert!(q("mutation { addPullRequestReviewThreadReply(input:{pullRequestReviewThreadId:\"PRRT_1\", body:\"\"\" \"\"\"}) { clientMutationId } deleteIssue(input:{issueId:\"I\"}) { clientMutationId } }").is_err());
    }

    #[test]
    fn refuses_argv_the_guard_cannot_see_through() {
        let query = "query={ __typename }";
        for (args, want) in [
            (vec!["api", "graphql"], "no query"),
            (
                vec!["api", "graphql", "--input", "body.json"],
                "not supported",
            ),
            (vec!["api", "graphql", "--input=-"], "not supported"),
            (
                vec!["api", "graphql", "-F", "query=@q.graphql"],
                "file or stdin",
            ),
            (
                vec!["api", "graphql", "-f", query, "-F", "o={owner}"],
                "placeholders",
            ),
            (
                vec!["api", "graphql", "-F", "query=query { x(b: \":branch\") }"],
                "placeholders",
            ),
            (
                vec![
                    "api",
                    "graphql",
                    "-f",
                    query,
                    "-H",
                    "Content-Type: text/plain",
                ],
                "not supported",
            ),
            (vec!["api", "graphql", "-f", query, "-X", "GET"], "POST"),
            (vec!["api", "graphql", "-f", query, "-f", query], "twice"),
            (
                vec!["api", "graphql", "-f", query, "-f", "input[threadId]=x"],
                "nested",
            ),
            (
                vec!["api", "graphql", "-fquery={ __typename }"],
                "not supported",
            ),
            (
                vec![
                    "api",
                    "graphql",
                    "-f",
                    query,
                    "--hostname",
                    "ghe.example.com",
                ],
                "github.com",
            ),
            (
                vec!["api", "graphql", "graphql", "-f", query],
                "not supported",
            ),
            (vec!["api", "-f", query], "exactly 'graphql'"),
            (
                vec!["api", "graphql", "-f", query, "--", "x"],
                "not supported",
            ),
        ] {
            let err = run(&args).unwrap_err();
            assert!(err.contains(want), "{args:?}: expected {want:?}, got {err}");
        }
        let err = run(&["api", "graphql", "-F", "query=5"]).unwrap_err();
        assert!(err.contains("must be a string"), "{err}");
        assert_eq!(
            run(&[
                "api",
                "graphql",
                "-X",
                "POST",
                "--paginate",
                "-q",
                ".data",
                "-f",
                query
            ]),
            Ok(vec![])
        );
    }

    #[test]
    fn lookup_response_names_the_repository() {
        let ok = r#"{"data":{"node":{"__typename":"PullRequestReviewThread","repository":{"url":"https://github.com/navikt/cplt"}}}}"#;
        assert_eq!(
            repo_from_lookup(ok, NodeKind::ReviewThread).as_deref(),
            Some("navikt/cplt")
        );
        // Wrong node type, missing node, GraphQL errors, another host: no answer.
        assert_eq!(repo_from_lookup(ok, NodeKind::Review), None);
        assert_eq!(
            repo_from_lookup(r#"{"data":{"node":null}}"#, NodeKind::ReviewThread),
            None
        );
        let with_errors = ok.replace("{\"data\"", "{\"errors\":[{}],\"data\"");
        assert_eq!(repo_from_lookup(&with_errors, NodeKind::ReviewThread), None);
        let ghes = ok.replace("https://github.com/", "https://ghe.example.com/");
        assert_eq!(repo_from_lookup(&ghes, NodeKind::ReviewThread), None);
        let deep = ok.replace("navikt/cplt", "navikt/cplt/pull/1");
        assert_eq!(repo_from_lookup(&deep, NodeKind::ReviewThread), None);
        assert_eq!(repo_from_lookup("not json", NodeKind::ReviewThread), None);
    }

    /// The #414 workflow: list open threads with their comments, paginated.
    #[test]
    fn allows_listing_unresolved_threads_with_comments() {
        let query = r#"query=query($endCursor: String) {
          repository(owner: "navikt", name: "cplt") {
            pullRequests(first: 5, states: OPEN, headRefName: "feat/x") { nodes { number title url isDraft } }
            pullRequest(number: 568) {
              __typename number state headRefName baseRefName
              reviewThreads(first: 100, after: $endCursor) {
                totalCount
                pageInfo { hasNextPage endCursor startCursor hasPreviousPage }
                edges { cursor node { id } }
                nodes {
                  id isResolved isOutdated path line originalLine startLine diffSide
                  comments(first: 50) {
                    nodes { id body url createdAt path author { login __typename } }
                  }
                }
              }
            }
          }
        }"#;
        assert_eq!(
            run(&["api", "graphql", "--paginate", "-f", query]),
            Ok(vec![])
        );
    }

    #[test]
    fn allows_resolving_and_replying_with_the_allowlisted_payloads() {
        assert_eq!(
            q(
                "mutation { resolveReviewThread(input:{threadId:\"PRRT_1\"}) { clientMutationId thread { id isResolved } } }"
            ),
            Ok(thread("PRRT_1"))
        );
        assert_eq!(
            q(
                "mutation { addPullRequestReviewThreadReply(input:{pullRequestReviewThreadId:\"PRRT_1\", body:\"done\"}) { comment { id url } } }"
            ),
            Ok(thread("PRRT_1"))
        );
    }

    /// Every route out of the scope repository the #568 review found.
    #[test]
    fn refuses_pivots_out_of_the_scope_repository() {
        const R: &str = "repository(owner:\"navikt\", name:\"cplt\")";
        for (query, want) in [
            // Another repository through the head repository's owner.
            (
                format!("{{ {R} {{ pullRequest(number:1) {{ headRepositoryOwner {{ repository(name:\"secret\") {{ object(expression:\"HEAD:.env\") {{ ... on Blob {{ text }} }} }} }} }} }} }}"),
                "field 'headRepositoryOwner' on PullRequest",
            ),
            // ... through a comment author, as a User.
            (
                format!("{{ {R} {{ pullRequest(number:1) {{ reviewThreads(first:1) {{ nodes {{ comments(first:1) {{ nodes {{ author {{ ... on User {{ repository(name:\"secret\") {{ id }} }} }} }} }} }} }} }} }} }}"),
                "fragments",
            ),
            (
                format!("{{ {R} {{ pullRequest(number:1) {{ reviewThreads(first:1) {{ nodes {{ comments(first:1) {{ nodes {{ author {{ repository(name:\"secret\") {{ id }} }} }} }} }} }} }} }} }}"),
                "field 'repository' on Author",
            ),
            (
                format!("{{ {R} {{ pullRequest(number:1) {{ author {{ login }} }} }} }}"),
                "field 'author' on PullRequest",
            ),
            (
                format!("{{ {R} {{ mentionableUsers(first:1) {{ nodes {{ repository(name:\"secret\") {{ id }} }} }} }} }}"),
                "field 'mentionableUsers' on Repository",
            ),
            (
                format!("{{ {R} {{ assignableUsers(first:1) {{ nodes {{ login }} }} }} }}"),
                "field 'assignableUsers' on Repository",
            ),
            // ... through a cross-reference from another repository.
            (
                format!("{{ {R} {{ pullRequest(number:1) {{ timelineItems(first:9) {{ nodes {{ ... on CrossReferencedEvent {{ source {{ ... on Issue {{ repository {{ nameWithOwner }} }} }} }} }} }} }} }} }}"),
                "field 'timelineItems' on PullRequest",
            ),
            // ... through a fork parent or template.
            (
                format!("{{ {R} {{ parent {{ object(expression:\"HEAD:.env\") {{ id }} }} }} }}"),
                "field 'parent' on Repository",
            ),
            (
                format!("{{ {R} {{ templateRepository {{ nameWithOwner }} }} }}"),
                "field 'templateRepository' on Repository",
            ),
            (
                format!("{{ {R} {{ pullRequest(number:1) {{ headRepository {{ nameWithOwner }} }} }} }}"),
                "field 'headRepository' on PullRequest",
            ),
            // File contents, even of the scope repository.
            (
                format!("{{ {R} {{ object(expression:\"HEAD:.env\") {{ ... on Blob {{ text }} }} }} }}"),
                "field 'object' on Repository",
            ),
            // The viewer and what it can enumerate, via an author fragment.
            (
                format!("{{ {R} {{ pullRequest(number:1) {{ reviewThreads(first:1) {{ nodes {{ comments(first:1) {{ nodes {{ author {{ ... on User {{ topRepositories(first:9, orderBy:{{field:NAME, direction:ASC}}) {{ nodes {{ nameWithOwner }} }} starredRepositories {{ totalCount }} }} }} }} }} }} }} }} }} }}"),
                "fragments",
            ),
            // A named fragment is refused too, whatever it selects.
            (
                format!("{{ {R} {{ ...F }} }} fragment F on Repository {{ pullRequest(number:1) {{ id }} }}"),
                "fragments",
            ),
            (
                format!("{{ {R} {{ __typename }} }} fragment F on Repository {{ owner {{ login }} }}"),
                "fragments",
            ),
            // Harmless-looking field with an argument not on its list.
            (
                format!("{{ {R} {{ pullRequest(number:1) {{ reviewThreads(first:1, last:1) {{ totalCount }} }} }} }}"),
                "argument 'last'",
            ),
            (
                format!("{{ {R} {{ pullRequest(number:1) {{ number {{ x }} }} }} }}"),
                "no fields to select",
            ),
            // A mutation payload that climbs to the repository and beyond.
            (
                "mutation { resolveReviewThread(input:{threadId:\"PRRT_1\"}) { thread { pullRequest { headRepositoryOwner { login } } } } }".to_string(),
                "field 'pullRequest' on PayloadThread",
            ),
            (
                "mutation { addPullRequestReviewThreadReply(input:{pullRequestReviewThreadId:\"PRRT_1\", body:\"x\"}) { comment { author { ... on User { repositories(first:9) { nodes { name } } } } } } }".to_string(),
                "field 'author' on PayloadComment",
            ),
            (
                "mutation { resolveReviewThread(input:{threadId:\"PRRT_1\"}) { thread { comments(first:1) { nodes { body } } } } }".to_string(),
                "field 'comments' on PayloadThread",
            ),
        ] {
            let err = q(&query).unwrap_err();
            assert!(err.contains(want), "{query}: expected {want:?}, got {err}");
        }
    }

    #[test]
    fn nits_exact_post_and_bounded_type_nesting() {
        let query = "query={ __typename }";
        let err = run(&["api", "graphql", "-X", "post", "-f", query]).unwrap_err();
        assert!(err.contains("POST"), "{err}");
        let deep = format!(
            "query($a: {}Int{}) {{ __typename }}",
            "[".repeat(100),
            "]".repeat(100)
        );
        let err = q(&deep).unwrap_err();
        assert!(err.contains("nesting too deep"), "{err}");
    }
}

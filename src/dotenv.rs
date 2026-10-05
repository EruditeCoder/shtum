//! Reading a `.env` file, so existing keys can move into shtum without anyone typing them.
//!
//! Handles what real `.env` files contain: comments, `export ` prefixes, single quotes
//! (literal), double quotes (with `\n`, `\"` and `\\` escapes, possibly spanning lines), and
//! unquoted values with a trailing ` # comment`.

use anyhow::{Result, bail};

pub fn parse(text: &str) -> Result<Vec<(String, String)>> {
    let mut out = vec![];
    let mut lines = text.lines().enumerate();
    while let Some((n, raw)) = lines.next() {
        let line = raw.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line
            .strip_prefix("export ")
            .map(str::trim_start)
            .unwrap_or(line);
        let Some((key, rest)) = line.split_once('=') else {
            bail!("line {}: expected NAME=value", n + 1);
        };
        let key = key.trim().to_string();
        if !crate::vault::valid_name(&key) {
            bail!("line {}: {key:?} is not a variable name", n + 1);
        }
        let rest = rest.trim_start();
        let value = if let Some(body) = rest.strip_prefix('"') {
            let mut acc = body.to_string();
            loop {
                if let Some(end) = closing_quote(&acc) {
                    break unescape(&acc[..end]);
                }
                match lines.next() {
                    Some((_, more)) => {
                        acc.push('\n');
                        acc.push_str(more);
                    }
                    None => bail!("line {}: unclosed double quote for {key}", n + 1),
                }
            }
        } else if let Some(body) = rest.strip_prefix('\'') {
            match body.find('\'') {
                Some(end) => body[..end].to_string(),
                None => bail!("line {}: unclosed single quote for {key}", n + 1),
            }
        } else {
            let v = match rest.find(" #") {
                Some(i) => &rest[..i],
                None => rest,
            };
            v.trim().to_string()
        };
        out.push((key, value));
    }
    Ok(out)
}

fn closing_quote(s: &str) -> Option<usize> {
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        match c {
            '\\' if !escaped => escaped = true,
            '"' if !escaped => return Some(i),
            _ => escaped = false,
        }
    }
    None
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some(o) => out.push(o),
            None => out.push('\\'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_shapes_real_files_have() {
        let text = r#"
# comment
PLAIN=abc
export EXPORTED=def
SPACED = ghi   # trailing comment
URL=postgres://u:p@h/db?x=1#frag
SINGLE='lit $HOME \n'
DOUBLE="a\nb \"q\""
MULTI="-----BEGIN KEY-----
line2
-----END KEY-----"
EMPTY=
"#;
        let got = parse(text).unwrap();
        let get = |k: &str| got.iter().find(|(n, _)| n == k).unwrap().1.clone();
        assert_eq!(get("PLAIN"), "abc");
        assert_eq!(get("EXPORTED"), "def");
        assert_eq!(get("SPACED"), "ghi");
        assert_eq!(get("URL"), "postgres://u:p@h/db?x=1#frag");
        assert_eq!(get("SINGLE"), "lit $HOME \\n");
        assert_eq!(get("DOUBLE"), "a\nb \"q\"");
        assert_eq!(
            get("MULTI"),
            "-----BEGIN KEY-----\nline2\n-----END KEY-----"
        );
        assert_eq!(get("EMPTY"), "");
    }

    #[test]
    fn refuses_what_it_cannot_read_rather_than_guessing() {
        assert!(parse("NOEQUALS\n").is_err());
        assert!(parse("A=\"open\n").is_err());
        assert!(parse("1BAD=x\n").is_err());
    }
}

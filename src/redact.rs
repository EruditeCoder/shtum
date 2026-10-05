//! Masking values in a stream of output.
//!
//! When `shtum run` is not talking to a person's terminal, everything the child prints passes
//! through here and each injected value comes out as `[shtum:NAME]`. That catches the ordinary
//! accident — a debug log, a stack trace with a config object, `curl -v` echoing a header — on
//! its way into an agent's context, where it would be sent to a model and saved to disk.
//!
//! It is not a sandbox: a value that is encoded, split or transformed before it is printed gets
//! through. Values shorter than [`MIN_LEN`] are not masked, because masking `3000` everywhere
//! would wreck the output while protecting nothing.

pub const MIN_LEN: usize = 8;

pub struct Redactor {
    /// (value, replacement), longest value first so a value containing another wins.
    patterns: Vec<(Vec<u8>, Vec<u8>)>,
    longest: usize,
    held: Vec<u8>,
}

impl Redactor {
    pub fn new<'a>(values: impl IntoIterator<Item = (&'a str, &'a [u8])>) -> Redactor {
        let mut patterns: Vec<(Vec<u8>, Vec<u8>)> = values
            .into_iter()
            .filter(|(_, v)| v.len() >= MIN_LEN)
            .map(|(n, v)| (v.to_vec(), format!("[shtum:{n}]").into_bytes()))
            .collect();
        // A value with a trailing newline is usually printed without it.
        let trimmed: Vec<_> = patterns
            .iter()
            .filter_map(|(v, r)| {
                let t = v.trim_ascii_end();
                (t.len() != v.len() && t.len() >= MIN_LEN).then(|| (t.to_vec(), r.clone()))
            })
            .collect();
        patterns.extend(trimmed);
        patterns.sort_by_key(|p| std::cmp::Reverse(p.0.len()));
        patterns.dedup_by(|a, b| a.0 == b.0);
        let longest = patterns.first().map_or(0, |p| p.0.len());
        Redactor {
            patterns,
            longest,
            held: vec![],
        }
    }

    /// Feed a chunk; returns what is safe to print now. A tail that could be the start of a
    /// value is held back until the next chunk shows whether it is.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.held.extend_from_slice(chunk);
        let (out, keep_from) = self.scan(false);
        self.held.drain(..keep_from);
        out
    }

    /// The stream has ended: whatever is held cannot become a full value any more.
    pub fn finish(&mut self) -> Vec<u8> {
        let (out, _) = self.scan(true);
        self.held.clear();
        out
    }

    fn scan(&self, last: bool) -> (Vec<u8>, usize) {
        let buf = &self.held;
        let mut out = Vec::with_capacity(buf.len());
        let mut i = 0;
        'outer: while i < buf.len() {
            let rest = &buf[i..];
            for (v, r) in &self.patterns {
                if rest.starts_with(v) {
                    out.extend_from_slice(r);
                    i += v.len();
                    continue 'outer;
                }
            }
            if !last
                && rest.len() < self.longest
                && self.patterns.iter().any(|(v, _)| v.starts_with(rest))
            {
                return (out, i);
            }
            out.push(buf[i]);
            i += 1;
        }
        (out, i)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(values: &[(&str, &str)], chunks: &[&str]) -> String {
        let mut r = Redactor::new(values.iter().map(|(n, v)| (*n, v.as_bytes())));
        let mut out = vec![];
        for c in chunks {
            out.extend(r.push(c.as_bytes()));
        }
        out.extend(r.finish());
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn masks_a_value_and_leaves_the_rest() {
        assert_eq!(
            run(
                &[("K", "fake-secret-abcdef")],
                &["key=fake-secret-abcdef ok\n"]
            ),
            "key=[shtum:K] ok\n"
        );
    }

    #[test]
    fn masks_a_value_split_across_chunks() {
        let out = run(
            &[("K", "fake-secret-abcdef")],
            &["a fake-se", "cret-ab", "cdef b"],
        );
        assert_eq!(out, "a [shtum:K] b");
        let out = run(
            &[("K", "fake-secret-abcdef")],
            &["f", "a", "k", "e-secret-abcdef", ""],
        );
        assert_eq!(out, "[shtum:K]");
    }

    #[test]
    fn a_partial_prefix_at_the_end_is_released() {
        assert_eq!(
            run(&[("K", "fake-secret-abcdef")], &["tail fake-se"]),
            "tail fake-se"
        );
    }

    #[test]
    fn short_values_are_not_masked_and_longest_wins() {
        assert_eq!(run(&[("PORT", "3000")], &["port 3000"]), "port 3000");
        let out = run(
            &[("A", "abcdefgh"), ("B", "abcdefghijk")],
            &["abcdefghijk abcdefgh"],
        );
        assert_eq!(out, "[shtum:B] [shtum:A]");
    }

    #[test]
    fn a_value_with_a_trailing_newline_is_masked_without_it() {
        assert_eq!(
            run(
                &[("K", "fake-secret-abcdef\n")],
                &["x fake-secret-abcdef y"]
            ),
            "x [shtum:K] y"
        );
    }
}

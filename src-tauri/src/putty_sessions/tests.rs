use super::*;

fn s(value: &str) -> RegValue {
    RegValue::Str(value.to_string())
}

fn d(value: u32) -> RegValue {
    RegValue::Dword(value)
}

fn raw(key_name: &str, values: Vec<(&str, RegValue)>) -> RawSession {
    RawSession {
        key_name: key_name.to_string(),
        values: values
            .into_iter()
            .map(|(name, value)| (name.to_string(), value))
            .collect(),
        unreadable: None,
    }
}

/// A session key the reader could not open, and why.
fn unreadable(key_name: &str, error: &str) -> RawSession {
    RawSession {
        unreadable: Some(error.to_string()),
        ..raw(key_name, vec![])
    }
}

/// An SSH session to `host`, with `more` values beside it.
fn ssh(key_name: &str, host: &str, more: Vec<(&str, RegValue)>) -> RawSession {
    let mut values = vec![("Protocol", s("ssh")), ("HostName", s(host))];
    values.extend(more);
    raw(key_name, values)
}

fn convert(session: &RawSession) -> Result<PuttySession, SkippedSession> {
    session_from_raw(session, Some("local-user"))
}

fn skip_reason(session: &RawSession) -> String {
    match convert(session) {
        Ok(converted) => panic!("{session:?} was not skipped: {converted:?}"),
        Err(skipped) => skipped.reason,
    }
}

fn names(listing: &PuttyListing) -> Vec<&str> {
    listing.sessions.iter().map(|s| s.name.as_str()).collect()
}

#[test]
fn session_names_are_unescaped_the_way_putty_escapes_them() {
    for (escaped, name) in [
        ("Default%20Settings", "Default Settings"),
        ("%2Ehidden", ".hidden"),
        ("%2ehidden", ".hidden"),
        ("100%25", "100%"),
        ("a%3Ab%3ac", "a:b:c"),
        ("back%5Cslash%2A%3F", "back\\slash*?"),
        ("tab%09here", "tab\there"),
        // A `%` without two hex digits after it is itself.
        ("50%", "50%"),
        ("50%2", "50%2"),
        ("%zz", "%zz"),
        ("%g1x", "%g1x"),
        ("%%41", "%A"),
        // The bytes are UTF-8 in current PuTTY (the ANSI code page in
        // older ones: see the tests below and the Windows tests).
        ("caf%C3%A9", "café"),
        ("plain", "plain"),
        ("", ""),
    ] {
        assert_eq!(unescape_session_name(escaped), name, "{escaped}");
    }
}

/// Off Windows there is no ANSI code page to ask, and only the tests
/// decode names: Windows-1252 stands in for it.
#[cfg(not(windows))]
#[test]
fn off_windows_names_that_are_not_utf8_are_read_as_windows_1252() {
    for (escaped, name) in [
        ("caf%E9", "café"),
        ("%80uro", "€uro"),
        ("caf%E9%BA%FE", "caféºþ"),
    ] {
        assert_eq!(unescape_session_name(escaped), name, "{escaped}");
    }
    // 0x81 has no character in Windows-1252: it reads as the C1 control
    // of that number, so the session is skipped.
    assert_eq!(
        skip_reason(&ssh("caf%81", "h", vec![])),
        "name contains a control character"
    );
}

#[test]
fn a_name_with_a_control_character_is_skipped_and_shown_without_it() {
    // LF, DEL, NUL and NEL (C1, as UTF-8).
    for key in ["line%0Abreak", "del%7F", "nul%00x", "c1%C2%85"] {
        let skipped = convert(&ssh(key, "host.example", vec![])).unwrap_err();
        assert_eq!(skipped.reason, "name contains a control character", "{key}");
        assert!(
            !skipped.name.chars().any(char::is_control),
            "{key}: {:?}",
            skipped.name
        );
    }
    let skipped = convert(&ssh("line%0Abreak", "host.example", vec![])).unwrap_err();
    assert_eq!(skipped.name, "line\u{FFFD}break");
}

#[test]
fn host_names_are_cleaned_up_the_way_putty_does_before_it_connects() {
    // HostName, UserName, the host stored, the user name stored.
    for (host_name, user_name, host, username) in [
        ("example.com", None, "example.com", None),
        ("  example.com\t", None, "example.com", None),
        ("deploy@example.com", None, "example.com", Some("deploy")),
        (
            "deploy@example.com",
            Some("other"),
            "example.com",
            Some("deploy"),
        ),
        ("a@b@example.com", None, "example.com", Some("a@b")),
        (
            "@example.com",
            Some("fallback"),
            "example.com",
            Some("fallback"),
        ),
        // One colon: PuTTY drops it and what follows (it is not a port).
        ("example.com:22", None, "example.com", None),
        ("example.com:", None, "example.com", None),
        (
            "deploy@example.com:2222",
            None,
            "example.com",
            Some("deploy"),
        ),
        // More than one: an IPv6 address, kept.
        ("::1", None, "::1", None),
        ("fe80::1:2", None, "fe80::1:2", None),
        // Brackets are dropped from an IPv6 address.
        ("[::1]", None, "::1", None),
        ("[2001:db8::5]:22", None, "2001:db8::5", None),
        // Spaces and tabs anywhere are removed.
        ("exa mple.com", None, "example.com", None),
        ("exa\tmple . com", None, "example.com", None),
    ] {
        let mut more = vec![];
        if let Some(user) = user_name {
            more.push(("UserName", s(user)));
        }
        let session = convert(&ssh("s", host_name, more)).unwrap();
        assert_eq!(session.host, host, "{host_name:?}");
        assert_eq!(session.username.as_deref(), username, "{host_name:?}");
    }
}

#[test]
fn a_session_without_a_usable_host_is_skipped() {
    let bracketed = "bracketed host name is not an IPv6 address";
    for (host_name, reason) in [
        ("", "no host name"),
        ("  \t ", "no host name"),
        ("deploy@", "no host name"),
        (":22", "no host name"),
        ("[not-ipv6]", bracketed),
        ("[example.com]:22", bracketed),
        ("[::1", bracketed),
        ("::1]", bracketed),
        ("[]", bracketed),
        (
            "bad\nhost.example",
            "host name contains a control character",
        ),
        (
            "bad\u{7f}host.example",
            "host name contains a control character",
        ),
    ] {
        assert_eq!(
            skip_reason(&ssh("s", host_name, vec![])),
            reason,
            "{host_name:?}"
        );
    }
    let longest = "h".repeat(255);
    assert_eq!(convert(&ssh("s", &longest, vec![])).unwrap().host, longest);
    assert_eq!(
        skip_reason(&ssh("s", &"h".repeat(256), vec![])),
        "host name longer than 255 characters"
    );
}

#[test]
fn the_port_is_22_unless_putty_has_a_valid_one() {
    for (port, expected) in [
        (None, Some(22)),
        (Some(d(0)), Some(22)),
        (Some(d(1)), Some(1)),
        (Some(d(2222)), Some(2222)),
        (Some(d(65535)), Some(65535)),
        // A string is not a port number PuTTY wrote: absent.
        (Some(s("2222")), Some(22)),
        (Some(d(65536)), None),
        (Some(d(70000)), None),
        (Some(d(u32::MAX)), None),
    ] {
        let mut more = vec![];
        if let Some(value) = port.clone() {
            more.push(("PortNumber", value));
        }
        let session = ssh("s", "host.example", more);
        match expected {
            Some(number) => assert_eq!(convert(&session).unwrap().port, number, "{port:?}"),
            None => assert_eq!(skip_reason(&session), "port out of range", "{port:?}"),
        }
    }
}

#[test]
fn only_ssh_sessions_are_offered() {
    let without_protocol = raw("s", vec![("HostName", s("host.example"))]);
    assert!(convert(&without_protocol).is_ok(), "absent means ssh");
    // An empty string, or a DWORD, is no protocol: absent.
    for protocol in [s("ssh"), s(" ssh "), s(""), s("  "), d(1)] {
        let session = raw(
            "s",
            vec![
                ("HostName", s("host.example")),
                ("Protocol", protocol.clone()),
            ],
        );
        assert!(convert(&session).is_ok(), "{protocol:?}");
    }
    for protocol in [
        "telnet", "serial", "raw", "rlogin", "supdup", "bare", "SSH2",
    ] {
        let session = raw(
            "s",
            vec![("HostName", s("host.example")), ("Protocol", s(protocol))],
        );
        assert_eq!(
            skip_reason(&session),
            format!("not an SSH session ({protocol})")
        );
    }
    // Not repeated when it is not something to show.
    for protocol in ["tel\nnet".to_string(), "x".repeat(100)] {
        let session = raw(
            "s",
            vec![("HostName", s("host.example")), ("Protocol", s(&protocol))],
        );
        assert_eq!(skip_reason(&session), "not an SSH session");
    }
}

#[test]
fn the_user_name_comes_from_the_host_then_putty_then_the_local_user() {
    let env = || ("UserNameFromEnvironment", d(1));
    // HostName, other values, the local user, the user name stored.
    for (host_name, more, local, expected) in [
        (
            "me@h",
            vec![("UserName", s("putty")), env()],
            Some("local"),
            Some("me"),
        ),
        (
            "h",
            vec![("UserName", s(" putty ")), env()],
            Some("local"),
            Some("putty"),
        ),
        (
            "h",
            vec![("UserName", s("  ")), env()],
            Some("local"),
            Some("local"),
        ),
        ("h", vec![env()], Some(" local "), Some("local")),
        ("h", vec![env()], None, None),
        ("h", vec![env()], Some("  "), None),
        (
            "h",
            vec![("UserNameFromEnvironment", d(0))],
            Some("local"),
            None,
        ),
        // On when nonzero, the way PuTTY reads its booleans.
        (
            "h",
            vec![("UserNameFromEnvironment", d(2))],
            Some("local"),
            Some("local"),
        ),
        (
            "h",
            vec![("UserNameFromEnvironment", d(u32::MAX))],
            Some("local"),
            Some("local"),
        ),
        (
            "h",
            vec![("UserNameFromEnvironment", s("1"))],
            Some("local"),
            None,
        ),
        ("h", vec![("UserName", d(5))], Some("local"), None),
        ("h", vec![], Some("local"), None),
        (" me @h", vec![("UserName", s("putty"))], None, Some("me")),
    ] {
        let session = session_from_raw(&ssh("s", host_name, more.clone()), local).unwrap();
        assert_eq!(
            session.username.as_deref(),
            expected,
            "{host_name:?} {more:?} {local:?}"
        );
    }
}

#[test]
fn a_key_file_means_publickey_and_none_means_password() {
    for (key_file, expected) in [
        (Some(s(r"C:\keys\prod.ppk")), Some(r"C:\keys\prod.ppk")),
        (
            Some(s("  C:\\keys\\spaced.ppk ")),
            Some(r"C:\keys\spaced.ppk"),
        ),
        (
            Some(s(r"\\fileserver\keys\shared.ppk")),
            Some(r"\\fileserver\keys\shared.ppk"),
        ),
        (Some(s("")), None),
        (Some(s("   ")), None),
        (Some(d(1)), None),
        (None, None),
    ] {
        let mut more = vec![];
        if let Some(value) = key_file.clone() {
            more.push(("PublicKeyFile", value));
        }
        let session = convert(&ssh("s", "host.example", more)).unwrap();
        assert_eq!(session.key_file.as_deref(), expected, "{key_file:?}");
        let method = if expected.is_some() {
            "publickey"
        } else {
            "password"
        };
        assert_eq!(session.auth_method, method, "{key_file:?}");
    }
}

#[test]
fn settings_sshspan_does_not_use_are_noted() {
    let all = vec![
        ("ProxyMethod", d(5)),
        ("PortForwardings", s("L8080=localhost:80")),
        ("AgentFwd", d(1)),
        ("X11Forward", d(1)),
    ];
    assert_eq!(
        convert(&ssh("s", "h", all)).unwrap().notes,
        [
            "proxy",
            "portForwarding",
            "agentForwarding",
            "x11Forwarding"
        ]
    );
    for (name, value, note) in [
        ("ProxyMethod", d(1), "proxy"),
        ("PortForwardings", s("R2222=localhost:22"), "portForwarding"),
        ("AgentFwd", d(1), "agentForwarding"),
        ("X11Forward", d(1), "x11Forwarding"),
    ] {
        let session = convert(&ssh("s", "h", vec![(name, value)])).unwrap();
        assert_eq!(session.notes, [note], "{name}");
    }
    let none = vec![
        ("ProxyMethod", d(0)),
        ("PortForwardings", s("  ")),
        ("AgentFwd", d(0)),
        ("X11Forward", d(0)),
    ];
    assert!(convert(&ssh("s", "h", none)).unwrap().notes.is_empty());
    // On when nonzero, the way PuTTY reads its booleans.
    let nonzero = vec![("AgentFwd", d(2)), ("X11Forward", d(u32::MAX))];
    assert_eq!(
        convert(&ssh("s", "h", nonzero)).unwrap().notes,
        ["agentForwarding", "x11Forwarding"]
    );
    let wrong_types = vec![
        ("ProxyMethod", s("5")),
        ("PortForwardings", d(1)),
        ("AgentFwd", s("1")),
        ("X11Forward", s("1")),
    ];
    assert!(convert(&ssh("s", "h", wrong_types))
        .unwrap()
        .notes
        .is_empty());
    assert!(convert(&ssh("s", "h", vec![])).unwrap().notes.is_empty());
}

#[test]
fn already_saved_matches_host_port_and_user_name() {
    let saved = [
        SavedServer {
            host: " Example.COM ",
            port: 22,
            username: " deploy ",
        },
        SavedServer {
            host: "db.example",
            port: 2222,
            username: "ops",
        },
    ];
    let session = |key: &str, host: &str, port: u32, user: Option<&str>| {
        let mut more = vec![("PortNumber", d(port))];
        if let Some(user) = user {
            more.push(("UserName", s(user)));
        }
        ssh(key, host, more)
    };
    let listing = build_listing(
        vec![
            session("a same account", "example.com", 22, Some("deploy")),
            session("b user name case", "example.com", 22, Some("Deploy")),
            session("c other user", "example.com", 22, Some("root")),
            session("d other port", "example.com", 2222, Some("deploy")),
            session("e other host", "example.org", 22, Some("deploy")),
            session("f no user, saved host and port", "EXAMPLE.com", 22, None),
            session("g no user, other saved server", "db.example", 2222, None),
            session("h no user, port not saved", "db.example", 22, None),
        ],
        &saved,
        None,
    );
    let flags: Vec<(&str, bool)> = listing
        .sessions
        .iter()
        .map(|s| (s.name.as_str(), s.already_saved))
        .collect();
    assert_eq!(
        flags,
        [
            ("a same account", true),
            ("b user name case", false),
            ("c other user", false),
            ("d other port", false),
            ("e other host", false),
            ("f no user, saved host and port", true),
            ("g no user, other saved server", true),
            ("h no user, port not saved", false),
        ]
    );
}

#[test]
fn default_settings_is_not_a_session_and_is_never_listed() {
    let web = || ssh("web", "web.example", vec![]);
    for template in [
        ssh("Default%20Settings", "", vec![]),
        ssh("Default%20Settings", "default.example", vec![]),
        raw("Default%20Settings", vec![("Protocol", s("telnet"))]),
        ssh("Default Settings", "", vec![]),
    ] {
        let listing = build_listing(vec![template.clone(), web()], &[], None);
        assert_eq!(names(&listing), ["web"], "{template:?}");
        assert!(listing.skipped.is_empty(), "{template:?}: {listing:?}");
    }
    // PuTTY compares the name exactly: another spelling is a session.
    let listing = build_listing(vec![ssh("default%20settings", "h", vec![])], &[], None);
    assert_eq!(names(&listing), ["default settings"]);
}

#[test]
fn names_and_hosts_over_the_limits_are_skipped() {
    let longest = "n".repeat(256);
    assert_eq!(convert(&ssh(&longest, "h", vec![])).unwrap().name, longest);
    assert_eq!(
        skip_reason(&ssh(&"n".repeat(257), "h", vec![])),
        "name longer than 256 characters"
    );
    // Counted after unescaping, in characters.
    let escaped = "%C3%A9".repeat(256);
    assert_eq!(
        convert(&ssh(&escaped, "h", vec![])).unwrap().name,
        "é".repeat(256)
    );
}

#[test]
fn at_most_a_thousand_sessions_are_listed() {
    let many = |count: usize| -> Vec<RawSession> {
        (0..count)
            .map(|i| {
                let protocol = if i % 2 == 0 { "ssh" } else { "telnet" };
                raw(
                    &format!("s{i:04}"),
                    vec![("HostName", s("h")), ("Protocol", s(protocol))],
                )
            })
            .collect()
    };
    let listed = |listing: &PuttyListing| listing.sessions.len() + listing.skipped.len();
    let exactly = build_listing(many(MAX_SESSIONS), &[], None);
    assert_eq!(listed(&exactly), MAX_SESSIONS);
    assert!(!exactly.truncated);
    let over = build_listing(many(MAX_SESSIONS + 5), &[], None);
    assert_eq!(listed(&over), MAX_SESSIONS);
    assert!(over.truncated);
    assert_eq!(
        over.sessions.last().unwrap().name,
        "s0998",
        "the first ones read"
    );
    assert_eq!(over.skipped.last().unwrap().name, "s0999");
    // PuTTY's template is not one of the thousand.
    let mut with_template = many(MAX_SESSIONS);
    with_template.insert(0, ssh("Default%20Settings", "", vec![]));
    let listing = build_listing(with_template, &[], None);
    assert_eq!(listed(&listing), MAX_SESSIONS);
    assert!(!listing.truncated);
    assert!(build_listing(vec![], &[], None) == PuttyListing::default());
}

#[test]
fn sessions_and_skipped_ones_are_sorted_by_name_ignoring_case() {
    let mut raws: Vec<RawSession> = ["delta", "Bravo", "alpha", "Charlie", "ALPHA2"]
        .into_iter()
        .map(|name| ssh(name, "h", vec![]))
        .collect();
    for name in ["zulu", "Echo"] {
        raws.push(raw(name, vec![("Protocol", s("telnet"))]));
    }
    let listing = build_listing(raws, &[], None);
    assert_eq!(
        names(&listing),
        ["alpha", "ALPHA2", "Bravo", "Charlie", "delta"]
    );
    let skipped: Vec<&str> = listing.skipped.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(skipped, ["Echo", "zulu"]);
}

#[test]
fn a_value_of_the_wrong_type_counts_as_absent() {
    let session = convert(&ssh("s", "h", vec![("PortNumber", s("2222"))])).unwrap();
    assert_eq!(session.port, 22);
    let dword_host = raw("s", vec![("HostName", d(1)), ("Protocol", s("ssh"))]);
    assert_eq!(skip_reason(&dword_host), "no host name");
}

#[test]
fn the_listing_has_the_contracts_json_field_names() {
    let listing = build_listing(
        vec![
            ssh(
                "prod%20web",
                "deploy@10.0.0.5",
                vec![
                    ("PortNumber", d(22)),
                    ("PublicKeyFile", s(r"C:\keys\prod.ppk")),
                    ("ProxyMethod", d(1)),
                ],
            ),
            ssh("bare", "bare.example", vec![]),
            raw("console", vec![("Protocol", s("serial"))]),
        ],
        &[],
        None,
    );
    assert_eq!(
        serde_json::to_value(&listing).unwrap(),
        serde_json::json!({
            "sessions": [
                {
                    "name": "bare",
                    "host": "bare.example",
                    "port": 22,
                    "username": null,
                    "keyFile": null,
                    "authMethod": "password",
                    "notes": [],
                    "alreadySaved": false
                },
                {
                    "name": "prod web",
                    "host": "10.0.0.5",
                    "port": 22,
                    "username": "deploy",
                    "keyFile": "C:\\keys\\prod.ppk",
                    "authMethod": "publickey",
                    "notes": ["proxy"],
                    "alreadySaved": false
                }
            ],
            "skipped": [{ "name": "console", "reason": "not an SSH session (serial)" }],
            "truncated": false
        })
    );
    assert_eq!(
        serde_json::to_value(PuttyListing::default()).unwrap(),
        serde_json::json!({ "sessions": [], "skipped": [], "truncated": false })
    );
}

fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

#[test]
fn registry_data_is_read_as_putty_writes_it() {
    // REG_SZ = 1, REG_EXPAND_SZ = 2, REG_BINARY = 3, REG_DWORD = 4,
    // REG_DWORD_BIG_ENDIAN = 5, REG_MULTI_SZ = 7, REG_QWORD = 11.
    let limit = "x".repeat(MAX_STRING_BYTES / 2);
    let over = "x".repeat(MAX_STRING_BYTES / 2 + 1);
    let at_cap_with_nul = format!("{}\0", "x".repeat(MAX_STRING_BYTES / 2 - 1));
    let over_with_nul = format!("{limit}\0");
    for (value_type, data, expected) in [
        (1, utf16("host\0"), Some(s("host"))),
        (1, utf16("host"), Some(s("host"))),
        (1, utf16("host\0junk\0"), Some(s("host"))),
        (1, utf16(""), Some(s(""))),
        (1, vec![0x68, 0x00, 0x6f], None),
        (1, vec![0x00, 0xd8], Some(s("\u{FFFD}"))),
        (1, utf16(&limit), Some(s(&limit))),
        (
            1,
            utf16(&at_cap_with_nul),
            Some(s(&"x".repeat(MAX_STRING_BYTES / 2 - 1))),
        ),
        // Over the cap a string is too long - not absent - whatever it
        // holds: the reader knows only its size.
        (1, utf16(&over), Some(RegValue::TooLong)),
        (1, utf16(&over_with_nul), Some(RegValue::TooLong)),
        (1, vec![0x41; MAX_STRING_BYTES + 1], Some(RegValue::TooLong)),
        (4, vec![0x16, 0, 0, 0], Some(d(22))),
        (4, vec![0xff, 0xff, 0xff, 0xff], Some(d(u32::MAX))),
        (4, vec![0x16, 0, 0], None),
        (4, vec![0x16, 0, 0, 0, 0, 0, 0, 0], None),
        (2, utf16("host\0"), None),
        (3, vec![0x16, 0, 0, 0], None),
        (5, vec![0, 0, 0, 0x16], None),
        (7, utf16("host\0\0"), None),
        (11, vec![0x16, 0, 0, 0, 0, 0, 0, 0], None),
    ] {
        assert_eq!(
            decode_value(value_type, &data),
            expected,
            "type {value_type}, {} bytes",
            data.len()
        );
    }
}

/// [`read_value`] driven by scripted answers: what it gave, how often it
/// measured the value, and the room it read the data into each time.
fn scripted(
    measured: Vec<Option<(u32, usize)>>,
    fetched: Vec<Fetch>,
) -> (Option<RegValue>, usize, Vec<usize>) {
    let measured = std::cell::RefCell::new(measured.into_iter());
    let fetched = std::cell::RefCell::new(fetched.into_iter());
    let measures = std::cell::Cell::new(0);
    let rooms = std::cell::RefCell::new(Vec::new());
    let value = read_value(
        || {
            measures.set(measures.get() + 1);
            measured
                .borrow_mut()
                .next()
                .expect("measured once too often")
        },
        |room| {
            rooms.borrow_mut().push(room);
            fetched.borrow_mut().next().expect("read once too often")
        },
    );
    (value, measures.get(), rooms.into_inner())
}

#[test]
fn a_value_that_grows_while_it_is_read_is_measured_and_read_again() {
    const SZ: u32 = 1;
    const DWORD: u32 = 4;
    let host = utf16("host.example\0");
    let size = host.len();
    let data = |value_type, data: &[u8]| Fetch::Data {
        value_type,
        data: data.to_vec(),
    };
    let grew = |size| Fetch::Grew { size };
    let over = MAX_STRING_BYTES + 2;
    for (what, measured, fetched, expected) in [
        (
            "read at once",
            vec![Some((SZ, size))],
            vec![data(SZ, &host)],
            (Some(s("host.example")), 1, vec![size]),
        ),
        (
            "grew once, then read at its new size",
            vec![Some((SZ, 4)), Some((SZ, size))],
            vec![grew(size), data(SZ, &host)],
            (Some(s("host.example")), 2, vec![4, size]),
        ),
        (
            "kept growing within the cap: absent after three attempts",
            vec![Some((SZ, 4)), Some((SZ, 6)), Some((SZ, 8))],
            vec![grew(6), grew(8), grew(10)],
            (None, 3, vec![4, 6, 8]),
        ),
        (
            "kept growing, last measured over the cap: too long",
            vec![Some((SZ, 4)), Some((SZ, 6)), Some((SZ, 8))],
            vec![grew(6), grew(8), grew(over)],
            (Some(RegValue::TooLong), 3, vec![4, 6, 8]),
        ),
        (
            "grew past the cap: measured again, not read",
            vec![Some((SZ, 4)), Some((SZ, over))],
            vec![grew(over)],
            (Some(RegValue::TooLong), 2, vec![4]),
        ),
        (
            "a number rewritten as a long string, again and again: absent",
            vec![Some((DWORD, 4)), Some((DWORD, 4)), Some((DWORD, 4))],
            vec![grew(over), grew(over), grew(over)],
            (None, 3, vec![4, 4, 4]),
        ),
        (
            "deleted in between: absent",
            vec![Some((SZ, 4)), None],
            vec![grew(6)],
            (None, 2, vec![4]),
        ),
        (
            "any other error: absent, not tried again",
            vec![Some((SZ, 4))],
            vec![Fetch::Failed],
            (None, 1, vec![4]),
        ),
        (
            "a number",
            vec![Some((DWORD, 4))],
            vec![data(DWORD, &[22, 0, 0, 0])],
            (Some(d(22)), 1, vec![4]),
        ),
        (
            "over the cap when measured: too long, never read",
            vec![Some((SZ, over))],
            vec![],
            (Some(RegValue::TooLong), 1, vec![]),
        ),
        (
            "empty: nothing to read",
            vec![Some((SZ, 0))],
            vec![],
            (Some(s("")), 1, vec![]),
        ),
        (
            "another type, or a DWORD of another size: never read",
            vec![Some((3, 4))],
            vec![],
            (None, 1, vec![]),
        ),
        (
            "a DWORD of 8 bytes",
            vec![Some((DWORD, 8))],
            vec![],
            (None, 1, vec![]),
        ),
        ("not there", vec![None], vec![], (None, 1, vec![])),
    ] {
        assert_eq!(scripted(measured, fetched), expected, "{what}");
    }
}

#[test]
fn a_skipped_name_is_shown_cut_to_256_characters() {
    let cut = format!("{}\u{2026}", "n".repeat(256));
    let long = convert(&ssh(&"n".repeat(300), "h", vec![])).unwrap_err();
    assert_eq!(long.reason, "name longer than 256 characters");
    assert_eq!(long.name, cut);
    // The control-character check comes first; the name is cut all the
    // same.
    let both = convert(&ssh(&format!("{}%0A", "n".repeat(300)), "h", vec![])).unwrap_err();
    assert_eq!(both.reason, "name contains a control character");
    assert_eq!(both.name, cut);
    // 256 characters are shown whole.
    let whole = "n".repeat(256);
    let telnet = raw(&whole, vec![("Protocol", s("telnet"))]);
    assert_eq!(convert(&telnet).unwrap_err().name, whole);
}

/// Unescaping only shortens a name PuTTY wrote (ASCII and `%XX`). A key
/// name holding characters other than ASCII as they are - not PuTTY's
/// doing - that is not UTF-8 once unescaped is read byte by byte in the
/// code page, longer than the key: so the skip for a long name can come
/// from a key Windows allows (256 characters at most).
#[cfg(not(windows))]
#[test]
fn a_name_can_come_out_longer_than_its_key() {
    let key = format!("{}%FF", "\u{e9}".repeat(200));
    assert_eq!(key.chars().count(), 203);
    assert_eq!(unescape_session_name(&key).chars().count(), 401);
    let skipped = convert(&ssh(&key, "h", vec![])).unwrap_err();
    assert_eq!(skipped.reason, "name longer than 256 characters");
    assert_eq!(skipped.name.chars().count(), 257);
}

#[test]
fn string_values_are_read_up_to_8_kib() {
    assert_eq!(MAX_STRING_BYTES, 8 * 1024);
}

#[test]
fn a_value_too_long_to_read_is_never_taken_as_absent() {
    let too_long = || RegValue::TooLong;
    let host_only = raw("s", vec![("HostName", too_long())]);
    assert_eq!(
        skip_reason(&host_only),
        "host name longer than 255 characters"
    );
    let user = ssh("s", "h", vec![("UserName", too_long())]);
    assert_eq!(skip_reason(&user), "user name longer than 256 characters");
    // Not used, so no matter: the user name comes from the host.
    let unused = ssh("s", "me@h", vec![("UserName", too_long())]);
    assert_eq!(convert(&unused).unwrap().username.as_deref(), Some("me"));
    let key_file = ssh("s", "h", vec![("PublicKeyFile", too_long())]);
    assert_eq!(
        skip_reason(&key_file),
        "key file path longer than 4,095 characters"
    );
    let protocol = raw("s", vec![("HostName", s("h")), ("Protocol", too_long())]);
    assert_eq!(skip_reason(&protocol), "not an SSH session");
    let forwardings = ssh("s", "h", vec![("PortForwardings", too_long())]);
    assert_eq!(convert(&forwardings).unwrap().notes, ["portForwarding"]);
    // A number given as a string is the wrong type, too long or not:
    // absent.
    for name in [
        "PortNumber",
        "UserNameFromEnvironment",
        "ProxyMethod",
        "AgentFwd",
        "X11Forward",
    ] {
        let session = convert(&ssh("s", "h", vec![(name, too_long())])).unwrap();
        assert_eq!(session.port, 22, "{name}");
        assert_eq!(session.username, None, "{name}");
        assert!(session.notes.is_empty(), "{name}");
    }
}

#[test]
fn key_file_paths_over_4095_characters_are_skipped() {
    let longest = "k".repeat(4095);
    let session = convert(&ssh("s", "h", vec![("PublicKeyFile", s(&longest))])).unwrap();
    assert_eq!(session.key_file, Some(longest));
    let over = ssh("s", "h", vec![("PublicKeyFile", s(&"k".repeat(4096)))]);
    assert_eq!(
        skip_reason(&over),
        "key file path longer than 4,095 characters"
    );
}

#[test]
fn user_names_over_256_characters_are_skipped() {
    let longest = "u".repeat(256);
    let over = "u".repeat(257);
    let from_host = convert(&ssh("s", &format!("{longest}@h"), vec![])).unwrap();
    assert_eq!(from_host.username, Some(longest.clone()));
    let from_env = vec![("UserNameFromEnvironment", d(1))];
    for (session, local) in [
        (ssh("s", &format!("{over}@h"), vec![]), None),
        (ssh("s", "h", vec![("UserName", s(&over))]), None),
        (ssh("s", "h", from_env.clone()), Some(over.as_str())),
    ] {
        let skipped = session_from_raw(&session, local).unwrap_err();
        assert_eq!(skipped.reason, "user name longer than 256 characters");
    }
    let at_limit = session_from_raw(&ssh("s", "h", from_env), Some(&longest)).unwrap();
    assert_eq!(at_limit.username, Some(longest));
    // A long user name that is not used does not matter.
    let unused = ssh("s", "me@h", vec![("UserName", s(&over))]);
    assert!(session_from_raw(&unused, Some(&over)).is_ok());
}

#[test]
fn a_session_that_could_not_be_read_is_skipped_with_why() {
    let denied = unreadable("locked", "Access is denied. (os error 5)");
    assert_eq!(
        skip_reason(&denied),
        "could not be read (Access is denied. (os error 5))"
    );
    // The name checks come first.
    assert_eq!(
        skip_reason(&unreadable("bad%0Aname", "gone")),
        "name contains a control character"
    );
    assert_eq!(
        skip_reason(&unreadable(&"n".repeat(257), "gone")),
        "name longer than 256 characters"
    );
    // Whatever the error says is shown without control characters.
    let odd = convert(&unreadable("odd", "line\r\nbreak")).unwrap_err();
    assert_eq!(odd.reason, "could not be read (line\u{FFFD}\u{FFFD}break)");
    // One entry each, the template still left out.
    let listing = build_listing(
        vec![
            unreadable("Default%20Settings", "gone"),
            unreadable("b", "gone"),
            ssh("a", "h", vec![]),
        ],
        &[],
        None,
    );
    assert_eq!(names(&listing), ["a"]);
    assert_eq!(
        listing.skipped,
        [SkippedSession {
            name: "b".into(),
            reason: "could not be read (gone)".into(),
        }]
    );
    // Each counts toward the thousand.
    let many: Vec<RawSession> = (0..=MAX_SESSIONS)
        .map(|i| unreadable(&format!("s{i:04}"), "denied"))
        .collect();
    let listing = build_listing(many, &[], None);
    assert_eq!(listing.skipped.len(), MAX_SESSIONS);
    assert!(listing.truncated);
}

#[test]
fn the_local_user_is_the_trimmed_user_name_when_there_is_one() {
    assert_eq!(
        local_user_from(Some(" andrei ".into())),
        Some("andrei".into())
    );
    assert_eq!(local_user_from(Some("  ".into())), None);
    assert_eq!(local_user_from(None), None);
}

/// The listing reports the key file as a string and never looks at it:
/// on Windows a path to a share would open a network connection, with an
/// NTLM sign-in. Nothing in the module's code - every file of it but the
/// tests', read in full - reaches the file system. A new file of the
/// module's code belongs in this list.
#[test]
fn the_listing_code_never_touches_the_file_system() {
    for (file, source) in [
        ("mod.rs", include_str!("mod.rs")),
        ("registry.rs", include_str!("registry.rs")),
    ] {
        for call in [
            "std::fs",
            "fs::",
            "File::",
            "metadata(",
            "Path::",
            "canonicalize",
        ] {
            assert!(!source.contains(call), "{call} in {file}");
        }
    }
}

// Names that are not UTF-8, decoded the way Windows decodes the ANSI code
// page older PuTTY wrote them in. (Windows only.)

/// "caf" and the bytes 0xE9 0xBA 0xFE, which are not UTF-8.
#[cfg(windows)]
const NOT_UTF8: &[u8] = b"caf\xE9\xBA\xFE";

/// Read in a code page byte by byte, a name with characters other than
/// ASCII as they are comes out longer than its key (see
/// `a_name_can_come_out_longer_than_its_key`, off Windows).
#[cfg(windows)]
#[test]
fn a_name_can_come_out_longer_than_its_key_in_a_code_page() {
    let bytes = ["\u{e9}".repeat(200).into_bytes(), vec![0xFF]].concat();
    let decoded = decode_code_page(&bytes, 1252).unwrap();
    assert_eq!(decoded.chars().count(), 401);
}

#[cfg(windows)]
#[test]
fn bytes_are_decoded_with_the_code_page_given() {
    for (code_page, expected) in [
        (1250, "caf\u{e9}\u{15f}\u{163}"),
        (1251, "caf\u{439}\u{454}\u{44e}"),
        (1252, "caf\u{e9}\u{ba}\u{fe}"),
    ] {
        assert_eq!(
            decode_code_page(NOT_UTF8, code_page).as_deref(),
            Some(expected),
            "code page {code_page}"
        );
        assert_eq!(
            decode_code_page(b"plain name", code_page).as_deref(),
            Some("plain name"),
            "code page {code_page}"
        );
    }
}

#[cfg(windows)]
#[test]
fn names_that_are_not_utf8_are_read_in_the_systems_ansi_code_page() {
    use windows_sys::Win32::Globalization::GetACP;
    assert_eq!(unescape_session_name("plain%20name"), "plain name");
    let name = unescape_session_name("caf%E9%BA%FE");
    // SAFETY: GetACP takes nothing and only returns a number.
    let code_page = unsafe { GetACP() };
    match code_page {
        1250 => assert_eq!(name, "caf\u{e9}\u{15f}\u{163}"),
        1251 => assert_eq!(name, "caf\u{439}\u{454}\u{44e}"),
        1252 => assert_eq!(name, "caf\u{e9}\u{ba}\u{fe}"),
        _ => assert!(
            name.starts_with("caf") && name.len() > 3,
            "{code_page}: {name:?}"
        ),
    }
}

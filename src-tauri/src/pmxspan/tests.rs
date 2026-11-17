//! Discovery with every input injected: no real PATH, home or registry.

use super::*;

struct Tree(PathBuf);
impl Tree {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("sshspan-pmx-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    /// An executable file at `rel` under the tree.
    fn exe(&self, rel: &str) -> PathBuf {
        let p = self.0.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, b"#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        p
    }
}
impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn unix_env(t: &Tree) -> DiscoveryEnv {
    DiscoveryEnv {
        path_var: None,
        home: Some(t.0.join("home")),
        windows: false,
        program_files: None,
        registry_dirs: Vec::new(),
        root: t.0.join("root"),
    }
}

#[test]
fn nothing_installed_finds_nothing() {
    let t = Tree::new();
    assert_eq!(discover(&unix_env(&t)), None);
    assert_eq!(route(None, None, &unix_env(&t), || false), Route::None);
    assert_eq!(route(None, None, &unix_env(&t), || true), Route::Scheme);
}

#[cfg(unix)]
#[test]
fn unix_order_is_path_then_fixed_locations() {
    let t = Tree::new();
    let mut env = unix_env(&t);
    let opt = t.exe("root/opt/PMXSpan/pmxspan");
    assert_eq!(discover(&env), Some(opt.clone()));
    let local = t.exe("home/.local/bin/pmxspan");
    assert_eq!(discover(&env), Some(local), "~/.local/bin before /opt");
    let usr = t.exe("root/usr/bin/pmxspan");
    assert_eq!(discover(&env), Some(usr.clone()));
    let on_path = t.exe("bin-on-path/pmxspan");
    env.path_var =
        Some(std::env::join_paths([t.0.join("empty"), t.0.join("bin-on-path")]).unwrap());
    assert_eq!(discover(&env), Some(on_path), "PATH first");
    // A file without an execute bit is not runnable.
    let t2 = Tree::new();
    let p = t2.0.join("root/usr/bin/pmxspan");
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, b"x").unwrap();
    assert_eq!(discover(&unix_env(&t2)), None);
}

#[cfg(unix)]
#[test]
fn appimages_in_home_applications_are_found() {
    let t = Tree::new();
    let img = t.exe("home/Applications/PMXSpan-0.7.0-x86_64.AppImage");
    t.exe("home/Applications/Other.AppImage");
    assert_eq!(discover(&unix_env(&t)), Some(img));
    let mac = Tree::new();
    let app = mac.exe("root/Applications/PMXSpan.app/Contents/MacOS/pmxspan");
    assert_eq!(discover(&unix_env(&mac)), Some(app));
}

#[test]
fn windows_order_is_registry_program_files_then_path() {
    let t = Tree::new();
    let env = DiscoveryEnv {
        path_var: Some(std::env::join_paths([t.0.join("pathdir")]).unwrap()),
        home: None,
        windows: true,
        program_files: Some(t.0.join("pf")),
        registry_dirs: vec![t.0.join("reg")],
        root: t.0.clone(),
    };
    let c = candidates(&env);
    assert_eq!(
        c,
        vec![
            t.0.join("reg").join("pmxspan.exe"),
            t.0.join("pf").join("PMXSpan").join("pmxspan.exe"),
            t.0.join("pathdir").join("pmxspan.exe"),
        ]
    );
    let on_path = t.exe("pathdir/pmxspan.exe");
    assert_eq!(discover(&env), Some(on_path));
    let pf = t.exe("pf/PMXSpan/pmxspan.exe");
    assert_eq!(discover(&env), Some(pf));
    let reg = t.exe("reg/pmxspan.exe");
    assert_eq!(discover(&env), Some(reg));
}

#[test]
fn a_user_path_is_validated_and_wins() {
    let t = Tree::new();
    let exe = t.exe("custom/pmxspan-bin");
    let env = unix_env(&t);
    t.exe("root/usr/bin/pmxspan");
    let s = exe.display().to_string();
    if cfg!(unix) {
        assert_eq!(
            route(Some(&s), None, &env, || false),
            Route::UserPath(exe.clone())
        );
    }
    assert!(validate_user_path(Path::new("relative/pmxspan"), false)
        .unwrap_err()
        .contains("absolute"));
    assert!(validate_user_path(&t.0.join("missing"), false)
        .unwrap_err()
        .contains("Nothing exists"));
    assert!(validate_user_path(&t.0, false)
        .unwrap_err()
        .contains("not a regular file"));
    assert!(validate_user_path(&exe, true).unwrap_err().contains(".exe"));
    // A stored path that no longer validates falls back to discovery,
    // which asks before the first launch.
    let gone = t.0.join("gone").display().to_string();
    match route(Some(&gone), None, &env, || false) {
        Route::Discovered { approved, .. } => assert!(!approved),
        other => panic!("{other:?}"),
    }
}

#[test]
fn an_approved_path_is_remembered_and_a_changed_one_asks_again() {
    let t = Tree::new();
    let env = unix_env(&t);
    if cfg!(not(unix)) {
        return;
    }
    let usr = t.exe("root/usr/bin/pmxspan");
    let approved = usr.display().to_string();
    assert_eq!(
        route(None, Some(&approved), &env, || false),
        Route::Discovered {
            path: usr.clone(),
            approved: true
        }
    );
    let other = t.0.join("root/usr/local/bin/pmxspan").display().to_string();
    assert_eq!(
        route(None, Some(&other), &env, || false),
        Route::Discovered {
            path: usr,
            approved: false
        }
    );
}

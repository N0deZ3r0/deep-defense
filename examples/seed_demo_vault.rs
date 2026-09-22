//! Creates a throwaway vault with sample entries, for screenshots and for
//! trying the interface without inventing data by hand.
//!
//! Not part of the shipped program — `examples/` is excluded from the binary.
//!
//! ```text
//! cargo run --example seed_demo_vault -- <vault path> <master password>
//! ```
//!
//! The passwords below are deliberately a mixed bag — strong, weak, reused and
//! stale — so the password-health report has something to find.

use std::path::PathBuf;

use deep_defense::config::Config;
use deep_defense::crypto::KdfParams;
use deep_defense::model::Entry;
use deep_defense::secret::Secret;
use deep_defense::session;
use deep_defense::veracrypt::VeraCrypt;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let path = PathBuf::from(
        args.next()
            .ok_or("usage: seed_demo_vault <vault path> <master password>")?,
    );
    let password = Secret::from_string(
        args.next()
            .ok_or("usage: seed_demo_vault <vault path> <master password>")?,
    );

    if path.exists() {
        std::fs::remove_file(&path)?;
    }

    let config = Config {
        use_container: false,
        vault_path: path.clone(),
        // Light parameters: this is a demo vault, not a real one, and the
        // point is to get to the screen quickly.
        kdf: KdfParams {
            m_cost: KdfParams::MIN_M_COST,
            t_cost: 2,
            p_cost: 1,
            algorithm: "argon2id".into(),
        },
        ..Config::default()
    };

    let mut open = session::create_vault(&VeraCrypt::discover(), &config, &password, 0)?;

    for (name, user, secret, url, tags, totp) in samples() {
        let mut entry = Entry::new(name);
        entry.username = user.into();
        entry.url = url.into();
        entry.tags = tags.iter().map(|t| (*t).to_string()).collect();
        entry.totp_secret = totp.into();
        entry.set_password(secret.into());
        open.vault.add(entry)?;
    }
    open.vault.save()?;

    println!("seeded {} entries into {}", open.vault.data.entries.len(), path.display());
    Ok(())
}

type Sample = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static [&'static str],
    &'static str,
);

fn samples() -> Vec<Sample> {
    vec![
        (
            "GitHub",
            "me@example.com",
            "F7#qL2vTm9!xZr4KpW8s",
            "https://github.com",
            &["work", "dev"],
            "JBSWY3DPEHPK3PXP",
        ),
        (
            "Bank",
            "1234 5678 9012",
            "Vh2$nQ8pLz6!WdR3xYt7",
            "https://bank.example",
            &["finance", "critical"],
            "",
        ),
        (
            "Mail",
            "me@example.com",
            "qwerty123",
            "https://mail.example",
            &["personal"],
            "",
        ),
        (
            "Router",
            "admin",
            "admin",
            "http://192.168.1.1",
            &["home"],
            "",
        ),
        (
            "Cloud storage",
            "me@example.com",
            "Vh2$nQ8pLz6!WdR3xYt7",
            "https://cloud.example",
            &["personal"],
            "",
        ),
        (
            "Work VPN",
            "a.ivanov",
            "Kx9&mR4tN7#pQz2BvL5c",
            "https://vpn.example",
            &["work"],
            "",
        ),
        (
            "Forum",
            "nickname",
            "Sunshine2019",
            "https://forum.example",
            &["personal"],
            "",
        ),
    ]
}

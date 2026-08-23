//! Renders a ledger from the real code paths so the format can be read as a
//! whole, rather than only asserted on piece by piece.

use pinnacle_cypat::{remediation, run_log};

#[tokio::test]
async fn ledger_sample_output() {
    run_log::clear();

    run_log::in_task("Security Hardening", async {
        // A value that was wrong and is now right.
        let reads = std::cell::Cell::new(0);
        let _ = remediation::apply(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA",
            "REG_DWORD = 1 (Enable UAC)",
            || {
                reads.set(reads.get() + 1);
                let first = reads.get() == 1;
                async move { Some(if first { "0" } else { "1" }.to_string()) }
            },
            |s| s == "1",
            "wrote REG_DWORD 1",
            || async { Ok(()) },
        )
        .await;

        // A write that claims success and does not land.
        let _ = remediation::apply(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL",
            "REG_DWORD = 1 (Enable LSA protection)",
            || async { Some("0".to_string()) },
            |s| s == "1",
            "wrote REG_DWORD 1",
            || async { Ok(()) },
        )
        .await;

        // Already correct - nothing written.
        let _ = remediation::apply(
            "Service TlntSvr",
            "start type disabled, so it cannot return after a reboot",
            || async { Some("disabled".to_string()) },
            |s| s == "disabled",
            "set the start type to disabled",
            || async { Ok(()) },
        )
        .await;
    })
    .await;

    run_log::in_task("User Management", async {
        let _ = remediation::apply(
            "Account hacker",
            "deleted (not in the README's authorised list)",
            || async { Some("present".to_string()) },
            |s| s == "absent",
            "deleted the account",
            || async { Err("Access is denied".to_string()) },
        )
        .await;

        let _ = remediation::apply_unprovable(
            "Account jsmith",
            "a strong password that is not the competition default",
            "wrote a new password into the account database",
            "Windows will not read a password back, so the status code the account \
             database returned is the strongest evidence there is",
            || async { Ok(()) },
        )
        .await;

        remediation::record_skipped(
            "Account CyberPatriot",
            "left alone",
            "the README names it as the auto-login user",
        );
    })
    .await;

    run_log::append_ledger();
    let log = run_log::entries().join("\n");
    println!("{log}");

    // Each outcome the ledger can reach, driven through the real `apply`.
    for expected in [
        "[FIXED] HKLM\\SOFTWARE",
        "[UNVERIFIED] HKLM\\SYSTEM",
        "[ALREADY OK] Service TlntSvr",
        "[FAILED] Account hacker",
        "[SKIPPED] Account CyberPatriot",
    ] {
        assert!(log.contains(expected), "missing {expected} in:\n{log}");
    }

    // Grouped under the task that made the change, which for the concurrent
    // audits depends on the attribution being task-local rather than global.
    // Positions are taken within the ledger only: each fix is also mirrored into
    // the narrative above it, and those copies come first.
    let ledger = &log[log.find("REMEDIATION LEDGER").expect("ledger")..];
    let hardening = ledger.find("--- Security Hardening ---").expect("group");
    let users = ledger.find("--- User Management ---").expect("group");
    assert!(hardening < users, "groups out of order:\n{ledger}");
    assert!(
        ledger.find("[FAILED] Account hacker").unwrap() > users,
        "the account change was filed under the wrong task:\n{ledger}"
    );

    // A change that never read the state must not claim it tried and failed.
    assert!(log.contains("Before: (not read)"), "{log}");

    assert!(
        log.contains("Totals: 1 fixed, 1 already compliant, 1 failed, 2 unverified, 1 skipped"),
        "{log}"
    );

    run_log::clear();
}

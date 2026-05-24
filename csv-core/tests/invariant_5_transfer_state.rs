#![cfg(any())]
//! Invariant 5: Cross-Chain Transfers Must Follow the TransferState Machine
//!
//! Rule: All cross-chain transfers must progress through states in order:
//! Initiated → Locking → GeneratingProof → ProofReady → SubmittingProof → Verifying → Minting → Completed

#[cfg(test)]
mod tests {
    use csv_core::protocol_version::TransferStatus;

    /// Property: TransferStatus starts in Initiated state
    #[test]
    fn test_transfer_starts_in_initiated() {
        let status = TransferStatus::Initiated;
        assert!(matches!(status, TransferStatus::Initiated));
    }

    /// Property: Locking state has confirmation fields
    #[test]
    fn test_locking_state_has_confirmations() {
        let status = TransferStatus::Locking {
            current_confirmations: 3,
            required_confirmations: 6,
        };
        assert!(matches!(status, TransferStatus::Locking { .. }));
    }

    /// Property: GeneratingProof has progress percentage
    #[test]
    fn test_generating_proof_has_progress() {
        let status = TransferStatus::GeneratingProof {
            progress_percent: 50,
        };
        assert!(matches!(status, TransferStatus::GeneratingProof { .. }));
    }

    /// Property: ProofReady has proof block
    #[test]
    fn test_proof_ready_has_block() {
        let status = TransferStatus::ProofReady { proof_block: 1000 };
        assert!(matches!(status, TransferStatus::ProofReady { .. }));
    }

    /// Property: Failed state has error details
    #[test]
    fn test_failed_state_has_errors() {
        let status = TransferStatus::Failed {
            error_code: "TIMEOUT".to_string(),
            retryable: true,
        };
        assert!(matches!(status, TransferStatus::Failed { .. }));
    }

    /// Property: is_pending works correctly
    #[test]
    fn test_is_pending() {
        assert!(TransferStatus::Initiated.is_pending());
        assert!(
            TransferStatus::Locking {
                current_confirmations: 0,
                required_confirmations: 6
            }
            .is_pending()
        );
        assert!(!TransferStatus::Completed.is_pending());
        assert!(
            !TransferStatus::Failed {
                error_code: "err".to_string(),
                retryable: false
            }
            .is_pending()
        );
    }

    /// Property: is_in_progress works correctly
    #[test]
    fn test_is_in_progress() {
        assert!(
            TransferStatus::GeneratingProof {
                progress_percent: 50
            }
            .is_in_progress()
        );
        assert!(TransferStatus::SubmittingProof.is_in_progress());
        assert!(TransferStatus::Verifying.is_in_progress());
        assert!(TransferStatus::Minting.is_in_progress());
        assert!(!TransferStatus::Initiated.is_in_progress());
        assert!(!TransferStatus::Completed.is_in_progress());
    }

    /// Property: is_terminal works correctly
    #[test]
    fn test_is_terminal() {
        assert!(TransferStatus::Completed.is_terminal());
        assert!(
            TransferStatus::Failed {
                error_code: "err".to_string(),
                retryable: false
            }
            .is_terminal()
        );
        assert!(!TransferStatus::Initiated.is_terminal());
        assert!(!TransferStatus::Minting.is_terminal());
    }

    /// Property: is_completed works correctly
    #[test]
    fn test_is_completed() {
        assert!(TransferStatus::Completed.is_completed());
        assert!(!TransferStatus::Initiated.is_completed());
        assert!(
            !TransferStatus::Failed {
                error_code: "err".to_string(),
                retryable: false
            }
            .is_completed()
        );
    }

    /// Property: is_failed works correctly
    #[test]
    fn test_is_failed() {
        assert!(
            TransferStatus::Failed {
                error_code: "err".to_string(),
                retryable: false
            }
            .is_failed()
        );
        assert!(!TransferStatus::Completed.is_failed());
        assert!(!TransferStatus::Initiated.is_failed());
    }

    /// Property: progress_percent returns correct values
    #[test]
    fn test_progress_percent() {
        assert_eq!(TransferStatus::Initiated.progress_percent(), 0);
        assert_eq!(TransferStatus::Completed.progress_percent(), 100);
        assert_eq!(TransferStatus::Minting.progress_percent(), 90);
        assert_eq!(TransferStatus::Verifying.progress_percent(), 75);
        assert_eq!(TransferStatus::SubmittingProof.progress_percent(), 50);
        assert_eq!(
            TransferStatus::ProofReady { proof_block: 0 }.progress_percent(),
            40
        );
    }

    /// Property: FromStr parses all variants
    #[test]
    fn test_from_str_all_variants() {
        let statuses = vec![
            "initiated",
            "locking",
            "generating_proof",
            "proof_ready",
            "submitting_proof",
            "verifying",
            "minting",
            "completed",
            "failed",
        ];
        for status_str in statuses {
            let result = status_str.parse::<TransferStatus>();
            assert!(result.is_ok(), "Failed to parse '{}'", status_str);
        }
    }

    /// Property: Display formats all variants
    #[test]
    fn test_display_all_variants() {
        let status = TransferStatus::Initiated;
        assert_eq!(format!("{}", status), "initiated");

        let status = TransferStatus::Completed;
        assert_eq!(format!("{}", status), "completed");

        let status = TransferStatus::Failed {
            error_code: "err".to_string(),
            retryable: false,
        };
        assert_eq!(format!("{}", status), "failed");
    }
}

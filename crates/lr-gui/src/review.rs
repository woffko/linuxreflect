//! Restore review state, independent of widgets and the async runtime.

use std::sync::Arc;

/// A request retains its generation while an RPC is in flight.
pub(crate) struct Request {
    generation: Arc<()>,
    image: String,
    target: String,
    passphrase_file: String,
}

struct Prepared {
    image: String,
    target: String,
    token: String,
    passphrase_file: String,
}

/// The token and credential path belong to the same reviewed operation.
pub(crate) struct Approved {
    pub(crate) token: String,
    pub(crate) passphrase_file: String,
}

/// Only a current review and explicit confirmation can yield an apply token.
pub(crate) struct Review {
    generation: Arc<()>,
    prepared: Option<Prepared>,
}

impl Default for Review {
    fn default() -> Self {
        Self {
            generation: Arc::new(()),
            prepared: None,
        }
    }
}

impl Review {
    pub(crate) fn invalidate(&mut self) {
        self.generation = Arc::new(());
        self.prepared = None;
    }

    pub(crate) fn begin(
        &mut self,
        image: String,
        target: String,
        passphrase_file: String,
    ) -> Request {
        self.invalidate();
        Request {
            generation: Arc::clone(&self.generation),
            image,
            target,
            passphrase_file,
        }
    }

    pub(crate) fn accept(&mut self, request: Request, token: String) -> bool {
        if !Arc::ptr_eq(&self.generation, &request.generation) || token.is_empty() {
            return false;
        }
        self.prepared = Some(Prepared {
            image: request.image,
            target: request.target,
            token,
            passphrase_file: request.passphrase_file,
        });
        true
    }

    pub(crate) fn take_confirmed(
        &mut self,
        image: &str,
        target: &str,
        passphrase_file: &str,
        confirmed: bool,
    ) -> Option<Approved> {
        let prepared = self.prepared.as_ref()?;
        if prepared.image != image
            || prepared.target != target
            || prepared.passphrase_file != passphrase_file
        {
            self.invalidate();
            return None;
        }
        if !confirmed {
            return None;
        }
        self.prepared.take().map(|prepared| Approved {
            token: prepared.token,
            passphrase_file: prepared.passphrase_file,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Review;

    #[test]
    fn editing_and_reverting_rejects_a_delayed_response() {
        let mut review = Review::default();
        let old = review.begin("backup".into(), "disk-a".into(), String::new());
        review.invalidate(); // Choose disk-b.
        review.invalidate(); // Choose disk-a again.
        assert!(!review.accept(old, "obsolete".into()));
        assert!(
            review
                .take_confirmed("backup", "disk-a", "", true)
                .is_none()
        );
    }

    #[test]
    fn confirmation_is_required_and_a_token_is_consumed_once() {
        let mut review = Review::default();
        let request = review.begin("backup".into(), "disk-a".into(), String::new());
        assert!(review.accept(request, "token".into()));
        assert!(
            review
                .take_confirmed("backup", "disk-a", "", false)
                .is_none()
        );
        assert_eq!(
            review
                .take_confirmed("backup", "disk-a", "", true)
                .map(|approved| approved.token)
                .as_deref(),
            Some("token")
        );
        assert!(
            review
                .take_confirmed("backup", "disk-a", "", true)
                .is_none()
        );
    }

    #[test]
    fn changed_target_cannot_reuse_a_prepared_token() {
        let mut review = Review::default();
        let request = review.begin("backup".into(), "disk-a".into(), String::new());
        assert!(review.accept(request, "token".into()));
        assert!(
            review
                .take_confirmed("backup", "disk-b", "", true)
                .is_none()
        );
        assert!(
            review
                .take_confirmed("backup", "disk-a", "", true)
                .is_none()
        );
    }

    #[test]
    fn newer_request_supersedes_an_in_flight_review() {
        let mut review = Review::default();
        let first = review.begin("old".into(), "disk-a".into(), String::new());
        let second = review.begin("new".into(), "disk-a".into(), String::new());
        assert!(!review.accept(first, "old-token".into()));
        assert!(review.accept(second, "new-token".into()));
        assert_eq!(
            review
                .take_confirmed("new", "disk-a", "", true)
                .map(|approved| approved.token)
                .as_deref(),
            Some("new-token")
        );
    }

    #[test]
    fn credentials_are_bound_to_the_reviewed_operation() {
        let mut review = Review::default();
        let first = review.begin("backup".into(), "disk".into(), "key-a".into());
        assert!(review.accept(first, "token".into()));
        assert!(
            review
                .take_confirmed("backup", "disk", "key-b", true)
                .is_none()
        );
        let second = review.begin("backup".into(), "disk".into(), "key-b".into());
        assert!(review.accept(second, "new-token".into()));
        let approved = review
            .take_confirmed("backup", "disk", "key-b", true)
            .unwrap();
        assert_eq!(approved.passphrase_file, "key-b");
        assert_eq!(approved.token, "new-token");
    }
}

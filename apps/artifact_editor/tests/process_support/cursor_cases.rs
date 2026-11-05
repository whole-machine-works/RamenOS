//! Cursor/selection/scroll comparison against a separately approved legacy Host.
//! Each Host keeps its unchanged composition quota; every corpus step still
//! composes both genuine frames and compares the complete application crop.
use super::*;

pub(super) struct ReferenceFixture {
    parents: Option<ParentOwners<(Fixture, Option<artifact_editor::NativeArtifactEditor>)>>,
}

impl ReferenceFixture {
    pub(super) fn new(body: &[u8]) -> Self {
        // Stage the durable fixture before approval, Read, or editor opening
        // can fail. ParentOwners quarantines the actual group on unwind.
        let fixture = fixture::fixture_with_contents("d09_cursor_reference", &[body]);
        let mut reference = Self {
            parents: Some(ParentOwners::new((fixture, None))),
        };
        let parents = reference.parents.as_mut().unwrap().borrow();
        parents.1 = Some(parents.0.app(0, 101, 1));
        assert_eq!(ok(parents.1.as_ref().unwrap().observe(1)).bytes, body);
        assert_eq!(parents.0.counts(101), (0, 0, 0));
        reference
    }

    fn parts(&mut self) -> (&mut Fixture, &mut artifact_editor::NativeArtifactEditor) {
        let (fixture, editor) = self.parents.as_mut().unwrap().borrow();
        (fixture, editor.as_mut().unwrap())
    }

    pub(super) fn drive(&mut self, group: &mut ChildGroup, index: usize) {
        {
            let (reference, _) = self.parts();
            let process = group.fixture();
            assert_ne!(reference.path, process.path);
            assert!(
                !std::sync::Arc::ptr_eq(&reference.dc, &process.dc),
                "reference has its own genuine Host and composition budget"
            );
        }
        let mut corpus = vec![74, 79, 225, 79, 79, 225, 42, 77, 82, 74];
        corpus.extend(std::iter::repeat_n(81, 50));
        corpus.extend([77, 225, 80, 80, 225, 4]);
        let mut shift_down = false;
        let mut saw_selection = false;
        let mut saw_scroll = false;
        for usage in corpus {
            let events: Vec<(u32, u32)> = if usage == 225 {
                shift_down = !shift_down;
                vec![(225, if shift_down { 1 } else { 2 })]
            } else {
                vec![(usage, 1), (usage, 2)]
            };
            for (usage, phase) in events {
                ok(deliver(group, index, 0, usage, phase, 2));
                let (fixture, reference) = self.parts();
                fixture.drivers[0].send(&fixture.h, usage, phase, 2);
                ok(reference.step(2));
            }
            // This is the same genuine request/publication acceptance. Its
            // automatic composition alone is omitted: the explicit process
            // composition and independent reference composition below remain.
            ok(request_without_compose(group, index, 2));
            let (reference_fixture, reference) = self.parts();
            ok(reference.render(2));
            let (process_fixture, child) = group.borrow(index);
            let actual = ok(process_fixture.h.observe_process_editor(child, 2));
            let expected = ok(reference.observe(2));
            assert_eq!(actual.bytes, expected.bytes);
            assert_eq!(actual.cursor, expected.cursor);
            assert_eq!(actual.selection, expected.selection);
            assert_eq!(actual.first_visible_line, expected.first_visible_line);
            assert_eq!(actual.text_generation, expected.text_generation);
            assert_eq!(actual.view_version, expected.view_version);
            let process_frame = ok(process_fixture.compose(0, 2));
            let reference_frame = ok(reference_fixture.compose(0, 2));
            assert_eq!(
                volatile::hash(&process_frame.bgra[48 * 2560..528 * 2560]),
                volatile::hash(&reference_frame.bgra[48 * 2560..528 * 2560])
            );
            saw_selection |= actual.selection.is_some();
            saw_scroll |= actual.first_visible_line > 0;
        }
        assert!(!shift_down);
        assert!(
            saw_selection && saw_scroll,
            "corpus must actually select and scroll"
        );
        assert_eq!(group.fixture().counts(101), (0, 0, 0));
        assert_eq!(self.parts().0.counts(101), (0, 0, 0));
    }

    pub(super) fn finish(mut self) {
        let mut parents = self.parents.take().unwrap();
        let end = parents.begin_cleanup().0;
        let (fixture, editor) = parents.borrow();
        assert_eq!(fixture.counts(101), (0, 0, 0));
        // This reference never creates a Linux child or admits a Save. Keep
        // its app/root/Store group until its genuine Read producers are joined.
        loop {
            fixture.join_all();
            if fixture.h.native_producer_counts().held == 0 {
                break;
            }
            assert!(Instant::now() < end, "original reference cleanup budget");
            std::thread::yield_now();
        }
        drop(editor.take());
        let (fixture, editor) = parents.release_after_join();
        assert!(editor.is_none());
        // The unchanged fixture owns the actual Store quiescence fence,
        // complete producer/IO checks, recording transfer and durable cleanup.
        fixture.finish();
    }
}

//! Cursor/selection/scroll comparison against a separately approved legacy Host.
//! Each Host keeps its unchanged composition quota; every corpus step still
//! composes both genuine frames and compares the complete application crop.
use super::*;

pub(super) struct ReferenceFixture {
    parents: Option<ParentOwners<(Fixture, Option<artifact_editor::NativeArtifactEditor>)>>,
    phases: recording::PhaseTimingLog,
    process_recording: recording::PhaseTimingLog,
    reference_recording: recording::PhaseTimingLog,
    completed_steps: usize,
}

impl ReferenceFixture {
    pub(super) fn new(body: &[u8]) -> Self {
        // Stage the durable fixture before approval, Read, or editor opening
        // can fail. ParentOwners quarantines the actual group on unwind.
        let fixture = fixture::fixture_with_contents("d09_cursor_reference", &[body]);
        let mut reference = Self {
            parents: Some(ParentOwners::new((fixture, None))),
            phases: recording::PhaseTimingLog::new([
                "reference_render",
                "process_compose_including_recording",
                "reference_compose_including_recording",
            ]),
            process_recording: recording::PhaseTimingLog::new([
                "inventory_scan",
                "raw_write_hash_and_identity_checks",
                "crop_hash_and_frame_row",
            ]),
            reference_recording: recording::PhaseTimingLog::new([
                "inventory_scan",
                "raw_write_hash_and_identity_checks",
                "crop_hash_and_frame_row",
            ]),
            completed_steps: 0,
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
        // Buffers were allocated before child admission. Only this corpus opts
        // into timing; the two already-rendered initial frames stay unchanged.
        group.fixture().record(|recorder| {
            recorder.enable_frame_timings(self.process_recording.clone());
            Ok(())
        });
        let reference_recording = self.reference_recording.clone();
        self.parts().0.record(|recorder| {
            recorder.enable_frame_timings(reference_recording);
            Ok(())
        });
        let phases = self.phases.clone();
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
            let render_timing = phases.start(0);
            ok(reference.render(2));
            if let Some(timer) = render_timing {
                timer.complete();
            }
            let (process_fixture, child) = group.borrow(index);
            let actual = ok(process_fixture.h.observe_process_editor(child, 2));
            let expected = ok(reference.observe(2));
            assert_eq!(actual.bytes, expected.bytes);
            assert_eq!(actual.cursor, expected.cursor);
            assert_eq!(actual.selection, expected.selection);
            assert_eq!(actual.first_visible_line, expected.first_visible_line);
            assert_eq!(actual.text_generation, expected.text_generation);
            assert_eq!(actual.view_version, expected.view_version);
            let process_timing = phases.start(1);
            let process_frame = ok(process_fixture.compose(0, 2));
            if let Some(timer) = process_timing {
                timer.complete();
            }
            let reference_timing = phases.start(2);
            let reference_frame = ok(reference_fixture.compose(0, 2));
            if let Some(timer) = reference_timing {
                timer.complete();
            }
            // Both actual full frames and their crop hashes are already
            // retained by compose's recorder. Compare every application byte
            // directly here rather than hashing the same two crops again.
            assert!(
                process_frame.bgra[48 * 2560..528 * 2560]
                    == reference_frame.bgra[48 * 2560..528 * 2560],
                "exact full application pixels differ for usage {usage}"
            );
            saw_selection |= actual.selection.is_some();
            saw_scroll |= actual.first_visible_line > 0;
            self.completed_steps += 1;
        }
        assert!(!shift_down);
        assert!(
            saw_selection && saw_scroll,
            "corpus must actually select and scroll"
        );
        assert_eq!(group.fixture().counts(101), (0, 0, 0));
        assert_eq!(self.parts().0.counts(101), (0, 0, 0));
    }

    // Called only after the original ChildGroup cleanup returned authentic
    // exit proofs. This is diagnostic data, never a successful scenario receipt.
    pub(super) fn emit_phase_timings(&self, proofs: &[desktop::OwnedEditorChildExitProof]) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let owners: Vec<_> = proofs
                .iter()
                .map(|proof| {
                    serde_json::json!({
                        "process_id": proof.process_id(), "birth_ticks": proof.birth_ticks(),
                        "supervisor_joined": proof.supervisor_joined(),
                        "wait_outcome": format!("{:?}", proof.wait_outcome()),
                    })
                })
                .collect();
            let report = serde_json::json!({
                "schema_version": 1, "acceptance": false,
                "scope": "D09 diagnostic phases after actual child cleanup; not qualification",
                "coverage": "66 corpus steps; initial process/reference frames are not timed",
                "completed_corpus_steps": self.completed_steps,
                "timing": "monotonic wall time includes observer overhead; nested recorder phases are not additive with compose totals",
                "owners": owners, "outer": self.phases.observation(),
                "process_recording": self.process_recording.observation(),
                "reference_recording": self.reference_recording.observation(),
            });
            let mut bytes = b"D09_PHASE_TIMINGS ".to_vec();
            if serde_json::to_writer(&mut bytes, &report).is_ok() {
                bytes.push(b'\n');
                let _ = std::io::Write::write_all(&mut std::io::stderr().lock(), &bytes);
            }
        }));
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

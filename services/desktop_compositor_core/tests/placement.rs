use desktop_compositor_core::{PlacementError, place_app};

// Independent profile coordinates, not derived from implementation constants.
const ROW_BYTES: usize = 640 * 4;
const OUTPUT_BYTES: usize = 640 * 568 * 4;
const APP_BYTES: usize = 640 * 480 * 4;
const APP_START: usize = 48 * ROW_BYTES;
const APP_END: usize = 528 * ROW_BYTES;

fn fixture() -> Vec<u8> {
    let mut source = vec![0; APP_BYTES];
    for &(x, y, pixel) in &[
        (0, 0, [1, 2, 3, 4]),
        (639, 0, [5, 6, 7, 8]),
        (0, 1, [9, 10, 11, 12]),
        (321, 207, [13, 14, 15, 16]),
        (0, 479, [17, 18, 19, 20]),
        (639, 479, [21, 22, 23, 24]),
    ] {
        let start = (y * 640 + x) * 4;
        source[start..start + 4].copy_from_slice(&pixel);
    }
    source
}

#[test]
fn exact_frame_placement_keeps_chrome_and_all_alpha_bytes() {
    let source = fixture();
    let original = source.clone();
    let mut destination = vec![0x5a; OUTPUT_BYTES];
    place_app(Some(&source), &mut destination).unwrap();
    assert!(destination[..APP_START].iter().all(|v| *v == 0x5a));
    assert!(destination[APP_END..].iter().all(|v| *v == 0x5a));
    assert_eq!(&destination[APP_START..APP_END], source.as_slice());
    for &(x, y, pixel) in &[
        (0, 0, [1, 2, 3, 4]),
        (639, 0, [5, 6, 7, 8]),
        (0, 1, [9, 10, 11, 12]),
        (321, 207, [13, 14, 15, 16]),
        (0, 479, [17, 18, 19, 20]),
        (639, 479, [21, 22, 23, 24]),
    ] {
        let i = (y + 48) * ROW_BYTES + x * 4;
        assert_eq!(&destination[i..i + 4], &pixel);
    }
    assert_eq!(source, original);
}

#[test]
fn absent_source_whitens_only_app_region() {
    let mut destination = vec![0x63; OUTPUT_BYTES];
    place_app(None, &mut destination).unwrap();
    assert!(destination[..APP_START].iter().all(|v| *v == 0x63));
    assert!(destination[APP_START..APP_END].iter().all(|v| *v == 0xff));
    assert!(destination[APP_END..].iter().all(|v| *v == 0x63));
}

#[test]
fn malformed_inputs_deny_without_any_write_then_fresh_valid_succeeds() {
    let source = fixture();
    for size in [OUTPUT_BYTES - 1, OUTPUT_BYTES + 1] {
        let mut destination = vec![0xa5; size];
        let before = destination.clone();
        assert_eq!(
            place_app(Some(&source), &mut destination),
            Err(PlacementError::DestinationLength)
        );
        assert_eq!(destination, before);
        assert_eq!(
            place_app(None, &mut destination),
            Err(PlacementError::DestinationLength)
        );
        assert_eq!(destination, before);
    }
    for size in [APP_BYTES - 1, APP_BYTES + 1] {
        let wrong_source = vec![0x39; size];
        let mut destination = vec![0xa5; OUTPUT_BYTES];
        let before = destination.clone();
        assert_eq!(
            place_app(Some(&wrong_source), &mut destination),
            Err(PlacementError::SourceLength)
        );
        assert_eq!(destination, before);
        place_app(Some(&source), &mut destination).unwrap();
        assert_eq!(&destination[APP_START..APP_END], source.as_slice());
    }
    let mut wrong_destination = vec![0xa5; OUTPUT_BYTES - 1];
    let before = wrong_destination.clone();
    assert_eq!(
        place_app(Some(&source[..source.len() - 1]), &mut wrong_destination),
        Err(PlacementError::DestinationLength)
    );
    assert_eq!(wrong_destination, before);
    let mut fresh = vec![0xa5; OUTPUT_BYTES];
    place_app(None, &mut fresh).unwrap();
    assert!(fresh[APP_START..APP_END].iter().all(|v| *v == 0xff));
    assert!(fresh[..APP_START].iter().all(|v| *v == 0xa5));
    assert!(fresh[APP_END..].iter().all(|v| *v == 0xa5));
}

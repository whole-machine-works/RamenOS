use desktop_editor_core::{
    EditorModel, FRAME_BYTES, InitialView,
    process_data::{
        DataError, FONT_BYTES, TextHeader, TextState, decode_text64, encode_text64, frozen_font,
        sha256,
    },
};

fn hex(input: &str) -> Vec<u8> {
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn state(body: &[u8]) -> TextState {
    TextState {
        header: TextHeader::new(0x0102_0304_0506_0708, 0x1112_1314_1516_1718, body).unwrap(),
        cursor: body.len() as u32,
        selection: None,
        first_visible_line: 0,
        text_generation: 1,
        view_generation: 1,
        surface_sha256: [7; 32],
    }
}

#[test]
fn process_data_text64_literal_layout_and_borrowed_body() {
    let bytes = encode_text64(0x0102_0304_0506_0708, 0x1112_1314_1516_1718, b"abc").unwrap();
    let expected = hex(concat!(
        "010000004300000008070605040302011817161514131211",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "0300000000000000616263"
    ));
    assert_eq!(bytes, expected);
    let (header, body) = decode_text64(&bytes).unwrap();
    assert_eq!(header.selected_object_id, 0x0102_0304_0506_0708);
    assert_eq!(header.revision, 0x1112_1314_1516_1718);
    assert_eq!(body, b"abc");
    assert_eq!(body.as_ptr(), bytes[64..].as_ptr());
    assert_eq!(header.encode().unwrap().as_slice(), &bytes[..64]);
}

#[test]
fn process_data_text64_refuses_malformed_shape_identity_ascii_and_hash() {
    let valid = encode_text64(1, 1, b"abc").unwrap();
    for (offset, byte, error) in [
        (0, 2, DataError::Version),
        (60, 1, DataError::Reserved),
        (4, 68, DataError::Length),
        (8, 0, DataError::Identity),
        (16, 0, DataError::Identity),
        (56, 4, DataError::Length),
        (64, b'b', DataError::Hash),
        (64, 0x80, DataError::Ascii),
    ] {
        let mut broken = valid.clone();
        broken[offset] = byte;
        assert_eq!(decode_text64(&broken), Err(error));
    }
    for bytes in [&valid[..63], &[0; 4161][..]] {
        assert_eq!(decode_text64(bytes), Err(DataError::Length));
    }
    assert_eq!(encode_text64(1, 1, &[b'a'; 4097]), Err(DataError::Length));
    assert_eq!(encode_text64(1, 1, b"bad\0"), Err(DataError::Ascii));
    assert_eq!(encode_text64(0, 1, b""), Err(DataError::Identity));
    assert_eq!(encode_text64(1, 0, b""), Err(DataError::Identity));
    let fresh = encode_text64(1, 2, b"fresh\n").unwrap();
    assert_eq!(decode_text64(&fresh).unwrap().1, b"fresh\n");
}

#[test]
fn process_data_text64_empty_and_maximum_unsigned_bindings() {
    let empty = encode_text64(u64::MAX, u64::MAX, b"").unwrap();
    assert_eq!(empty.len(), 64);
    let (header, body) = decode_text64(&empty).unwrap();
    assert!(body.is_empty());
    assert_eq!(
        (header.selected_object_id, header.revision),
        (u64::MAX, u64::MAX)
    );
    let full = encode_text64(1, 1, &[b'a'; 4096]).unwrap();
    assert_eq!(full.len(), 4160);
    assert_eq!(decode_text64(&full).unwrap().1.len(), 4096);
}

#[test]
fn process_data_state_layout_keeps_embedded_text64_length_separate() {
    let body = b"hello\tworld\n";
    let mut original = state(body);
    original.cursor = 3;
    // The wire only bounds cursor and selection; it does not require the
    // cursor be a selection endpoint. EditorModel's stronger invariant remains
    // local to actual child models, rather than silently changing this codec.
    original.selection = Some((1, 5));
    original.first_visible_line = 1;
    original.text_generation = u64::MAX;
    original.view_generation = u64::MAX;
    let encoded = original.encode(body).unwrap();
    assert_eq!(encoded.len(), 128 + body.len());
    assert_eq!(&encoded[4..8], &(64u32 + body.len() as u32).to_le_bytes());
    assert_eq!(
        &encoded[64..80],
        &[3, 0, 0, 0, 1, 0, 0, 0, 5, 0, 0, 0, 1, 0, 0, 0]
    );
    assert_eq!(&encoded[80..96], &[255; 16]);
    assert_eq!(&encoded[96..128], &[7; 32]);
    let (decoded, borrowed) = TextState::decode(&encoded).unwrap();
    assert_eq!(decoded, original);
    assert_eq!(borrowed, body);
    assert_eq!(borrowed.as_ptr(), encoded[128..].as_ptr());
}

#[test]
fn process_data_state_refuses_shape_sentinels_and_generation_faults() {
    let original = state(b"abc");
    let valid = original.encode(b"abc").unwrap();
    for offset in [68, 72] {
        let mut broken = valid.clone();
        broken[offset..offset + 4].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(TextState::decode(&broken), Err(DataError::State));
    }
    for offset in [80, 88] {
        let mut broken = valid.clone();
        broken[offset..offset + 8].copy_from_slice(&0u64.to_le_bytes());
        assert_eq!(TextState::decode(&broken), Err(DataError::State));
    }
    for (cursor, selection, line) in [
        (4, None, 0),
        (1, Some((0, 4)), 0),
        (1, Some((2, 1)), 0),
        (1, None, 1),
    ] {
        let mut broken = original.clone();
        broken.cursor = cursor;
        broken.selection = selection;
        broken.first_visible_line = line;
        assert_eq!(broken.encode(b"abc"), Err(DataError::State));
    }
    for length in [127, 4225] {
        assert_eq!(TextState::decode(&vec![0; length]), Err(DataError::Length));
    }
    let mut wrong_embedded_length = valid.clone();
    wrong_embedded_length[4..8].copy_from_slice(&(valid.len() as u32).to_le_bytes());
    assert_eq!(
        TextState::decode(&wrong_embedded_length),
        Err(DataError::Length)
    );
    assert_eq!(TextState::decode(&valid).unwrap().0, original);
    // Wire ordering permits an empty range. The actual editor model's
    // normalized None/nonempty invariant is not an additional wire rule.
    let mut empty_range = original;
    empty_range.selection = Some((2, 2));
    let encoded = empty_range.encode(b"abc").unwrap();
    assert_eq!(TextState::decode(&encoded).unwrap().0, empty_range);
}

#[test]
fn process_data_state_line_inventory_reuses_wrap_tab_and_newline_rules() {
    for body in [
        vec![b'a'; 80],
        [vec![b'a'; 79], b"\t".to_vec()].concat(),
        b"a\n".to_vec(),
    ] {
        let mut value = state(&body);
        value.first_visible_line = 1;
        let bytes = value.encode(&body).unwrap();
        assert_eq!(TextState::decode(&bytes).unwrap().0, value);
        value.first_visible_line = 2;
        assert_eq!(value.encode(&body), Err(DataError::State));
    }
    let mut empty = state(b"");
    empty.first_visible_line = 1;
    assert_eq!(empty.encode(b""), Err(DataError::State));
}

#[test]
fn process_data_surface_validation_checks_all_bytes_and_opaque_alpha() {
    let mut model =
        EditorModel::from_selected_ascii(b"note=old\n", 1, InitialView::KeepTop).unwrap();
    let mut pixels = vec![0; FRAME_BYTES];
    model.rasterize_bgra(&frozen_font(), &mut pixels).unwrap();
    let mut value = state(b"note=old\n");
    value.surface_sha256 = sha256(&pixels);
    value.validate_surface(&pixels).unwrap();
    assert_eq!(
        value.validate_surface(&pixels[..FRAME_BYTES - 1]),
        Err(DataError::Length)
    );
    for index in [0, FRAME_BYTES / 2, FRAME_BYTES - 4] {
        let before = pixels[index];
        pixels[index] ^= 1;
        assert_eq!(value.validate_surface(&pixels), Err(DataError::Hash));
        pixels[index] = before;
    }
    pixels[FRAME_BYTES - 1] = 0;
    assert_eq!(value.validate_surface(&pixels), Err(DataError::Surface));
    model.apply_key(4, 0).unwrap();
    model.rasterize_bgra(&frozen_font(), &mut pixels).unwrap();
    value.surface_sha256 = sha256(&pixels);
    value.validate_surface(&pixels).unwrap();
}

#[test]
fn process_data_font_bytes_are_the_frozen_existing_asset() {
    assert_eq!(
        sha256(FONT_BYTES).as_slice(),
        hex("50ab6522c495f06a69590ccb6958458be15e02a2ca4c6b1024b052e826d21c64")
    );
    let rows = frozen_font();
    let flattened: Vec<u8> = rows.into_iter().flatten().collect();
    assert_eq!(flattened.as_slice(), FONT_BYTES);
}

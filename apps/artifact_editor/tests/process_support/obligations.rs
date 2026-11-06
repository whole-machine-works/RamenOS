//! Independently frozen obligations consumed by substantive P0 assertions.
//! Catalog membership alone is never execution or a passing behavior result.
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::OnceLock,
};

pub struct Control {
    pub group: &'static str,
    pub scenarios: Vec<&'static str>,
}
pub struct Family {
    pub id: &'static str,
    pub positive: &'static str,
    pub controls: Vec<Control>,
}
fn permanent(text: &str) -> &'static str {
    Box::leak(text.to_owned().into_boxed_str())
}
fn inventory() -> &'static Vec<Family> {
    static INVENTORY: OnceLock<Vec<Family>> = OnceLock::new();
    INVENTORY.get_or_init(|| {
        let raw: serde_json::Value =
            serde_json::from_str(include_str!("p0_obligations.json")).unwrap();
        let contract = include_bytes!("../../../../docs/contracts/editor-process-v0.json");
        let digest = Sha256::digest(contract);
        let actual = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(raw["contract_sha256"].as_str(), Some(actual.as_str()));
        assert_eq!(raw["family_count"], 30);
        let contract: serde_json::Value = serde_json::from_slice(contract).unwrap();
        let expected = contract["assertions"]["assertions"].as_array().unwrap();
        let mut ids = BTreeSet::new();
        let mut total = 0;
        let result = raw["families"]
            .as_array()
            .unwrap()
            .iter()
            .zip(expected)
            .map(|(family, frozen)| {
                let id = permanent(family["id"].as_str().unwrap());
                assert_eq!(family["id"], frozen["id"]);
                assert!(ids.insert(id));
                let mut controls: BTreeMap<usize, Vec<&'static str>> = BTreeMap::new();
                let mut case_ids = BTreeSet::new();
                for case in family["negative_scenarios"].as_array().unwrap() {
                    let index = case["contract_control_index"].as_u64().unwrap() as usize;
                    assert!(
                        index > 0
                            && index
                                <= frozen["finite_denial_failure_controls"]
                                    .as_array()
                                    .unwrap()
                                    .len()
                    );
                    assert_eq!(
                        case["contract_control"],
                        frozen["finite_denial_failure_controls"][index - 1]
                    );
                    let name = permanent(case["scenario"].as_str().unwrap());
                    assert!(name.starts_with(id) && case_ids.insert(name));
                    controls.entry(index).or_default().push(name);
                    total += 1;
                }
                assert_eq!(
                    controls.len(),
                    frozen["finite_denial_failure_controls"]
                        .as_array()
                        .unwrap()
                        .len()
                );
                Family {
                    id,
                    positive: permanent(family["positive_scenario"].as_str().unwrap()),
                    controls: controls
                        .into_iter()
                        .map(|(index, scenarios)| Control {
                            group: permanent(&format!("{id}C{index:02}")),
                            scenarios,
                        })
                        .collect(),
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(result.len(), 30);
        assert_eq!(total, 223);
        result
    })
}
pub fn family(id: &str) -> &'static Family {
    inventory()
        .iter()
        .find(|f| f.id == id)
        .expect("literal frozen family")
}

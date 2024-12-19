use std::{
    collections::BinaryHeap,
    fs::{self, File},
    io::{BufReader, ErrorKind},
    path::Path,
    vec,
};

use anyhow::{Context, Result};
use serde::{self, Deserialize, Serialize};
use serde_json::json;

use crate::nixos;

const NIXOS_SEARCH_URL: &str =
    "https://search.nixos.org/backend/latest-*-nixos-unstable/_search";

const NIXOS_SEARCH_USER: &str = "aWVSALXpZv";
const NIXOS_SEARCH_PASS: &str = "X8gPHnzL52wFEekuxsfQ9cSh";

#[derive(Serialize, Deserialize)]
struct ESResponse {
    hits: ESHits,
}

#[derive(Serialize, Deserialize)]
struct ESHits {
    hits: Vec<Hit>,
}

#[derive(Serialize, Deserialize)]
struct Hit {
    #[serde(rename = "_source")]
    package: Package,
}

#[derive(
    Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct Package {
    #[serde(rename = "package_attr_name")]
    pub name: String,
    #[serde(rename = "package_pversion")]
    pub version: String,
    #[serde(rename = "package_description")]
    pub description: Option<String>,
}

pub type Packages = Vec<Package>;

impl Package {
    pub fn new(name: &str, version: &str, description: Option<&str>) -> Self {
        Package {
            name: name.to_string(),
            version: version.to_string(),
            description: description.map(|s| s.to_string()),
        }
    }

    pub fn new_builtin(name: &str) -> Self {
        Self::new(name, "builtin", None)
    }

    pub fn is_builtin(&self) -> bool {
        self.version == "builtin"
    }
}

fn query_wildcards<'a, I: IntoIterator<Item = &'a String>>(
    keywords: I,
) -> serde_json::Value {
    let keywords: Vec<&str> =
        keywords.into_iter().map(|s| s.as_ref()).collect();
    let mut search_items = vec![json!({
      "multi_match": {
        "type": "cross_fields",
        "query": keywords.join(" "),
        "analyzer": "whitespace",
        "auto_generate_synonyms_phrase_query": false,
        "operator": "and",
        "fields": [
          "package_attr_name^9",
          "package_attr_name.*^5.3999999999999995",
          "package_programs^9",
          "package_programs.*^5.3999999999999995",
          "package_pname^6",
          "package_pname.*^3.5999999999999996",
          "package_description^1.3",
          "package_description.*^0.78",
          "package_longDescription^1",
          "package_longDescription.*^0.6",
          "flake_name^0.5",
          "flake_name.*^0.3"
        ]
      }
    })];

    for keyword in &keywords {
        search_items.push(json!({
          "wildcard": {
            "package_attr_name": {
              "value": format!("*{}*", keyword),
              "case_insensitive": true
            }
          }
        }));
    }

    search_items.push(json!({
            "wildcard": {
              "package_attr_name": {
                "value": format!("*{}*", keywords.join(" ")),
                "case_insensitive": true
              }
            }
          }
    ));

    serde_json::Value::Array(search_items)
}

fn excluded_package_sets() -> Vec<serde_json::Value> {
    const EXCLUDED_PACKAGE_SETS: [&str; 3] =
        ["nixVersions", "lixVersions", "linuxKernel"];

    EXCLUDED_PACKAGE_SETS
        .iter()
        .map(|s| {
            json!(
                { "term": { "package_attr_set": { "value": s } } }
            )
        })
        .collect()
}

fn query_payload<'a, I: IntoIterator<Item = &'a String>>(
    keywords: I,
) -> serde_json::Value {
    json!({
      "from": 0,
      "size": 20,
      "sort": [
        {
          "_score": "desc",
          "package_attr_name": "desc",
          "package_pversion": "desc"
        }
      ],
      "query": {
        "bool": {
          "filter": [
            {
              "term": {
                "type": {
                  "value": "package",
                }
              }
            },
            {
              "bool": {
                  "must_not": excluded_package_sets()
              }
            }
          ],
          "must": [
            {
              "dis_max": {
                "tie_breaker": 0.7,
                "queries": query_wildcards(keywords)
              }
            }
          ]
        }
      }
    })
}

fn get_basic_auth_header(user: &str, pass: &str) -> String {
    use base64::prelude::*;
    let usrpw = String::from(user) + ":" + pass;
    format!("Basic {}", BASE64_STANDARD.encode(usrpw.as_bytes()))
}

fn pkg_search(query: serde_json::Value) -> Result<Packages> {
    let response = ureq::post(NIXOS_SEARCH_URL)
        .set("Accept", "application/json")
        .set(
            "Authorization",
            &get_basic_auth_header(NIXOS_SEARCH_USER, NIXOS_SEARCH_PASS),
        )
        .send_json(query)?
        .into_json::<ESResponse>()?;

    let pkgs: Vec<Package> =
        response.hits.hits.into_iter().map(|h| h.package).collect();

    Ok(pkgs)
}

pub fn query<'a, I: IntoIterator<Item = &'a String>>(
    keywords: I,
) -> Result<Packages> {
    pkg_search(query_payload(keywords))
}

pub fn find_package(name: &str) -> Result<Option<Package>> {
    let pkgs = pkg_search(json!({
      "query": {
        "query_string": {
          "query": format!("package_attr_name:\"{}\"", name)
        }
      },
      "size": 1,
      "from": 0,
      "sort": []
    }))?;

    if !pkgs.is_empty() {
        Ok(Some(pkgs[0].clone()))
    } else {
        Ok(None)
    }
}

const INSTALLED_PACKAGES: &str = "/nix/var/data/user-env.json";

pub fn installed_packages() -> Result<Packages> {
    let maybe_file = File::open(INSTALLED_PACKAGES);
    match maybe_file {
        Ok(file) => {
            let reader = BufReader::new(file);
            let pkgs = serde_json::from_reader(reader)?;
            Ok(pkgs)
        }
        Err(err) => match err.kind() {
            ErrorKind::NotFound => Ok(Vec::new()),
            _ => Err(err.into()),
        },
    }
}

pub fn builtin_packages() -> Packages {
    crate::BASE_PACKAGES
        .iter()
        .map(|s| Package::new_builtin(s))
        .collect()
}

pub fn all_packages_sorted() -> Result<Packages> {
    let installed_packages = installed_packages()?;
    let builtin_packages = builtin_packages();

    Ok(BinaryHeap::from_iter(
        builtin_packages.into_iter().chain(installed_packages),
    )
    .into_sorted_vec())
}

fn write_installed_packages(pkgs: &Packages) -> Result<()> {
    let user_env_json = Path::new(INSTALLED_PACKAGES);
    fs::create_dir_all(user_env_json.parent().unwrap())?;
    fs::write(user_env_json, serde_json::to_string_pretty(pkgs)?)
        .context("failed to save installed packages")
}

pub fn install_package(pkg: Package) -> Result<()> {
    let mut pkgs = installed_packages()?;
    pkgs.push(pkg);

    build_user_env_flake(&pkgs)?;
    write_installed_packages(&pkgs)
}

pub fn remove_package(name: &str) -> Result<()> {
    let mut pkgs = installed_packages()?;
    let maybe_pos = pkgs.iter().position(|p| p.name == name);
    if let Some(pos) = maybe_pos {
        pkgs.remove(pos);
        build_user_env_flake(&pkgs)?;
        write_installed_packages(&pkgs)?;
        nixos::run_gc()?;
    }
    Ok(())
}

fn build_user_env_flake(pkgs: &Packages) -> Result<()> {
    let flake_pkgs: Vec<&str> = pkgs.iter().map(|p| p.name.as_ref()).collect();
    let flake_dir = Path::new(crate::CACHE_HOME).join("env-flake");
    let path = crate::nixos::build_flake_from_package_list(
        "user-env",
        "Dive installed packages",
        &flake_pkgs,
        &flake_dir,
    )
    .context("failed to build flake")?;
    nixos::symlink_store_path(path, "user-env", crate::USER_ENV_DIR)?;
    Ok(())
}

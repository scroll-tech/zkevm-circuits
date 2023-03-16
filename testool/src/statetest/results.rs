use anyhow::Result;
use handlebars::Handlebars;
use prettytable::Row;
use prettytable::Table;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use std::collections::HashSet;
use std::io::Read;
use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;
use strum::IntoEnumIterator;
use strum_macros::{EnumIter, EnumString}; // 0.17.1

const MAX_DETAILS_LEN: usize = 128;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, EnumIter, EnumString, Serialize, Deserialize)]
pub enum ResultLevel {
    Success,
    Ignored,
    Fail,
    Panic,
}

#[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub struct ResultInfo {
    pub level: ResultLevel,
    pub details: String,
}

impl ResultLevel {
    pub fn display_string(&self) -> String {
        use ResultLevel::*;
        match self {
            Panic => "💀PANIC",
            Fail => "🔴FAILD",
            Ignored => "🟠IGNOR",
            Success => "🟢SUCCS",
        }
        .to_string()
    }
}
pub struct DiffEntry {
    id: String,
    prev: Option<ResultInfo>,
    curr: Option<ResultInfo>,
}

pub struct Diffs {
    previous: String,
    tests: Vec<DiffEntry>,
}

fn trim(s: &str, max_len: usize) -> &str {
    if s.len() > max_len {
        &s[0..max_len]
    } else {
        s
    }
}

impl Diffs {
    pub fn gen_info(&self) -> (String, Table) {
        let mut stat: HashMap<ResultLevel, isize> = HashMap::new();
        let mut stat_news = 0isize;

        for t in &self.tests {
            if let Some(prev) = &t.prev {
                *stat.entry(prev.level).or_default() -= 1;
                *stat.entry(t.curr.as_ref().unwrap().level).or_default() += 1;
            } else {
                stat_news += 1;
            }
        }

        let mut summary = String::default();
        if stat_news > 0 {
            summary.push_str(&format!("new: {:+} ", stat_news));
        }
        for (lvl, n) in stat {
            summary.push_str(&format!("/ {:?}: {:+} ", lvl, n));
        }
        if summary.is_empty() {
            summary.push_str("No changes");
        }

        summary.push_str(&format!(" [diff from {}]", self.previous));

        let mut table = Table::new();
        for t in &self.tests {
            if let Some(prev) = &t.prev {
                let curr = t.curr.as_ref().unwrap();
                table.add_row(row![
                    t.id,
                    format!(
                        "{:?}({}) => {:?}({})",
                        prev.level,
                        trim(&prev.details, MAX_DETAILS_LEN),
                        curr.level,
                        trim(&curr.details, MAX_DETAILS_LEN)
                    ),
                ]);
            }
        }
        table.add_row(row!["Summary", summary]);
        (summary, table)
    }
}

pub struct Report {
    tests: HashMap<String, ResultInfo>,
    diffs: Diffs,
    by_folder: Table,
    by_result: Table,
}

impl Report {
    pub fn print_tty(&self) -> Result<()> {
        self.by_folder.print_tty(false)?;
        let mut by_result_short = self.by_result.clone();
        for row_no in 0..by_result_short.len() {
            let row = by_result_short.get_mut_row(row_no).unwrap();
            let cell_content = row.get_cell(1).unwrap().get_content().replace('\n', "");
            if cell_content.len() > 100 {
                let cell = prettytable::Cell::new(&cell_content[..100]);
                *row.get_mut_cell(1).unwrap() = cell;
            }
        }
        by_result_short.print_tty(false)?;
        let (_, files_diff) = self.diffs.gen_info();
        files_diff.print_tty(false)?;
        let mut num_succ = 0f32;
        let mut num_fail = 0f32;
        for (test_id, info) in &self.tests {
            if info.level == ResultLevel::Success {
                num_succ += 1.0;
            }
            if info.level == ResultLevel::Fail || info.level == ResultLevel::Panic {
                num_fail += 1.0;
                println!("- {:?} {}", info.level, test_id);
            }
        }
        log::info!(
            "success rate: {:.1}%",
            100f32 * num_succ / (num_succ + num_fail)
        );
        Ok(())
    }
    pub fn gen_html(&self) -> Result<String> {
        let template = include_str!("report.handlebars");
        let reg = Handlebars::new();
        let mut by_folder = Vec::new();
        let mut by_result = Vec::new();
        let mut diffs = Vec::new();

        self.by_folder.print_html(&mut by_folder)?;
        self.by_result.print_html(&mut by_result)?;
        self.diffs.gen_info().1.print_html(&mut diffs)?;

        let tests: HashMap<String, ResultInfo> = self
            .tests
            .clone()
            .into_iter()
            .filter(|(_k, v)| {
                !matches!(
                    v.level,
                    crate::ResultLevel::Ignored | crate::ResultLevel::Success
                )
            })
            .collect();
        let data = &json!({
                "by_folder": String::from_utf8(by_folder)?,
                "by_result" : String::from_utf8(by_result)? ,
                "diffs" : String::from_utf8(diffs)?,
                "all_results" : tests
        });

        let html = reg.render_template(template, data)?;
        Ok(html)
    }
}

#[derive(Default, Clone)]
pub struct Results {
    pub tests: HashMap<String, ResultInfo>,
    pub cache: Option<PathBuf>,
}

impl Results {
    pub fn from_file(path: PathBuf) -> Result<Self> {
        let mut file = std::fs::File::open(&path)?;
        let mut buf = String::new();
        file.read_to_string(&mut buf)?;
        let mut tests = HashMap::new();
        for line in buf.lines().filter(|l| l.len() > 1) {
            let mut split = line.splitn(3, ';');
            let level = split.next().unwrap();
            let level = ResultLevel::from_str(level).unwrap();
            let id = split.next().unwrap().to_string();
            let details = urlencoding::decode(split.next().unwrap())
                .expect("should be urldecodeable")
                .to_string();
            tests.insert(id, ResultInfo { level, details });
        }
        Ok(Self { cache: None, tests })
    }

    pub fn with_cache(path: PathBuf) -> Result<Self> {
        let tests = if path.exists() {
            Self::from_file(path.clone())?.tests
        } else {
            HashMap::new()
        };
        Ok(Self {
            tests,
            cache: Some(path),
        })
    }

    pub fn set_cache(&mut self, path: PathBuf) {
        self.cache = Some(path);
    }

    pub fn report(self, previous: Option<(String, Results)>) -> Report {
        // collect data
        let mut folders = HashSet::new();
        let mut results = HashSet::new();
        let mut count_by_folder_level: HashMap<String, usize> = HashMap::new();
        let mut count_by_result: HashMap<String, usize> = HashMap::new();

        let mut diffs = Diffs {
            previous: "<no previous commit>".into(),
            tests: Vec::new(),
        };
        let mut prev_results = None;
        if let Some((prev_info, p_results)) = previous {
            diffs.previous = prev_info;
            prev_results = Some(p_results);
        }

        for (id, info) in &self.tests {
            let (_, file_path) = id.split_once('#').unwrap();
            let filename = &file_path.rsplit_terminator('/').next().unwrap();
            let folder = &file_path[..file_path.len() - filename.len() - 1];

            let result = format!("{:?}_{}", info.level, info.details);

            folders.insert(folder);
            results.insert(result.to_string());

            let key = format!("{}_{:?}", folder, info.level);
            *count_by_folder_level.entry(key).or_default() += 1;
            *count_by_result.entry(result).or_default() += 1;

            if let Some(prev_results) = &prev_results {
                if let Some(prev_info) = prev_results.tests.get(id) {
                    if info != prev_info {
                        diffs.tests.push(DiffEntry {
                            id: id.to_string(),
                            prev: Some(prev_info.clone()),
                            curr: Some(info.clone()),
                        });
                    }
                } else {
                    diffs.tests.push(DiffEntry {
                        id: id.to_string(),
                        prev: None,
                        curr: Some(info.clone()),
                    });
                }
            }
        }

        let mut folders: Vec<_> = folders.iter().collect();
        folders.sort();
        let mut results: Vec<_> = results.iter().collect();
        results.sort();

        // generate tables

        let mut by_folder = Table::new();
        let mut header = vec![String::from("By path")];

        let levels: Vec<_> = ResultLevel::iter().collect();

        header.append(&mut levels.iter().map(|v| format!("{:?}", v)).collect());
        by_folder.add_row(Row::from_iter(header));

        let mut totals = vec![0usize; levels.len()];

        for folder in folders {
            let mut row = Vec::new();
            for i in 0..levels.len() {
                let key = format!("{}_{:?}", folder, levels[i]);
                let value = *count_by_folder_level.get(&key).unwrap_or(&0usize);
                row.push(value);
                totals[i] += value;
            }
            let sum: usize = row.iter().sum();
            let mut cells = vec![folder.to_string()];
            cells.append(
                &mut row
                    .iter()
                    .map(|n| format!("{} ({}%)", n, (100 * n) / sum))
                    .collect(),
            );
            by_folder.add_row(Row::from_iter(cells));
        }
        let sum: usize = totals.iter().sum();
        let mut cells = vec!["TOTAL".to_string()];
        if sum != 0 {
            cells.append(
                &mut totals
                    .iter()
                    .map(|n| format!("{} ({}%)", n, (100 * n) / sum))
                    .collect(),
            );
        }
        by_folder.add_row(Row::from_iter(cells));

        let mut by_result = Table::new();
        by_result.add_row(row!["By type", "Count"]);
        let mut info = Vec::new();
        for (result, count) in count_by_result {
            info.push((count, result));
        }

        info.sort_by(|a, b| b.0.cmp(&a.0));
        for entry in info.iter().take(25) {
            by_result.add_row(row![format!("{}", entry.0), entry.1]);
        }

        Report {
            tests: self.tests,
            by_folder,
            by_result,
            diffs,
        }
    }

    pub fn success(&self) -> bool {
        !self
            .tests
            .values()
            .any(|result| result.level == ResultLevel::Fail || result.level == ResultLevel::Panic)
    }

    pub fn contains(&self, test: &str) -> bool {
        self.tests.contains_key(test)
    }

    pub fn write_cache(&self) -> Result<()> {
        if let Some(path) = &self.cache {
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .append(true)
                .open(path)?;
            for (test_id, result) in &self.tests {
                let entry = format!(
                    "{:?};{};{}\n",
                    result.level,
                    test_id,
                    urlencoding::encode(&result.details)
                );
                file.write_all(entry.as_bytes())?;
            }
        }
        Ok(())
    }

    #[allow(clippy::map_entry)]
    pub fn insert(&mut self, test_id: String, result: ResultInfo) -> Result<()> {
        if !self.tests.contains_key(&test_id) {
            if result.level == ResultLevel::Ignored {
                log::debug!(
                    target : "testool",
                    "{} {} {}",
                    result.level.display_string(),
                    test_id,
                    result.details
                );
            } else {
                log::info!(
                    "{} {} {}",
                    result.level.display_string(),
                    test_id,
                    result.details
                );
            }
            self.tests.insert(test_id, result);
        }

        Ok(())
    }
}

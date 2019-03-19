#[macro_use]
extern crate human_panic;
use fern;
#[macro_use]
extern crate log;
use log::LevelFilter;
use std::default::Default;
mod credentials;
use colored::*;
use credentials::CustomCredentialProvider;
use std::fmt;
use std::time::{Duration, Instant};

extern crate chrono;
use chrono::NaiveDateTime;
use std::ops::Deref;
extern crate regex;
use regex::Regex;
use std::cmp;
// ======== aws ========
extern crate rusoto_core;
extern crate rusoto_ec2;
extern crate rusoto_sts;

use rusoto_core::{HttpClient, Region};

use rusoto_cloudformation::{
    CloudFormation, CloudFormationClient, DescribeStackEventsError, DescribeStackEventsInput,
    StackEvent,
};
// ========== end of aws ======

pub fn setup_logger(
    self_level: LevelFilter,
    default_level: LevelFilter,
) -> Result<(), fern::InitError> {
    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}][{}] {}",
                chrono::Local::now().format("[%Y-%m-%d %H:%M:%S]"),
                record.target(),
                record.level(),
                message
            ))
        })
        .level(default_level)
        .level_for("tail-stack-events", self_level)
        .chain(std::io::stdout())
        .chain(fern::log_file("output.log")?)
        .apply()?;
    Ok(())
}

fn setup_aws_creds(
    region: Region,
    role_name: Option<String>,
) -> rusoto_credential::AutoRefreshingProvider<CustomCredentialProvider> {
    let provider = CustomCredentialProvider::new(role_name, region);
    let auto_refreshing_provider = rusoto_credential::AutoRefreshingProvider::new(provider);
    auto_refreshing_provider.expect("cannot get a sts provider\\creds")
}

struct CFDescriber {
    last_event: Option<StackEvent>,
    last_api_call: Instant,
    follow: bool,
    die: bool,
    exit_code: u32,
    client: CloudFormationClient,
}

struct CFStackEvent {
    inner: StackEvent,
}

impl std::fmt::Display for CFStackEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut msg;
        if let Some(mut status) = self.inner.resource_status.clone() {
            if status.contains("FAILED") {
                status = "✗ ".to_owned() + &status;
                msg = status.red();
            } else if status.contains("COMPLETE") {
                status = "✓ ".to_owned() + &status;
                msg = status.green();
            } else {
                status = "⌛ ".to_owned() + &status;
                msg = status.blue();
            }
        } else {
            msg = "⚠️ Not defined (probably a bug)!".to_owned().red();
            warn!("Got non-typical event without resource_status: {:#?}", self.inner);
        }

        let date = NaiveDateTime::parse_from_str(&self.inner.timestamp, "%+").unwrap();
        let logical_resource_id =
            self.inner
                .logical_resource_id
                .clone()
                .unwrap_or_else(|| "".to_owned());
        let resource_type = self.inner.resource_type.clone().unwrap_or_else(|| "".to_owned());
        let resource_status_reason =
            self.inner
                .resource_status_reason
                .clone()
                .unwrap_or_else(|| "".to_owned());

        f.write_fmt(format_args!(
            "{:<15.15} {:<25.25} {:<25.25} {:<25.25} {:<50}",
            date.format("%H:%M:%S"),
            logical_resource_id.bold(),
            resource_type.replace("AWS::", "").cyan(),
            msg,
            resource_status_reason
        ))
    }
}

impl Deref for CFStackEvent {
    type Target = StackEvent;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl From<StackEvent> for CFStackEvent {
    fn from(event: StackEvent) -> Self {
        Self { inner: event }
    }
}

impl CFDescriber {
    fn new(region: Region, role_arn: Option<String>, follow: bool, die: bool) -> Self {
        let provider = setup_aws_creds(region.clone(), role_arn);
        let client = HttpClient::new().expect("cannot get a client");
        let cf = CloudFormationClient::new_with(client, provider, region);

        Self {
            last_event: None,
            last_api_call: Instant::now(),
            follow,
            die,
            exit_code: 0,
            client: cf,
        }
    }

    fn get_recent_events(&mut self, stack_name: &str) -> Result<Vec<CFStackEvent>, String> {
        let cf_desc_input = DescribeStackEventsInput {
            stack_name: Some(stack_name.to_owned()),
            ..Default::default()
        };

        let evts = self.client.describe_stack_events(cf_desc_input);
        let evts = evts
            .sync()
            .map(|out| out.stack_events)
            .map_err(|e| format!("{:?}", e))?;

        let evts = evts.unwrap();
        self.last_api_call = Instant::now();
        let new_evts;
        if self.last_event.is_some() {
            let last_event_idx = evts.iter().position(|el| {
                let event_id = self
                    .last_event
                    .clone()
                    .expect("cannot get a last_event???")
                    .event_id;

                event_id == el.event_id
            });
            //.enumerate().filter(|(i, el)| ).nth(0).map(|(i, el)| i as i32).unwrap_or(-1);
            if last_event_idx.is_some() {
                new_evts = &evts[0..last_event_idx.unwrap()];
            } else {
                new_evts = &evts[0..evts.len()];
            };
        } else {
            new_evts = &evts[0..10];
        };

        if !new_evts.is_empty() {
            debug!("about to set last_event to: {:?}!", new_evts[0].clone());
            self.last_event = Some(new_evts[0].clone());
        }
        let mut new_evts = new_evts.to_vec();
        new_evts.reverse();
        Ok(new_evts
            .iter()
            .map(|e| CFStackEvent::from(e.clone()))
            .collect::<Vec<CFStackEvent>>())
        // evts
    }

    fn should_keep_tailing(&mut self, stack_name: &str) -> bool {
        if self.follow {
            return true;
        }
        if self.die {
            if let Some(last_event) = self.last_event.clone() {
                if last_event.resource_type.unwrap_or_else(|| "".to_owned()) == "AWS::CloudFormation::Stack"
                    && last_event.logical_resource_id.unwrap_or_else(|| "".to_owned()) == stack_name
                {
                    // emulate lookahead
                    // (?<!ROLLBACK)
                    if let Some(resource_status) = &last_event.resource_status {
                        let is_success = !resource_status.contains("ROLLBACK")
                            && resource_status.ends_with("_COMPLETE");
                        let is_failure =
                            Regex::new(r"(?:ROLLBACK_COMPLETE$|UPDATE_ROLLBACK_COMPLETE$|FAILED)")
                                .unwrap()
                                .is_match(&last_event.resource_status.unwrap_or_else(|| "".to_owned()));
                        if !is_success {
                            self.exit_code = 1
                        } else {
                            self.exit_code = 0
                        };
                        if is_success || is_failure {
                            return false;
                        }
                    } else {
                        //nothing in status
                    }
                }
            }
            return true;
        }
        false
    }

    fn print_events(&mut self, stack_name: &str) {
        while self.should_keep_tailing(stack_name) {
            match self.get_recent_events(stack_name) {
                Ok(evts) => {
                    for event in evts.iter() {
                        println!("{}", event);
                    }
                }
                Err(e) => {
                    error!("Error calling get_recent_events! {}", e);
                    // todo: retry
                    std::process::exit(2);
                }
            };

            // @TODO: fixme
            let last_api_call_sec = self.last_api_call.elapsed().as_secs();
            let wait_time;
            if last_api_call_sec < 3 {
                wait_time = cmp::max(1, 3 - last_api_call_sec);
            } else {
                wait_time = 3;
            };

            use std::thread;
            thread::sleep(Duration::from_secs(wait_time));
        }
    }
}

use std::env;

fn main() {
    //setup_panic!();
    setup_logger(LevelFilter::Warn, LevelFilter::Warn)
        .expect("Cannot setup logger. Shouldn't be possible in most cases");

    let mut cf = CFDescriber::new(Region::UsEast1, None, false, true);
    let args: Vec<String> = env::args().collect();
    let stack_name = if args.len() > 1 { &args[1] } else { "cf-test" };
    println!("{:?}", args);
    cf.print_events(stack_name);
}

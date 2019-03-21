#[macro_use]
extern crate human_panic;
#[macro_use]
extern crate log;
use std::default::Default;
mod credentials;
mod logging;
use colored::*;
use credentials::setup_aws_creds;
use logging::setup_logger;
use std::fmt;
use std::time::{Duration, Instant};

extern crate chrono;
use chrono::NaiveDateTime;
use std::ops::Deref;
extern crate regex;
use regex::Regex;
use std::cmp;

#[macro_use]
extern crate clap;
use clap::{App, Arg};
// ======== aws ========
extern crate rusoto_core;
extern crate rusoto_ec2;
extern crate rusoto_sts;

use rusoto_core::{HttpClient, Region};

use rusoto_cloudformation::{
    CloudFormation, CloudFormationClient, DescribeStackEventsError, DescribeStackEventsInput,
    DescribeStacksInput, StackEvent,
};
// ========== end of aws ======
use std::error::Error;
use std::str::FromStr;

const MAX_TRIES: u8 = 10;

struct Config {
    region: Region,
    stack_name: String,
    debug: u8,
    role_name: Option<String>,
    profile_name: Option<String>,
    follow: bool,
    num_events: u8,
}

fn get_config_from_args() -> Result<Config, String> {
    let matches = App::new("tail-stack-events")
        .version(crate_version!())
        .about("Tails CloudFormation stack events")
        .arg(
            Arg::with_name("region")
                .short("r")
                .long("region")
                .value_name("REGION")
                .help("Sets a region to use")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("stack")
                .help("Sets a stack name to watch for")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("debug")
                .short("d")
                .multiple(true)
                .help("Turn debugging logging on. Multiple occurences enable console debug. First one will write to separate logfile"),
        )
        .arg(
            Arg::with_name("role_arn")
                .long("role_arn")
                .value_name("ASSUME_ROLE_ARN")
                .help("Sets an ARN for assume-role to use")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("profile")
                .short("p")
                .long("profile")
                .takes_value(true)
                .help("Sets an AWS-cli profile from ~/.aws/config")
                .value_name("AWS_PROFILE"),
        ).
        arg(
            Arg::with_name("follow")
            .short("f")
            .multiple(false)
            .takes_value(false)
            .help("Follow stack events till success\\failure of the whole stack")
        ).
        arg(
            Arg::with_name("num_events")
            .help("Number of events to pull in one go (max: 100)")
            .value_name("NUMBER_OF_EVENTS")
            .default_value("10")
            .takes_value(true)
            .short("n")
        )
        .get_matches();
    let region;
    let debug;
    let stack_name;
    let role_name;
    let profile_name;
    let follow;
    let num_events: u8;

    if matches.is_present("region") {
        region = Region::from_str(matches.value_of("region").unwrap())
            .map_err(|e| format!("{:#?}", e))?;
    } else {
        return Err("no region name was given".to_owned());
    };

    if matches.is_present("stack") {
        stack_name = matches.value_of("stack").unwrap().to_owned();
    } else {
        return Err("no stack name was given".to_owned());
    };
    if matches.is_present("role_arn") {
        role_name = Some(matches.value_of("role_arn").unwrap().to_owned());
    } else {
        role_name = None
    };

    if matches.is_present("profile") {
        profile_name = Some(matches.value_of("profile").unwrap().to_owned());
    } else {
        profile_name = None
    };

    debug = matches.occurrences_of("debug") as u8;
    follow = matches.is_present("follow");
    num_events = cmp::min(100, value_t!(matches, "num_events", u8).unwrap_or(10));

    Ok(Config {
        region,
        stack_name,
        debug,
        role_name,
        profile_name,
        follow,
        num_events,
    })
}

struct CFDescriber {
    last_event: Option<StackEvent>,
    last_api_call: Instant,
    follow: bool,
    exit_code: u32,
    client: CloudFormationClient,
    api_timeout_max_ms: u128,
    failed_attempts: u8,
    num_events: u8,
    // todo: get rid of me
    first_call: bool,
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
            warn!(
                "Got non-typical event without resource_status: {:#?}",
                self.inner
            );
        }

        // pretty reasonable to always expect time in request (filed isn't optional)
        let date = NaiveDateTime::parse_from_str(&self.inner.timestamp, "%+").unwrap();
        let logical_resource_id = self
            .inner
            .logical_resource_id
            .clone()
            .unwrap_or_else(|| "".to_owned());
        let resource_type = self
            .inner
            .resource_type
            .clone()
            .unwrap_or_else(|| "".to_owned());
        let resource_status_reason = self
            .inner
            .resource_status_reason
            .clone()
            .unwrap_or_else(|| "".to_owned());

        f.write_fmt(format_args!(
            "{:<15.15} {:<25.25} {:<35.35} {:<25.25} {:<50}",
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
    fn new(config: &Config) -> Self {
        let provider = setup_aws_creds(
            config.region.clone(),
            config.role_name.clone(),
            config.profile_name.clone(),
        );
        let client = HttpClient::new().expect("cannot get a client");
        let cf = CloudFormationClient::new_with(client, provider, config.region.clone());

        Self {
            last_event: None,
            last_api_call: Instant::now(),
            follow: config.follow,
            exit_code: 0,
            client: cf,
            api_timeout_max_ms: 3000, // 3 seconds
            failed_attempts: 0,
            num_events: config.num_events,
            // todo: figure out
            first_call: true,
        }
    }

    fn get_recent_events(
        &mut self,
        stack_name: &str,
    ) -> Result<Vec<CFStackEvent>, rusoto_core::RusotoError<DescribeStackEventsError>> {
        let cf_desc_input = DescribeStackEventsInput {
            stack_name: Some(stack_name.to_owned()),
            ..Default::default()
        };

        self.last_api_call = Instant::now();
        let evts = self.client.describe_stack_events(cf_desc_input);
        let evts = evts.sync().map(|out| out.stack_events)?;

        // guaranteed to succeed, otherwise should bail out before
        let evts = evts.unwrap();
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

            if last_event_idx.is_some() {
                // can be rewritten as looooong if let Some(x) ... just to get rid of unwrap
                new_evts = &evts[0..last_event_idx.unwrap()];
            } else {
                new_evts = &evts[0..evts.len()];
            };
        } else {
            println!("self num: {}", self.num_events as usize);
            new_evts = &evts[0..self.num_events as usize];
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
            if let Some(last_event) = self.last_event.clone() {
                if last_event.resource_type.unwrap_or_else(|| "".to_owned())
                    == "AWS::CloudFormation::Stack"
                    && last_event
                        .logical_resource_id
                        .unwrap_or_else(|| "".to_owned())
                        == stack_name
                {
                    // emulate lookahead
                    // (?<!ROLLBACK)
                    if let Some(resource_status) = &last_event.resource_status {
                        let is_success = !resource_status.contains("ROLLBACK")
                            && resource_status.ends_with("_COMPLETE");
                        let is_failure =
                            Regex::new(r"(?:ROLLBACK_COMPLETE$|UPDATE_ROLLBACK_COMPLETE$|FAILED)")
                                .unwrap()
                                .is_match(
                                    &last_event.resource_status.unwrap_or_else(|| "".to_owned()),
                                );
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

    fn handle_retry(&mut self) {
        if self.failed_attempts >= MAX_TRIES {
            std::process::exit(2);
        } else {
            self.failed_attempts += 1;
            // naively increase the timeout
            self.api_timeout_max_ms += 500; // half of second each try
                                            // in the end it will take longer but allow to avoil possible ramming\rate-limiting from AWS
        }
    }

    fn is_stack_exists(&self, stack_name: &str) -> bool {
        let input = DescribeStacksInput {
            stack_name: Some(stack_name.to_owned()),
            ..Default::default()
        };
        self.client.describe_stacks(input).sync().is_ok()
    }

    fn print_events(&mut self, stack_name: &str) {
        if !self.is_stack_exists(stack_name) {
            error!("Stack with name {} doesn't exist!", stack_name);
            std::process::exit(1);
        }
        while self.should_keep_tailing(stack_name) || self.first_call {
            self.first_call = false;
            match self.get_recent_events(stack_name) {
                Ok(evts) => {
                    for event in evts.iter() {
                        println!("{}", event);
                    }
                }
                Err(e) => {
                    match e {
                        rusoto_core::RusotoError::Unknown(ref cause) => {
                            if cause.status == 403 {
                                // Mostly caused by credentials in my testing, somehow didn't end up in Credentials variant of enum
                                debug!("Error calling get_recent_events!\nStatus code: {}\nBody: {}\nHeaders: {:#?}",
                                    cause.status, cause.body_as_str(), cause.headers);
                                error!("Error calling get_recent_events! Got 403 Forbidden! Check your credentials!");
                                std::process::exit(2);
                            } else {
                                error!("Error calling get_recent_events!\nStatus code: {}\nBody: {}\nHeaders: {:#?}",
                                    cause.status, cause.body_as_str(), cause.headers);
                                self.handle_retry();
                            }
                        }
                        rusoto_core::RusotoError::Credentials(ref error) => {
                            error!("Error with provided credentials! {}", error.description());
                            std::process::exit(2);
                        }
                        _ => {
                            error!("Error calling get_recent_events! {:#?} Retrying...", e);
                            self.handle_retry();
                        }
                    };
                }
            };

            let last_api_call_sec = self.last_api_call.elapsed().as_millis();
            let wait_time = if last_api_call_sec < self.api_timeout_max_ms {
                cmp::max(100, self.api_timeout_max_ms - last_api_call_sec)
            } else {
                self.api_timeout_max_ms
            };

            use std::thread;
            thread::sleep(Duration::from_millis(wait_time as u64));
        }
    }
}

fn main() -> Result<(), String> {
    setup_panic!();
    let config = get_config_from_args()?;

    setup_logger(&config).expect("Cannot setup logger. Shouldn't be possible in most cases");

    let mut cf = CFDescriber::new(&config);
    cf.print_events(&config.stack_name);
    Ok(())
}

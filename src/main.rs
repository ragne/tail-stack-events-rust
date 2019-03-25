#[macro_use]
extern crate human_panic;
#[macro_use]
extern crate log;
use std::default::Default;
mod credentials;
mod logging;
#[macro_use]
extern crate clap;
mod arg_parse;
use arg_parse::{get_config_from_args, Config};
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

// ======== aws ========
extern crate rusoto_core;
extern crate rusoto_ec2;
extern crate rusoto_sts;

use rusoto_core::HttpClient;

use rusoto_cloudformation::{
    CloudFormation, CloudFormationClient, DescribeStackEventsError, DescribeStackEventsInput,
    DescribeStacksInput, StackEvent,
};
// ========== end of aws ======
use std::error::Error;
use std::thread;

const MAX_TRIES: u8 = 10;

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
    should_retry: bool,
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
            date.format("%b %d %H:%M:%S"),
            logical_resource_id.bold().yellow(),
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
            api_timeout_max_ms: config.timeout, // 10 seconds
            failed_attempts: 0,
            num_events: config.num_events,
            // todo: figure out
            first_call: true,
            should_retry: false,
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
            // in the end it will take longer but allow to avoil possible ramming\rate-limiting from AWS
            self.api_timeout_max_ms += (2 as u128).pow(self.failed_attempts as u32) * 50; // AWS recommended way
                                                                                          // if we're there, we should set should_retry
            self.should_retry = true;
        }
    }

    fn is_stack_exists(&mut self, stack_name: &str) -> bool {
        let input = DescribeStacksInput {
            stack_name: Some(stack_name.to_owned()),
            ..Default::default()
        };
        self.client
            .describe_stacks(input)
            .sync()
            .map_err(|e| self.handle_api_error(e))
            .is_ok()
    }

    fn handle_api_error<T>(&mut self, e: rusoto_core::RusotoError<T>)
    where
        T: Error,
    {
        match e {
            rusoto_core::RusotoError::Unknown(ref cause) => {
                if cause.status == 403 {
                    // Mostly caused by credentials in my testing, somehow didn't end up in Credentials variant of enum
                    debug!(
                        "Error calling AWS API!\nStatus code: {}\nBody: {}\nHeaders: {:#?}",
                        cause.status,
                        cause.body_as_str(),
                        cause.headers
                    );
                    error!("Error calling AWS API! Got 403 Forbidden! Check your credentials!");
                    std::process::exit(2);
                } else {
                    warn!(
                        "Error calling AWS API!\nStatus code: {}\nBody: {}\nHeaders: {:#?}",
                        cause.status,
                        cause.body_as_str(),
                        cause.headers
                    );
                    self.handle_retry();
                }
            }
            rusoto_core::RusotoError::Credentials(ref error) => {
                error!("Error with provided credentials! {}", error.description());
                std::process::exit(2);
            }
            _ => {
                warn!("Error calling AWS API! {:#?} Retrying...", e);
                self.handle_retry();
            }
        };
    }

    fn get_wait_time(&self) -> u64 {
        let last_api_call_sec = self.last_api_call.elapsed().as_millis();
        let wait_time = if last_api_call_sec < self.api_timeout_max_ms && !self.should_retry {
            cmp::max(100, self.api_timeout_max_ms - last_api_call_sec)
        } else {
            self.api_timeout_max_ms
        };

        debug!("wait time: {}, last_api_call(ms): {}, max_timeout(ms): {}, should_retry: {}", 
            wait_time,
            last_api_call_sec,
            self.api_timeout_max_ms,
            self.should_retry
            );
        // https://github.com/rust-lang/rust/issues/58580
        wait_time as u64
    }

    fn print_events(&mut self, stack_name: &str) {
        if !self.is_stack_exists(stack_name) {
            error!("Stack with name {} doesn't exist!", stack_name);
            std::process::exit(1);
        }
        // should always peek at last events for stack, even if there's no ongoing operations
        while self.should_keep_tailing(stack_name) || self.first_call {
            self.first_call = false;
            match self.get_recent_events(stack_name) {
                Ok(evts) => {
                    for event in evts.iter() {
                        println!("{}", event);
                    }
                    // succesfully printed events: reset flag
                    self.should_retry = false;
                }
                Err(e) => self.handle_api_error(e),
            };

            let wait_time = self.get_wait_time();
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

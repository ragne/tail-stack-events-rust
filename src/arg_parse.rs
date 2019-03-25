use clap::{App, Arg};
use rusoto_core::Region;
use std::cmp;
use std::str::FromStr;

pub(crate) struct Config {
    pub region: Region,
    pub stack_name: String,
    pub debug: u8,
    pub role_name: Option<String>,
    pub profile_name: Option<String>,
    pub follow: bool,
    pub num_events: u8,
    pub timeout: u128,
}

pub(crate) fn get_config_from_args() -> Result<Config, String> {
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
        .arg(
            Arg::with_name("timeout")
            .short("t")
            .help("Number of seconds to wait between subsequental calls (default: 3)")
            .default_value("3")
            .takes_value(true)
            .value_name("TIMEOUT")
        )
        .get_matches();
    let region;
    let debug;
    let stack_name;
    let role_name;
    let profile_name;
    let follow;
    let num_events: u8;
    let timeout: u128;

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

    // from cmd-args we got seconds, but internally we use ms
    timeout = cmp::max(
        1000,
        value_t!(matches, "timeout", u128).unwrap_or(3) * 1000,
    );

    Ok(Config {
        region,
        stack_name,
        debug,
        role_name,
        profile_name,
        follow,
        num_events,
        timeout,
    })
}

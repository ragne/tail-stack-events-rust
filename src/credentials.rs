use futures::{Future, Poll};
use rusoto_core::{
    credential::{ChainProvider, ProvideAwsCredentials},
    region::Region,
    request::HttpClient,
};
use rusoto_credential::{AwsCredentials, CredentialsError, ProfileProvider};
use rusoto_sts::{StsAssumeRoleSessionCredentialsProvider, StsClient};
use std::time::Duration;

pub(crate) struct CustomCredentialProvider {
    role_arn: Option<String>,
    region: Region,
    profile_name: Option<String>,
}

pub struct CustomCredentialProviderFuture {
    inner: Box<Future<Item = AwsCredentials, Error = CredentialsError> + Send>,
}

impl Future for CustomCredentialProviderFuture {
    type Item = AwsCredentials;
    type Error = CredentialsError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.inner.poll()
    }
}

impl ProvideAwsCredentials for CustomCredentialProvider {
    type Future = CustomCredentialProviderFuture;

    fn credentials(&self) -> Self::Future {
        let mut credentials;
        if self.profile_name.is_some() {
            let mut profile_provider = ProfileProvider::new().expect("Cannot create profile_provider");
            profile_provider.set_profile(self.profile_name.clone().unwrap());
            credentials = ChainProvider::with_profile_provider(profile_provider);
        } else {
            credentials = ChainProvider::new();
        };

        credentials.set_timeout(Duration::from_secs(10));

        if let Some(ref role_arn) = self.role_arn {
            let http_client = HttpClient::new().expect("Failed to create https client for sts");
            // no matter which region the sts credentials come from, they work globally
            let sts = StsClient::new_with(http_client, credentials, self.region.clone());
            let provider = StsAssumeRoleSessionCredentialsProvider::new(
                sts,
                role_arn.to_string(),
                "default".to_string(),
                None,
                None,
                None,
                None,
            );
            return CustomCredentialProviderFuture {
                inner: Box::new(provider.credentials()),
            };
            //return result(Ok(provider.credentials()));
        }
        CustomCredentialProviderFuture {
            inner: Box::new(credentials.credentials()),
        }
    }
}

impl CustomCredentialProvider {
    pub fn new(role_arn: Option<String>, region: Region, profile_name: Option<String>) -> Self {
        Self {
            role_arn,
            region,
            profile_name,
        }
    }
}

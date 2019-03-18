use futures::future::{result, FutureResult};
use futures::{Async, Future, Poll};
use rusoto_core::{
    credential::{AutoRefreshingProvider, ChainProvider, ProvideAwsCredentials},
    region::Region,
    request::HttpClient,
};
use rusoto_credential::{AwsCredentials, CredentialsError};
use rusoto_sts::{StsAssumeRoleSessionCredentialsProvider, StsClient};
use std::time::Duration;

pub(crate) struct CustomCredentialProvider {
    role_arn: Option<String>,
    region: Region,
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
        //write your logic here for accessing either chainprovider or stsprovider calling credentials()
        let mut credentials = ChainProvider::new();
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
    pub fn new(role_arn: Option<String>, region: Region) -> Self {
        Self { role_arn, region }
    }
}

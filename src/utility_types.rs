use std::{fmt::Display, ops::Deref};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClientId(String);

impl From<&str> for ClientId {
    fn from(value: &str) -> Self {
        ClientId(value.to_string())
    }
}

impl From<String> for ClientId {
    fn from(value: String) -> Self {
        ClientId(value)
    }
}

impl Deref for ClientId {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for ClientId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RequestId(String);

impl From<&str> for RequestId {
    fn from(value: &str) -> Self {
        RequestId(value.to_string())
    }
}

impl From<String> for RequestId {
    fn from(value: String) -> Self {
        RequestId(value)
    }
}

impl Deref for RequestId {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Method(String);

impl Method {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for Method {
    fn from(value: &str) -> Self {
        Method(value.to_string())
    }
}

impl From<String> for Method {
    fn from(value: String) -> Self {
        Method(value)
    }
}

impl Deref for Method {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

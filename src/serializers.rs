use num_enum::TryFromPrimitive;
use serde::{Deserialize, Deserializer};
use serde::de;
use serde_json::Value;

pub fn from_number_or_string_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    T: TryFromPrimitive + TryFrom<i32>,
    D: Deserializer<'de>
{
    match Value::deserialize(deserializer)? {
        Value::String(s) => {
            let n = s.parse::<i32>().map_err(de::Error::custom)?;
            let c = T::try_from(n).map_err(|_| de::Error::custom("failed to convert from primitive"))?;
            
            Ok(Some(c))
        },
        Value::Number(num) => {
            let n = num.as_i64().ok_or_else(|| de::Error::custom("invalid number"))? as i32;
            let c = T::try_from(n).map_err(|_| de::Error::custom("failed to convert from primitive"))?;
            
            Ok(Some(c))
        },
        Value::Null => Ok(None),
        _ => Err(de::Error::custom("not a number")),
    }
}

pub fn from_number_or_string<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    T: TryFromPrimitive + TryFrom<i32>,
    D: Deserializer<'de>
{
    let number = match Value::deserialize(deserializer)? {
        Value::String(s) => {
            Ok(s.parse::<i32>().map_err(de::Error::custom)?)
        },
        Value::Number(num) => {
            Ok(num.as_i64().ok_or_else(|| de::Error::custom("invalid number"))? as i32)
        },
        _ => Err(de::Error::custom("not a number")),
    }?;
    
    T::try_from(number).map_err(|_| de::Error::custom("failed to convert from primitive"))
}
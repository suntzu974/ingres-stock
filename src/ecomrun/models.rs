use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Stock {
    #[serde(rename="supplier")]
    pub i1depot:i32,
    #[serde(rename="coderav")]
    pub chcodi: String,
    #[serde(rename="quantity")]
    pub f8qtestk: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Tarif {
    #[serde(rename="coderav")]
    pub chcodi: String,
    #[serde(rename="public")]
    pub mfpvttc: f64,
    #[serde(rename="promo")]
    pub mfpromo: f64,
    #[serde(rename="debut")]
    pub debut: i32,
    #[serde(rename="fin")]
    pub fin: i32,
    #[serde(rename="tva")]
    pub tva: f64,

}

#[derive(Debug, Serialize, Deserialize)]
pub struct Transfert {
    #[serde(rename="refcli")]
    pub order:i32,
    #[serde(rename="coderav")]
    pub chcodi: String,
    #[serde(rename="supplier")]
    pub i1depot:i32,
    #[serde(rename="quantity")]
    pub f8qtestk: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NewProducts {
    #[serde(rename="i2sfam")]
    pub i2sfam:i32,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct ResponseStock {
    #[serde(rename="stockingres")]
    pub stocks: Vec<Stock>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResponseTarif {
    #[serde(rename="tarif")]
    pub tarifs: Vec<Tarif>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Appro {
    #[serde(rename="message")]
    pub message:String,
    #[serde(rename="appro")]
    pub appro:i32,
    #[serde(rename="type")]
    pub mouvement: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResponseAppro {
    #[serde(rename="response")]
    pub appro: Vec<Appro>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Query {
    pub supplier:i32,
    pub coderav: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ArticleTarif {
    pub coderav: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QueryStock {
    pub stockingres: Vec<Query>
}
#[derive(Debug, Serialize, Deserialize)]
pub struct QueryTarif {
    pub tarif: Vec<ArticleTarif>
}


#[derive(Debug, Serialize, Deserialize)]
pub struct QueryTransfert {
    pub transfert: Vec<Transfert>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QueryNewProducts {
    pub transfert: Vec<NewProducts>
}

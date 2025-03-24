use std::sync::Arc;

use parking_lot::Mutex as SyncMutex;
use parking_lot::RwLock;
use rust_cktap::apdu::DeriveResponse;
use rust_cktap::emulator::CardEmulator;
use rust_cktap::secp256k1;
use rust_cktap::TapSigner;
use tokio::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TapSignerReaderError {
    #[error("TapSignerError: {0}")]
    TapSignerError(String),

    #[error("UnknownCardType: {0}, expected TapSigner")]
    UnknownCardType(String),

    #[error("No command")]
    NoCommand,

    #[error("Invalid pin length, must be betweeen 6 and 32, found {0}")]
    InvalidPinLength(u8),

    #[error("PIN must be numeric only, found {0}")]
    NonNumericPin(String),

    #[error("Setup is already complete")]
    SetupAlreadyComplete,

    #[error("Invalid chain code length, must be 32, found {0}")]
    InvalidChainCodeLength(u32),

    #[error("Unknown error: {0}")]
    Unknown(String),
}

type Error = TapSignerReaderError;
type Result<T, E = Error> = std::result::Result<T, E>;

// Main interface exposed to Swift
#[derive(Debug)]
pub struct TapSignerReader {
    reader: Mutex<rust_cktap::TapSigner<CardEmulator>>,
    cmd: RwLock<Option<TapSignerCmd>>,

    /// Last response from the setup process, has started, if the last response is `Complete` then the setup process is complete
    last_response: SyncMutex<Option<Arc<SetupCmdResponse>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TapSignerCmd {
    Setup(Arc<SetupCmd>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupCmd {
    pub factory_pin: String,
    pub new_pin: String,
    pub chain_code: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TapSignerResponse {
    Setup(SetupCmdResponse),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetupCmdResponse {
    ContinueFromInit(ContinueFromInit),
    ContinueFromBackup(ContinueFromBackup),
    ContinueFromDerive(ContinueFromDerive),
    Complete(Complete),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinueFromInit {
    pub continue_cmd: Arc<SetupCmd>,
    pub error: TapSignerReaderError,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinueFromBackup {
    pub backup: Vec<u8>,
    pub continue_cmd: Arc<SetupCmd>,
    pub error: TapSignerReaderError,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinueFromDerive {
    pub backup: Vec<u8>,
    pub derive_info: DeriveInfo,
    pub continue_cmd: Arc<SetupCmd>,
    pub error: TapSignerReaderError,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Complete {
    pub backup: Vec<u8>,
    pub derive_info: DeriveInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeriveInfo {
    pub master_xpub: Vec<u8>,
    pub xpub: Vec<u8>,
    pub chain_code: Vec<u8>,
}

impl TapSignerReader {
    pub async fn new(card: TapSigner<CardEmulator>, cmd: Option<TapSignerCmd>) -> Result<Self> {
        Ok(Self {
            reader: Mutex::new(card),
            cmd: RwLock::new(cmd),
            last_response: SyncMutex::new(None),
        })
    }

    pub async fn run(&self) -> Result<TapSignerResponse> {
        let cmd = self
            .cmd
            .write()
            .take()
            .ok_or(TapSignerReaderError::NoCommand)?;

        match cmd {
            TapSignerCmd::Setup(cmd) => {
                let response = self.setup(cmd).await?;
                Ok(TapSignerResponse::Setup(response))
            }
        }
    }

    /// Start the setup process
    pub async fn setup(&self, cmd: Arc<SetupCmd>) -> Result<SetupCmdResponse, Error> {
        println!("setup");
        let new_pin = cmd.new_pin.as_bytes();
        if new_pin.len() < 6 || new_pin.len() > 32 {
            return Err(TapSignerReaderError::InvalidPinLength(new_pin.len() as u8));
        }

        if !cmd.new_pin.trim().chars().all(char::is_numeric) {
            return Err(TapSignerReaderError::NonNumericPin(cmd.new_pin.to_string()));
        }

        self.init_backup_change(cmd).await
    }

    /// User started the setup process, but errored out before completing the setup, we can continue from the last step
    pub async fn continue_setup(
        &self,
        response: SetupCmdResponse,
    ) -> Result<SetupCmdResponse, Error> {
        match response {
            SetupCmdResponse::ContinueFromInit(c) => self.init_backup_change(c.continue_cmd).await,

            SetupCmdResponse::ContinueFromBackup(c) => {
                let response = self.derive_and_change(c.continue_cmd, c.backup).await;
                Ok(response)
            }

            SetupCmdResponse::ContinueFromDerive(c) => {
                let response = self.change(c.continue_cmd, c.backup, c.derive_info).await;
                Ok(response)
            }

            // already complete, just return the backup
            SetupCmdResponse::Complete(c) => Ok(SetupCmdResponse::Complete(c)),
        }
    }
}

impl TapSignerReader {
    async fn init_backup_change(&self, cmd: Arc<SetupCmd>) -> Result<SetupCmdResponse, Error> {
        println!("init_backup_change");
        let _init_response = self
            .reader
            .lock()
            .await
            .init(cmd.chain_code, &cmd.factory_pin)
            .await
            .map_err(|e| TapSignerReaderError::TapSignerError(e.to_string()))?;

        Ok(self.backup_change_xpub(cmd).await)
    }

    async fn backup_change_xpub(&self, cmd: Arc<SetupCmd>) -> SetupCmdResponse {
        let backup_response = self.reader.lock().await.backup(&cmd.factory_pin).await;

        let backup = match backup_response {
            Ok(backup) => backup.data,
            Err(e) => {
                let error = TapSignerReaderError::TapSignerError(e.to_string());
                let response = SetupCmdResponse::ContinueFromInit(ContinueFromInit {
                    continue_cmd: cmd,
                    error,
                });

                *self.last_response.lock() = Some(response.clone().into());

                return response;
            }
        };

        println!("backup complete");
        self.derive_and_change(cmd.clone(), backup).await
    }

    async fn derive_and_change(&self, cmd: Arc<SetupCmd>, backup: Vec<u8>) -> SetupCmdResponse {
        println!("derive_and_change");
        let derive_response = self
            .reader
            .lock()
            .await
            .derive(&[84, 0, 0], &cmd.factory_pin)
            .await;

        let derive = match derive_response {
            Ok(derive) => derive,
            Err(e) => {
                let error = TapSignerReaderError::TapSignerError(e.to_string());
                let response = SetupCmdResponse::ContinueFromBackup(ContinueFromBackup {
                    backup,
                    continue_cmd: cmd,
                    error,
                });

                *self.last_response.lock() = Some(response.clone().into());
                return response;
            }
        };

        println!("derive complete");
        let derive_info = derive.try_into().expect("path 84/0/0 was sent");
        self.change(cmd, backup, derive_info).await
    }

    async fn change(
        &self,
        cmd: Arc<SetupCmd>,
        backup: Vec<u8>,
        derive_info: DeriveInfo,
    ) -> SetupCmdResponse {
        println!("change");
        let change_response = self
            .reader
            .lock()
            .await
            .change(&cmd.new_pin, &cmd.factory_pin)
            .await;

        if let Err(e) = change_response {
            let error = TapSignerReaderError::TapSignerError(e.to_string());
            let response = SetupCmdResponse::ContinueFromDerive(ContinueFromDerive {
                backup,
                derive_info,
                continue_cmd: cmd,
                error,
            });

            *self.last_response.lock() = Some(response.clone().into());
            return response;
        }

        let complete = Complete {
            backup,
            derive_info,
        };

        println!("complete");
        *self.last_response.lock() = Some(SetupCmdResponse::Complete(complete.clone()).into());
        SetupCmdResponse::Complete(complete)
    }
}

impl SetupCmd {
    pub fn try_new(
        factory_pin: String,
        new_pin: String,
        chain_code: Option<Vec<u8>>,
    ) -> Result<Self, Error> {
        let chain_code = match chain_code {
            Some(chain_code) => {
                let chain_code_len = chain_code.len() as u32;
                chain_code
                    .try_into()
                    .map_err(|_| Error::InvalidChainCodeLength(chain_code_len))?
            }
            None => rust_cktap::rand_chaincode(&mut secp256k1::rand::thread_rng()),
        };

        Ok(Self {
            factory_pin,
            new_pin,
            chain_code,
        })
    }
}

impl TryFrom<DeriveResponse> for DeriveInfo {
    type Error = eyre::Report;

    fn try_from(derive: DeriveResponse) -> Result<Self, Self::Error> {
        let master_xpub = derive.master_pubkey;
        let chain_code = derive.chain_code;
        let xpub = derive
            .pubkey
            .ok_or_else(|| eyre::eyre!("expecting pubkey, got None, path must be missing"))?;

        Ok(Self {
            master_xpub,
            xpub,
            chain_code,
        })
    }
}

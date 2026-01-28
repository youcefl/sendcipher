/* Created on 2025.12.20 */
/* Copyright Youcef Lemsafer, all rights reserved. */

use std::path::PathBuf;

pub(crate) trait UploadConfiguration {
    /// URL of the server
    fn server(&self) -> &String;
    /// Maximum number of concurrent threads to use for file upload
    fn threads(&self) -> u32;
    /// Optional path of the PGP public key file
    fn pgp_public_key_path(&self) -> &Option<PathBuf>;
    /// Optional password to use for file encryption
    fn password_file(&self) -> &Option<PathBuf>;
}

pub(crate) trait DownloadConfiguration {
    fn server(&self) -> &String;
    fn threads(&self) -> u32;
    fn pgp_private_key_path(&self) -> &Option<PathBuf>;
    fn password_file(&self) -> &Option<PathBuf>;
    fn output_dir(&self) -> &PathBuf;
}


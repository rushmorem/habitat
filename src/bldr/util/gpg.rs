//
// Copyright:: Copyright (c) 2015 Chef Software, Inc.
// License:: Apache License, Version 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

use error::{BldrResult, BldrError};
use std::process::Command;
use std::fs;
use util::perm;

fn gpg_cmd() -> Command {
    let mut command = Command::new("gpg");
    command.arg("--homedir");
    command.arg("/opt/bldr/cache/gpg");
    command
}

pub fn import(status: &str, keyfile: &str) -> BldrResult<()> {
    try!(fs::create_dir_all("/opt/bldr/cache/gpg"));
    try!(perm::set_permissions("/opt/bldr/cache/gpg", "0700"));
    let output = try!(gpg_cmd()
         .arg("--import")
         .arg(keyfile)
         .output());
    match output.status.success() {
        true => println!("   {}: GPG key imported", status),
        false => {
            println!("   {}: GPG import failed:\n{}\n{}", status, String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
            return Err(BldrError::GPGImportFailed);
        },
    }
    Ok(())
}

pub fn verify(status: &str, file: &str) -> BldrResult<()> {
    let output = try!(gpg_cmd()
        .arg("--verify")
        .arg(file)
        .output());
    match output.status.success() {
        true => println!("   {}: GPG signature verified", status),
        false => {
            println!("   {}: GPG signature failed", status);
            return Err(BldrError::GPGVerifyFailed);
        },
    }
    Ok(())
}

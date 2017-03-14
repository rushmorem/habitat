// Copyright (c) 2016-2017 Chef Software Inc. and/or applicable contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use hab_net::privilege;
use hab_net::server::Envelope;
use protocol::net::{self, ErrCode};
use protocol::sessionsrv as proto;
use zmq;

use super::ServerState;
use error::Result;

pub fn account_get_id(req: &mut Envelope,
                      sock: &mut zmq::Socket,
                      state: &mut ServerState)
                      -> Result<()> {
    let msg: proto::AccountGetId = try!(req.parse_msg());
    match state.datastore.get_account_by_id(&msg) {
        Ok(Some(account)) => req.reply_complete(sock, &account)?,
        Ok(None) => {
            let err = net::err(ErrCode::ENTITY_NOT_FOUND, "ss:account-get-id:0");
            try!(req.reply_complete(sock, &err));
        }
        Err(e) => {
            error!("{}", e);
            let err = net::err(ErrCode::DATA_STORE, "ss:account-get-id:1");
            try!(req.reply_complete(sock, &err));
        }
    }
    Ok(())
}

pub fn account_get(req: &mut Envelope,
                   sock: &mut zmq::Socket,
                   state: &mut ServerState)
                   -> Result<()> {
    let msg: proto::AccountGet = try!(req.parse_msg());
    match state.datastore.get_account(&msg) {
        Ok(Some(account)) => req.reply_complete(sock, &account)?,
        Ok(None) => {
            let err = net::err(ErrCode::ENTITY_NOT_FOUND, "ss:account-get:0");
            try!(req.reply_complete(sock, &err));
        }
        Err(e) => {
            error!("{}", e);
            let err = net::err(ErrCode::DATA_STORE, "ss:account-get:1");
            try!(req.reply_complete(sock, &err));
        }
    }
    Ok(())
}

// TODO: Remove the account search once we're ready to integrate, to be replaced at the API gateway
// with calls to account_get/account_get_by_id
//
// pub fn account_search(req: &mut Envelope,
//                       sock: &mut zmq::Socket,
//                       state: &mut ServerState)
//                       -> Result<()> {
//     let mut msg: proto::AccountSearch = try!(req.parse_msg());
//     let result = match msg.get_key() {
//         proto::AccountSearchKey::Id => {
//             let value: u64 = msg.take_value().parse().unwrap();
//             state.datastore.accounts.find(&value)
//         }
//         proto::AccountSearchKey::Name => {
//             state.datastore.accounts.find_by_username(&msg.take_value())
//         }
//     };
//     match result {
//         Ok(account) => try!(req.reply_complete(sock, &account)),
//         Err(dbcache::Error::EntityNotFound) => {
//             let err = net::err(ErrCode::ENTITY_NOT_FOUND, "ss:account-search:0");
//             try!(req.reply_complete(sock, &err));
//         }
//         Err(e) => {
//             error!("{}", e);
//             let err = net::err(ErrCode::DATA_STORE, "ss:account-search:1");
//             try!(req.reply_complete(sock, &err));
//         }
//     }
//     Ok(())
// }

pub fn session_create(req: &mut Envelope,
                      sock: &mut zmq::Socket,
                      state: &mut ServerState)
                      -> Result<()> {
    let msg: proto::SessionCreate = try!(req.parse_msg());

    let mut is_admin = false;
    let mut is_builder = false;
    let mut is_build_worker = false;

    let teams = match state.github.teams(msg.get_token()) {
        Ok(teams) => teams,
        Err(e) => {
            error!("Cannot retrieve teams from github; failing: {}", e);
            let err = net::err(ErrCode::DATA_STORE, "ss:session-create:0");
            req.reply_complete(sock, &err)?;
            return Ok(());
        }
    };
    for team in teams {
        if team.id != 0 && team.id == state.admin_team {
            debug!("Granting feature flag={:?} for team={:?}",
                   privilege::ADMIN,
                   team.name);
            is_admin = true;
        }
        if team.id != 0 && state.builder_teams.contains(&team.id) {
            debug!("Granting feature flag={:?} for team={:?}",
                   privilege::BUILDER,
                   team.name);
            is_builder = true;
        }
        if team.id != 0 && state.build_worker_teams.contains(&team.id) {
            debug!("Granting feature flag={:?} for team={:?}",
                   privilege::BUILD_WORKER,
                   team.name);
            is_build_worker = true;
        }
    }
    match state.datastore.find_or_create_account_via_session(&msg,
                                                             is_admin,
                                                             is_builder,
                                                             is_build_worker) {
        Ok(session) => req.reply_complete(sock, &session)?,
        Err(e) => {
            error!("{}", e);
            let err = net::err(ErrCode::DATA_STORE, "ss:session-create:1");
            req.reply_complete(sock, &err)?;
        }
    }
    Ok(())
}

pub fn session_get(req: &mut Envelope,
                   sock: &mut zmq::Socket,
                   state: &mut ServerState)
                   -> Result<()> {
    let msg: proto::SessionGet = try!(req.parse_msg());
    match state.datastore.get_session(&msg) {
        Ok(Some(session)) => {
            try!(req.reply_complete(sock, &session));
        }
        Ok(None) => {
            let err = net::err(ErrCode::SESSION_EXPIRED, "ss:auth:4");
            try!(req.reply_complete(sock, &err));
        }
        Err(e) => {
            error!("{}", e);
            let err = net::err(ErrCode::DATA_STORE, "ss:auth:5");
            try!(req.reply_complete(sock, &err));
        }
    }
    Ok(())
}

// Determine permissions and toggle feature flags on for the given Session
// fn set_features(state: &ServerState, session: &mut proto::Session) -> Result<()> {
//     let mut flags = FeatureFlags::empty();
//     // Initialize some empty flags in case we fail to obtain teams from remote
//     session.set_flags(flags.bits());
//     let teams = try!(state.github.teams(session.get_token()));
//     for team in teams {
//         if team.id != 0 && team.id == state.admin_team {
//             debug!("Granting feature flag={:?} for team={:?}",
//                    privilege::ADMIN,
//                    team.name);
//             flags.insert(privilege::ADMIN);
//             continue;
//         }
//         if let Some(raw_flags) = state.datastore
//                .features
//                .flags(team.id)
//                .ok() {
//             for raw_flag in raw_flags {
//                 let flag = FeatureFlags::from_bits(raw_flag).unwrap();
//                 debug!("Granting feature flag={:?} for team={:?}", flag, team.name);
//                 flags.insert(flag);
//             }
//         }
//     }
//     session.set_flags(flags.bits());
//     Ok(())
// }

/* Copyright (C) 2023 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

 /// To-dos:
 /// Fix the unit tests
 /// Are the transactions being freed properly? 
 /// Are the requests and responses being handled correctly?
 ///

use super::parser;
use crate::applayer::{self, *};
use crate::core::{AppProto, Flow, ALPROTO_UNKNOWN, IPPROTO_UDP};
use nom7 as nom;
use std;
use std::collections::VecDeque;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};

static mut ALPROTO_DELTAV: AppProto = ALPROTO_UNKNOWN;

#[derive(AppLayerEvent)]
enum DeltaVEvent {}

pub struct DeltaVTransaction {
    tx_id: u64,
    pub request: Option<String>,
    pub response: Option<String>,

    tx_data: AppLayerTxData,
}

impl Default for DeltaVTransaction {
    fn default() -> Self {
        Self::new()
    }
}

impl DeltaVTransaction {
    pub fn new() -> DeltaVTransaction {
        Self {
            tx_id: 0,
            request: None,
            response: None,
            tx_data: AppLayerTxData::new(),
        }
    }
}

impl Transaction for DeltaVTransaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

#[derive(Default)]
pub struct DeltaVState {
    state_data: AppLayerStateData,
    tx_id: u64,
    transactions: VecDeque<DeltaVTransaction>,
    request_gap: bool,
    response_gap: bool,
}

impl State<DeltaVTransaction> for DeltaVState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&DeltaVTransaction> {
        self.transactions.get(index)
    }
}

impl DeltaVState {
    pub fn new() -> Self {
        Default::default()
    }

    // Free a transaction by ID.
    fn free_tx(&mut self, tx_id: u64) {
        let len = self.transactions.len();
        let mut found = false;
        let mut index = 0;
        for i in 0..len {
            let tx = &self.transactions[i];
            if tx.tx_id == tx_id + 1 {
                found = true;
                index = i;
                break;
            }
        }
        if found {
            self.transactions.remove(index);
        }
    }

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&DeltaVTransaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id + 1)
    }

    fn new_tx(&mut self) -> DeltaVTransaction {
        let mut tx = DeltaVTransaction::new();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        return tx;
    }

    fn find_request(&mut self) -> Option<&mut DeltaVTransaction> {
        self.transactions
            .iter_mut()
            .find(|tx| tx.response.is_none())
    }

    fn parse_request(&mut self, input: &[u8]) -> AppLayerResult {
        // We're not interested in empty requests.
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        // If there was gap, check we can sync up again.
        if self.request_gap {
            if probe(input).is_err() {
                // The parser now needs to decide what to do as we are not in sync.
                // For this deltav, we'll just try again next time.
                return AppLayerResult::ok();
            }

            // It looks like we're in sync with a message header, clear gap
            // state and keep parsing.
            self.request_gap = false;
        }

        let mut start = input;
        while !start.is_empty() {
            match parser::parse_message(start) {
                Ok((rem, request)) => {
                    start = rem;

                    SCLogNotice!("{}", request);
                    let mut tx = self.new_tx();
                    tx.request = Some(request);
                    self.transactions.push_back(tx);
                }
                Err(nom::Err::Incomplete(_)) => {
                    // Not enough data. This parser doesn't give us a good indication
                    // of how much data is missing so just ask for one more byte so the
                    // parse is called as soon as more data is received.
                    let consumed = input.len() - start.len();
                    let needed = start.len() + 1;
                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
                }
                Err(_) => {
                    return AppLayerResult::err();
                }
            }
        }

        // Input was fully consumed.
        return AppLayerResult::ok();
    }

    fn parse_response(&mut self, input: &[u8]) -> AppLayerResult {
        // We're not interested in empty responses.
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        if self.response_gap {
            if probe(input).is_err() {
                // The parser now needs to decide what to do as we are not in sync.
                // For this deltav, we'll just try again next time.
                return AppLayerResult::ok();
            }

            // It looks like we're in sync with a message header, clear gap
            // state and keep parsing.
            self.response_gap = false;
        }
        let mut start = input;
        while !start.is_empty() {
            match parser::parse_message(start) {
                Ok((rem, response)) => {
                    start = rem;

                    if let Some(tx) = self.find_request() {
                        tx.response = Some(response);
                        //SCLogNotice!("Found response for request:");
                        //SCLogNotice!("- Request: {:?}", tx.request);
                        SCLogNotice!("{:?}", tx.response);
                    }
                }
                Err(nom::Err::Incomplete(_)) => {
                    let consumed = input.len() - start.len();
                    let needed = start.len() + 1;
                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
                }
                Err(_) => {
                    return AppLayerResult::err();
                }
            }
        }

        // All input was fully consumed.
        return AppLayerResult::ok();
    }

    fn on_request_gap(&mut self, _size: u32) {
        self.request_gap = true;
    }

    fn on_response_gap(&mut self, _size: u32) {
        self.response_gap = true;
    }
}

/// Probe for a valid header.
/// Messages should start with 0xfa 0xce bytes (FACE) 
fn probe(input: &[u8]) -> nom::IResult<&[u8], ()> {
    // Look at the first two bytes for 0xfa 0xce
    let (rem, prefix) = nom::bytes::complete::take(2usize)(input)?;
    let (_, _) = nom::bytes::complete::tag([0xfa, 0xce])(prefix)?;
    Ok((rem, ()))
}

// C exports.

/// C entry point for a probing parser.
unsafe extern "C" fn rs_deltav_probing_parser(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    // Need at least 2 bytes (FA CE bytes + message).
    if input_len > 1 && !input.is_null() {
        let slice = build_slice!(input, input_len as usize);
        if probe(slice).is_ok() {
            return ALPROTO_DELTAV;
        }
    }
    return ALPROTO_UNKNOWN;
}

extern "C" fn rs_deltav_state_new(_orig_state: *mut c_void, _orig_proto: AppProto) -> *mut c_void {
    let state = DeltaVState::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut c_void;
}

unsafe extern "C" fn rs_deltav_state_free(state: *mut c_void) {
    std::mem::drop(Box::from_raw(state as *mut DeltaVState));
}

unsafe extern "C" fn rs_deltav_state_tx_free(state: *mut c_void, tx_id: u64) {
    let state = cast_pointer!(state, DeltaVState);
    state.free_tx(tx_id);
}

unsafe extern "C" fn rs_deltav_parse_request(
    _flow: *const Flow, state: *mut c_void, pstate: *mut c_void, stream_slice: StreamSlice,
    _data: *const c_void,
) -> AppLayerResult {
    let eof = AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) > 0;

    if eof {
        // If needed, handle EOF, or pass it into the parser.
        return AppLayerResult::ok();
    }

    let state = cast_pointer!(state, DeltaVState);

    if stream_slice.is_gap() {
        // Here we have a gap signaled by the input being null, but a greater
        // than 0 input_len which provides the size of the gap.
        state.on_request_gap(stream_slice.gap_size());
        AppLayerResult::ok()
    } else {
        let buf = stream_slice.as_slice();
        state.parse_request(buf)
    }
}

unsafe extern "C" fn rs_deltav_parse_response(
    _flow: *const Flow, state: *mut c_void, pstate: *mut c_void, stream_slice: StreamSlice,
    _data: *const c_void,
) -> AppLayerResult {
    let _eof = AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) > 0;
    let state = cast_pointer!(state, DeltaVState);

    if stream_slice.is_gap() {
        // Here we have a gap signaled by the input being null, but a greater
        // than 0 input_len which provides the size of the gap.
        state.on_response_gap(stream_slice.gap_size());
        AppLayerResult::ok()
    } else {
        let buf = stream_slice.as_slice();
        state.parse_response(buf)
    }
}

unsafe extern "C" fn rs_deltav_state_get_tx(state: *mut c_void, tx_id: u64) -> *mut c_void {
    let state = cast_pointer!(state, DeltaVState);
    match state.get_tx(tx_id) {
        Some(tx) => {
            return tx as *const _ as *mut _;
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

unsafe extern "C" fn rs_deltav_state_get_tx_count(state: *mut c_void) -> u64 {
    let state = cast_pointer!(state, DeltaVState);
    return state.tx_id;
}

unsafe extern "C" fn rs_deltav_tx_get_alstate_progress(tx: *mut c_void, _direction: u8) -> c_int {
    let tx = cast_pointer!(tx, DeltaVTransaction);

    // Transaction is done if we have a response.
    if tx.response.is_some() {
        return 1;
    }
    return 0;
}

/// Get the request buffer for a transaction from C.
///
/// No required for parsing, but an example function for retrieving a
/// pointer to the request buffer from C for detection.
#[no_mangle]
pub unsafe extern "C" fn rs_deltav_get_request_buffer(
    tx: *mut c_void, buf: *mut *const u8, len: *mut u32,
) -> u8 {
    let tx = cast_pointer!(tx, DeltaVTransaction);
    if let Some(ref request) = tx.request {
        if !request.is_empty() {
            *len = request.len() as u32;
            *buf = request.as_ptr();
            return 1;
        }
    }
    return 0;
}

/// Get the response buffer for a transaction from C.
#[no_mangle]
pub unsafe extern "C" fn rs_deltav_get_response_buffer(
    tx: *mut c_void, buf: *mut *const u8, len: *mut u32,
) -> u8 {
    let tx = cast_pointer!(tx, DeltaVTransaction);
    if let Some(ref response) = tx.response {
        if !response.is_empty() {
            *len = response.len() as u32;
            *buf = response.as_ptr();
            return 1;
        }
    }
    return 0;
}

export_tx_data_get!(rs_deltav_get_tx_data, DeltaVTransaction);
export_state_data_get!(rs_deltav_get_state_data, DeltaVState);

// Parser name as a C style string.
const PARSER_NAME: &[u8] = b"deltav\0";

#[no_mangle]
pub unsafe extern "C" fn rs_deltav_register_parser() {
    let default_port = CString::new("[18507]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_UDP,
        probe_ts: Some(rs_deltav_probing_parser),
        probe_tc: Some(rs_deltav_probing_parser),
        min_depth: 0,
        max_depth: 16,
        state_new: rs_deltav_state_new,
        state_free: rs_deltav_state_free,
        tx_free: rs_deltav_state_tx_free,
        parse_ts: rs_deltav_parse_request,
        parse_tc: rs_deltav_parse_response,
        get_tx_count: rs_deltav_state_get_tx_count,
        get_tx: rs_deltav_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: rs_deltav_tx_get_alstate_progress,
        get_eventinfo: Some(DeltaVEvent::get_event_info),
        get_eventinfo_byid: Some(DeltaVEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(applayer::state_get_tx_iterator::<DeltaVState, DeltaVTransaction>),
        get_tx_data: rs_deltav_get_tx_data,
        get_state_data: rs_deltav_get_state_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
        truncate: None,
        get_frame_id_by_name: None,
        get_frame_name_by_id: None,
    };

    let ip_proto_str = CString::new("udp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_DELTAV = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogNotice!("Rust deltav parser registered.");
    } else {
        SCLogNotice!("Protocol detector and parser disabled for DELTAV.");
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_probe() {
        assert!(probe(&[0x0]).is_err());
        assert!(probe(&[0x0, 0x1]).is_err());
        assert!(probe(&[0x0, 0x1, 0x2]).is_err());
        assert!(probe(&[0x0, 0x1, 0x2, 0x3]).is_err());
        assert!(probe(&[0xfa, 0x1, 0xce, 0x2]).is_err());
        assert!(probe(&[0x1, 0xfa, 0xce, 0x2]).is_err());
        assert!(probe(&[0xfa]).is_err());
        assert!(probe(&[0xfa, 0xce]).is_ok());
        assert!(probe(&[0xfa, 0xce, 0x1]).is_ok());
    }
}

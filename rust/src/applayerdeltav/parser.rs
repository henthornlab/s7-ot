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

use nom7::{
    bytes::streaming::{take, tag},
    number::complete::be_u16,
   IResult,
};


/// Possible to-dos: 
/// Should we even send a response for Acks?
/// code_type 6 seems to be hearbeats. We can tell controller type from heartbeat payload.
/// Setpoint changes can be parsed to determine which person made the change and to what
/// (e.g. PIT-150 increased to 100 by username)

pub fn parse_message(i: &[u8]) -> IResult<&[u8], String> {
    // We can assume the message starts with FACE bytes, since that was necessary
    // for the probe() function
    let (i, _) = tag([0xfa, 0xce])(i)?;
    // Next two bytes are the length of the message
    let (i, len) = be_u16(i)?;

    // If the message has "0" length, it's an ACK and we're done
    if len == 0 {
        let i = b"";
        let result = "DeltaV - Ack".to_string();
        Ok((i, result))
    }
    else {

        //parse the rest
        let (i, type_code) = be_u16(i)?;
        // msg_id and sender_id are not currently used but could be
        let (i, _msg_id) = be_u16(i)?;
        let (i, _sender_id) = be_u16(i)?;
        //skip ahead by 6
        let (i, _sub_msg) = take(6usize)(i)?;
        //grab the subtype_code
        let (_i, subtype_code) = be_u16(i)?;

        let mut result = String::from("DeltaV - ");
        let command_code = (type_code, subtype_code);

        match command_code {
            (0x02, 0x0304) => result.push_str("Controller Reports Alarm or New Setpoint"),
            (0x02, 0x0403) => result.push_str("Data change on controller"),
            (0x02, 0x0801) => result.push_str("Download detected!"),
            (0x02, 0x0802) => result.push_str("Controller acks download"),
            (0x02, 0x0a01) => result.push_str("Setpoint change directed"),
            (0x06, _) => result.push_str("Controller heartbeat"),
            _      => result.push_str("Unknown command"),
        }

        // i has some good information left in it, like which alarm is sounding or
        // who is changing setpoints. It could be mined in the future. 
        // But for now we are done with it.
        let i = b"";
        Ok((i, result))
    }

}


#[cfg(test)]
mod tests {
    use super::*;
    use nom7::Err;

    /// Simple test of some valid data.
    #[test]
    fn test_parse_ack() {

        const REQ: &[u8] = &[0xfa, 0xce, 0x00, 0x00,];

        let result = parse_message(REQ);
        match result {
            Ok((_, message)) => {
                // Check the first message.
                assert_eq!(message, "DeltaV - Ack");
            }
            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) | Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }

    #[test]
    fn test_parse_download() {

        const REQ: &[u8] = &[0xfa, 0xce, 0x03, 0xf2, 0x00, 0x02, 
                            0xbc, 0x95, 0x00, 0x01, 0x28, 0x40, 
                            0x54,0x80, 0x04, 0x00, 0x08, 0x01];

        let result = parse_message(REQ);
        match result {
            Ok((_, message)) => {
                // Check the first message.
                assert_eq!(message, "DeltaV - Download detected!");
            }
            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) | Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }

    #[test]
    fn test_parse_heartbeat() {

        const REQ: &[u8] = &[0xfa, 0xce, 0x03, 0xf2, 0x00, 0x06, 
                            0xbc, 0x95, 0x00, 0x01, 0x28, 0x40, 
                            0x54,0x80, 0x04, 0x00, 0x08, 0x01];

        let result = parse_message(REQ);
        match result {
            Ok((_, message)) => {
                // Check the first message.
                assert_eq!(message, "DeltaV - Controller heartbeat");
            }
            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) | Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }
}

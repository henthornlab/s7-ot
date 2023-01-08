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
    bytes::streaming::{take, take_until, tag},
    number::complete::be_u16,
//    combinator::map_res,
   IResult,
};
//use std;

pub fn parse_message(i: &[u8]) -> IResult<&[u8], String> {
    // Message starts with FACE 0xfa 0xce bytes, which was already detected in probe()
    let (i, _) = tag([0xfa, 0xce])(i)?;
    // Next two bytes are the length of the message
    let (i, len) = be_u16(i)?;

    // If the message has "0" length, it's an ACK and we're done
    if len == 0 {
        let i = b"";
        let result = "DV - Ack".to_string();
        Ok((i, result))
    }
    else {
        
        let i = b"";
        let result = "DV - Control Message".to_string();
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

        const REQ1: &[u8] = &[0xfa, 0xce, 0x00, 0x00,];

        let result = parse_message(REQ1);
        match result {
            Ok((remainder, message)) => {
                // Check the first message.
                assert_eq!(message, "DV - Ack");
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

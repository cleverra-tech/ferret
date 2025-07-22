// HPACK Huffman decode tables and functions generated from RFC 7541 Appendix B
// This implements the Huffman decoder for HTTP/2 HPACK based on Chromium's implementation.

const std = @import("std");

pub const HuffmanWord = u32;
pub const HuffmanCodeLength = u8; // Max code length is 30, so u8 is sufficient

pub const kMinCodeLength: HuffmanCodeLength = 5;
pub const kMaxCodeLength: HuffmanCodeLength = 30;

pub const kInvalidLJCode: HuffmanWord = 0xFFFFFFFF; // Sentinel value
pub const kInvalidCanonical: u8 = 255; // Sentinel value

// Length of a code in bits to the first code with that length, left-justified.
// Note that this can be computed from kLengthToFirstCanonical.
pub const kLengthToFirstLJCode = [_]HuffmanWord{
    kInvalidLJCode, // Length 0
    kInvalidLJCode, // Length 1
    kInvalidLJCode, // Length 2
    kInvalidLJCode, // Length 3
    kInvalidLJCode, // Length 4
    0x00000000, // Length 5
    0x50000000, // Length 6
    0xb8000000, // Length 7
    0xf8000000, // Length 8
    kInvalidLJCode, // Length 9
    0xfe000000, // Length 10
    0xff400000, // Length 11
    0xffa00000, // Length 12
    0xffc00000, // Length 13
    0xfff00000, // Length 14
    0xfff80000, // Length 15
    kInvalidLJCode, // Length 16
    kInvalidLJCode, // Length 17
    kInvalidLJCode, // Length 18
    0xfffe0000, // Length 19
    0xfffe6000, // Length 20
    0xfffee000, // Length 21
    0xffff4800, // Length 22
    0xffffb000, // Length 23
    0xffffea00, // Length 24
    0xfffff600, // Length 25
    0xfffff800, // Length 26
    0xfffffbc0, // Length 27
    0xfffffe20, // Length 28
    kInvalidLJCode, // Length 29
    0xfffffff0, // Length 30
};

// Maps from length of a code to the first 'canonical symbol' with that length.
pub const kLengthToFirstCanonical = [_]u8{
    kInvalidCanonical, // Length 0, 0 codes.
    kInvalidCanonical, // Length 1, 0 codes.
    kInvalidCanonical, // Length 2, 0 codes.
    kInvalidCanonical, // Length 3, 0 codes.
    kInvalidCanonical, // Length 4, 0 codes.
    0, // Length 5, 10 codes.
    10, // Length 6, 26 codes.
    36, // Length 7, 32 codes.
    68, // Length 8, 6 codes.
    kInvalidCanonical, // Length 9, 0 codes.
    74, // Length 10, 5 codes.
    79, // Length 11, 3 codes.
    82, // Length 12, 2 codes.
    84, // Length 13, 6 codes.
    90, // Length 14, 2 codes.
    92, // Length 15, 3 codes.
    kInvalidCanonical, // Length 16, 0 codes.
    kInvalidCanonical, // Length 17, 0 codes.
    kInvalidCanonical, // Length 18, 0 codes.
    95, // Length 19, 3 codes.
    98, // Length 20, 8 codes.
    106, // Length 21, 13 codes.
    119, // Length 22, 26 codes.
    145, // Length 23, 29 codes.
    174, // Length 24, 12 codes.
    186, // Length 25, 4 codes.
    190, // Length 26, 15 codes.
    205, // Length 27, 19 codes.
    224, // Length 28, 29 codes.
    kInvalidCanonical, // Length 29, 0 codes.
    253, // Length 30, 4 codes.
};

// Mapping from canonical symbol (0 to 255) to actual symbol.
pub const kCanonicalToSymbol = [_]u8{
    '0',  '1',  '2',  'a',  'c',  'e',  'i',  'o',
    's',  't',  0x20, '%',  '-',  '.',  '/',  '3',
    '4',  '5',  '6',  '7',  '8',  '9',  '=',  'A',
    '_',  'b',  'd',  'f',  'g',  'h',  'l',  'm',
    'n',  'p',  'r',  'u',  ':',  'B',  'C',  'D',
    'E',  'F',  'G',  'H',  'I',  'J',  'K',  'L',
    'M',  'N',  'O',  'P',  'Q',  'R',  'S',  'T',
    'U',  'V',  'W',  'Y',  'j',  'k',  'q',  'v',
    'w',  'x',  'y',  'z',  '&',  '*',  ',',  ';',
    'X',  'Z',  '!',  '"',  '(',  ')',  '?',  '\'',
    '+',  '|',  '#',  '>',  0x00, '$',  '@',  '[',
    ']',  '~',  '^',  '}',  '<',  '`',  '{',  '\\',
    0xc3, 0xd0, 0x80, 0x82, 0x83, 0xa2, 0xb8, 0xc2,
    0xe0, 0xe2, 0x99, 0xa1, 0xa7, 0xac, 0xb0, 0xb1,
    0xb3, 0xd1, 0xd8, 0xd9, 0xe3, 0xe5, 0xe6, 0x81,
    0x84, 0x85, 0x86, 0x88, 0x92, 0x9a, 0x9c, 0xa0,
    0xa3, 0xa4, 0xa9, 0xaa, 0xad, 0xb2, 0xb5, 0xb9,
    0xba, 0xbb, 0xbd, 0xbe, 0xc4, 0xc6, 0xe4, 0xe8,
    0xe9, 0x01, 0x87, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
    0x8f, 0x93, 0x95, 0x96, 0x97, 0x98, 0x9b, 0x9d,
    0x9e, 0xa5, 0xa6, 0xa8, 0xae, 0xaf, 0xb4, 0xb6,
    0xb7, 0xbc, 0xbf, 0xc5, 0xe7, 0xef, 0x09, 0x8e,
    0x90, 0x91, 0x94, 0x9f, 0xab, 0xce, 0xd7, 0xe1,
    0xec, 0xed, 0xc7, 0xcf, 0xea, 0xeb, 0xc0, 0xc1,
    0xc8, 0xc9, 0xca, 0xcd, 0xd2, 0xd5, 0xda, 0xdb,
    0xee, 0xf0, 0xf2, 0xf3, 0xff, 0xcb, 0xcc, 0xd3,
    0xd4, 0xd6, 0xdd, 0xde, 0xdf, 0xf1, 0xf4, 0xf5,
    0xf6, 0xf7, 0xf8, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe,
    0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0b,
    0x0c, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
    0x15, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
    0x1e, 0x1f, 0x7f, 0xdc, 0xf9, 0x0a, 0x0d, 0x16,
};

/// Returns the length (in bits) of the HPACK Huffman code that starts with
/// the high bits of `value`.
pub fn CodeLengthOfPrefix(value: HuffmanWord) HuffmanCodeLength {
    var length: HuffmanCodeLength = 0;
    if (value < 0xb8000000) {
        if (value < 0x50000000) {
            length = 5;
        } else {
            length = 6;
        }
    } else {
        if (value < 0xfe000000) {
            if (value < 0xf8000000) {
                length = 7;
            } else {
                length = 8;
            }
        } else {
            if (value < 0xffc00000) {
                if (value < 0xffa00000) {
                    if (value < 0xff400000) {
                        length = 10;
                    } else {
                        length = 11;
                    }
                } else {
                    length = 12;
                }
            } else {
                if (value < 0xfffe0000) {
                    if (value < 0xfff80000) {
                        if (value < 0xfff00000) {
                            length = 13;
                        } else {
                            length = 14;
                        }
                    } else {
                        length = 15;
                    }
                } else {
                    if (value < 0xffff4800) {
                        if (value < 0xfffee000) {
                            if (value < 0xfffe6000) {
                                length = 19;
                            } else {
                                length = 20;
                            }
                        }
                    } else {
                        if (value < 0xffffea00) {
                            if (value < 0xffffb000) {
                                length = 22;
                            } else {
                                length = 23;
                            }
                        } else {
                            if (value < 0xfffffbc0) {
                                if (value < 0xfffff800) {
                                    if (value < 0xfffff600) {
                                        length = 24;
                                    } else {
                                        length = 25;
                                    }
                                } else {
                                    length = 26;
                                }
                            } else {
                                if (value < 0xfffffff0) {
                                    if (value < 0xfffffe20) {
                                        length = 27;
                                    } else {
                                        length = 28;
                                    }
                                } else {
                                    length = 30;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return length;
}

/// Decodes the code in the high `code_length` bits of `bits` to the
/// corresponding canonical symbol.
/// Returns a value in the range [0, 256] (257 values). 256 is the EOS symbol,
/// which must not be explicitly encoded; the HPACK spec says that a decoder
/// must treat EOS as a decoding error.
pub fn DecodeToCanonical(code_length: HuffmanCodeLength, bits: HuffmanWord) HuffmanWord {
    std.debug.assert(code_length >= kMinCodeLength and code_length <= kMaxCodeLength);

    // What is the first left-justified code of length `code_length`?
    const first_lj_code = kLengthToFirstLJCode[code_length];
    std.debug.assert(first_lj_code != kInvalidLJCode);

    // Which canonical symbol corresponds to the high order `code_length`
    // bits of `first_lj_code`?
    const first_canonical = kLengthToFirstCanonical[code_length];
    std.debug.assert(first_canonical != kInvalidCanonical);

    // What is the position of the canonical symbol being decoded within
    // the canonical symbols of length `code_length`?
    const ordinal_in_length = (bits - first_lj_code) >> @intCast(32 - code_length);

    // Combined these two to produce the position of the canonical symbol
    // being decoded within all of the canonical symbols.
    return first_canonical + ordinal_in_length;
}

/// Converts a canonical symbol to the source symbol (the char in the original
/// string that was encoded).
pub fn CanonicalToSource(canonical: HuffmanWord) u8 {
    std.debug.assert(canonical < 256);
    return kCanonicalToSymbol[canonical];
}

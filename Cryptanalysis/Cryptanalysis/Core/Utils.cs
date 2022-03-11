using System;
using System.Text;
using static Cryptanalysis.Core.Constants;

namespace Cryptanalysis.Core {
    internal static class Utils {
        internal static bool IsBin(byte val)
            => val == BYTE_ZERO || val == BYTE_ONE;
        internal static bool IsBin(byte val1, byte val2)
            => (val1 == BYTE_ZERO || val1 == BYTE_ONE)
            && (val2 == BYTE_ZERO || val2 == BYTE_ONE);
        internal static bool IsUndefined(byte val)
            => val == BYTE_UNDEFINED;
        internal static bool IsBinOrUndefined(byte val) => IsBin(val) || IsUndefined(val);

        internal static (int, int)[] CreateTransitionTableSbox4(string s) {
            var table = new (int, int)[s.Length];
            var res = convertHexString(s);
            for (int i = 0; i < s.Length; i++) {
                table[i] = (i, res[i]);
            }
            return table;
        }
        internal static int[] convertHexString(string s) {
            var r = new int[s.Length];
            for (int i = 0; i < s.Length; i++) {
                r[i] = HexToByte(s[i]);
            }
            return r;
        }
        internal static byte HexToByte(char hex) {
            return char.ToUpper(hex) switch {
                HEX_0 => 0,
                HEX_1 => 1,
                HEX_2 => 2,
                HEX_3 => 3,
                HEX_4 => 4,
                HEX_5 => 5,
                HEX_6 => 6,
                HEX_7 => 7,
                HEX_8 => 8,
                HEX_9 => 9,
                HEX_A => 10,
                HEX_B => 11,
                HEX_C => 12,
                HEX_D => 13,
                HEX_E => 14,
                HEX_F => 15,
                _ => 255,
            };
        }
        internal static Random RAND = new();
        internal static byte[] GetRndKey(int len) {
            var key = new byte[len];
            for (int i = 0; i < len; i++) {
                key[i] = (byte)RAND.Next(0, 2);
            }
            return key;
        }
        internal static string GetHyphens(int len) {
            if (len < 1)
                return "-";
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < len; i++) {
                sb.Append('-');
            }
            return sb.ToString();
        }
        internal static byte[] ConvertToBinary(int a, int binLength) {
            var r = new byte[binLength];
            var s = Convert.ToString(a, 2);
            if (s.Length > binLength)
                throw new ArgumentException("The binary representation of input int32 is longer than given binLength");
            for (int i = 0; i < binLength; i++)
                r[i] = 0;
            for (int i = s.Length - 1; i >= 0; i--)
                r[i + r.Length - s.Length] = Convert.ToByte(s[i].ToString());
            return r;
        }
        internal static byte[] ConvertToByteArr(string str) {
            var r = new byte[str.Length];
            for (int i = 0; i < str.Length; i++)
                r[i] = Convert.ToByte(str[i].ToString());
            return r;
        }
    }
}

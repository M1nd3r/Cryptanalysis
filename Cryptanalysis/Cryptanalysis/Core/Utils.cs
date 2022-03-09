using System;
using System.Text;
using static Cryptanalysis.Core.Constants;

namespace Cryptanalysis.Core {
    internal static class Utils {
        internal static bool IsBin(byte val)
            => val == BYTE_ZERO || val == BYTE_ONE;
        internal static bool IsBin(byte val1,byte val2)
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
            switch (char.ToUpper(hex)) {
                case HEX_0:
                    return 0;
                case HEX_1:
                    return 1;
                case HEX_2:
                    return 2;
                case HEX_3:
                    return 3;
                case HEX_4:
                    return 4;
                case HEX_5:
                    return 5;
                case HEX_6:
                    return 6;
                case HEX_7:
                    return 7;
                case HEX_8:
                    return 8;
                case HEX_9:
                    return 9;
                case HEX_A:
                    return 10;
                case HEX_B:
                    return 11;
                case HEX_C:
                    return 12;
                case HEX_D:
                    return 13;
                case HEX_E:
                    return 14;
                case HEX_F:
                    return 15;
                default:
                    return 255;
            }
        }
        internal static Random RAND = new Random(); 
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
                sb.Append("-");
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
            for (int i = s.Length-1; i >= 0; i--)
                r[i+r.Length-s.Length] = Convert.ToByte(s[i].ToString());
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

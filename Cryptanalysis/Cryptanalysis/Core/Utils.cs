using System;
using System.Collections.Generic;
using System.Text;
using Cryptanalysis.Experiments;
using static Cryptanalysis.Core.Constants;

namespace Cryptanalysis.Core {

    internal static class Utils {
        internal static Random RAND = new Random();

        internal static byte And(byte a, byte b) {
            if (a == 1 && b == 1)
                return 1;
            return 0;
        }

        internal static byte[] ANDs(byte[] arr1, byte[] arr2)
            => OperationOnByteArrs(arr1, arr2, And);

        internal static bool CompareArrValues(byte[] a, byte[] b) {
            if (b.Length != a.Length)
                return false;
            for (int i = 0; i < a.Length; i++) {
                if (a[i] != b[i])
                    return false;
            }
            return true;
        }

        internal static int[] ConvertHexString(string s) {
            var r = new int[s.Length];
            for (int i = 0; i < s.Length; i++) {
                r[i] = HexToByte(s[i]);
            }
            return r;
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

        internal static int ConvertToInt(byte[] binaryArr) {
            int
                r = 0,
                increment = 1;
            for (int i = binaryArr.Length - 1; i >= 0; i--) {
                if (binaryArr[i] == 1)
                    r += increment;
                increment *= 2;
            }
            return r;
        }

        internal static byte[] CreateCopy(byte[] arr) {
            byte[] x = new byte[arr.Length];
            Array.Copy(arr, x, arr.Length);
            return x;
        }

        internal static (int, int)[] CreateTransitionTableSbox4(string s) {
            if (s.Length != 16)
                throw new ArgumentException("The string does not define bijective sbox");
            var table = new (int, int)[s.Length];
            var res = ConvertHexString(s);
            for (int i = 0; i < s.Length; i++) {
                table[i] = (i, res[i]);
            }
            return table;
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

        internal static byte[] GetPolynomialForLFSR(int[] nonZeroCoeficients) {
            for (int i = 0; i < nonZeroCoeficients.Length; i++) {
                if (nonZeroCoeficients[i] < 0)
                    throw new ArgumentException("Degree of every term must be non-negative!", nameof(nonZeroCoeficients));
            }
            int degree = 0;
            for (int i = 0; i < nonZeroCoeficients.Length; i++) {
                if (nonZeroCoeficients[i] > degree)
                    degree = nonZeroCoeficients[i];
            }

            VerifyMaxDegreeIsNotTooBig(degree);
            byte[] func = new byte[degree];

            for (int i = 1; i < nonZeroCoeficients.Length; i++) {
                func[nonZeroCoeficients[i] - 1] = 1;
            }
            return func;
        }

        internal static byte[] GetRndInput(int len) => GetRndKey(len);

        internal static byte[] GetRndKey(int len) {
            var key = new byte[len];
            for (int i = 0; i < len; i++) {
                key[i] = (byte)RAND.Next(0, 2);
            }
            return key;
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

        internal static double CheckSimilarity(byte[] a, byte[] b, List<int> validPoints = null) {
            int t = 0;
            if (validPoints == null || validPoints.Count == 0) {
                for (int i = 0; i < Math.Min(a.Length, b.Length); i++) {
                    if (a[i] == b[i])
                        t++;
                }
                return t / (double)Math.Min(a.Length, b.Length);
            }
            foreach (var validPoint in validPoints) {
                if (a[validPoint] == b[validPoint])
                    t++;
            }
            return t / (double)validPoints.Count;
        }

        internal static (int source, int target)[] Invert(this (int source, int target)[] table) {
            (int source, int target)[] r = new (int, int)[table.Length];
            for (int i = 0; i < table.Length; i++)
                r[i] = (table[i].target, table[i].source);
            return r;
        }

        internal static bool IsBin(byte val)
            => val is BYTE_ZERO || val is BYTE_ONE;

        internal static bool IsBin(byte val1, byte val2)
            => (val1 == BYTE_ZERO || val1 == BYTE_ONE)
            && (val2 == BYTE_ZERO || val2 == BYTE_ONE);

        internal static bool IsBinOrUndefined(byte val) => IsBin(val) || IsUndefined(val);

        internal static bool IsUndefined(byte val)
                    => val == BYTE_UNDEFINED;

        internal static byte Mult(byte[] arr1, byte[] arr2) {
            var x = ANDs(arr1, arr2);
            byte r = 0;
            foreach (var b in x)
                r = Xor(r, b);
            return r;
        }

        internal static byte Neg(byte a) {
            if (a == 1)
                return 0;
            return 1;
        }

        internal static byte[] OperationOnByteArrs(byte[] arr1, byte[] arr2, Func<byte, byte, byte> byteOperation) {
            if (arr1 == null)
                throw new ArgumentNullException(nameof(arr1));
            if (arr2 == null)
                throw new ArgumentNullException(nameof(arr2));
            if (arr1.Length != arr2.Length)
                throw new ArgumentException("Arrays are not the same length!");

            var arr = new byte[arr1.Length];
            for (int i = 0; i < arr.Length; i++)
                arr[i] = byteOperation(arr1[i], arr2[i]);
            return arr;
        }

        internal static int[] ParseParmutationTable(string s, char separator = ',') {
            //TODO - missing validity check
            var nums = s.Split(separator);
            var table = new int[nums.Length];
            for (int i = 0; i < nums.Length; i++)
                table[i] = int.Parse(nums[i]);
            return table;
        }

        internal static void PrintKeys(Cipher cipher, IPrinter printer) {
            var keys = AttackUtils.GetKeys(cipher);
            for (int i = 0; i < keys.Count; i++) {
                printer.Write("key_" + i.ToString() + ": ");
                printer.WriteLine(keys[i]);
            }
        }

        internal static void SetPrinter(List<AChanger> l, IPrinter pr) {
            foreach (var gate in l)
                gate.SetPrinter(pr);
        }

        internal static byte Xor(byte a, byte b) {
            if (a == 0 && b == 0)
                return 0;
            if (a == 1 && b == 1)
                return 0;
            if (a == 1 && b == 0)
                return 1;
            if (a == 0 && b == 1)
                return 1;
            throw new ArgumentException("At least one of the arguments is not zero or one!");
        }

        internal static byte[] XORs(byte[] arr1, byte[] arr2)
            => OperationOnByteArrs(arr1, arr2, Xor);

        private static void VerifyMaxDegreeIsNotTooBig(int degree) {
            int limit = 100000;
            if (degree > limit)
                throw new ArgumentException("Highest degree must be smaller then " + limit.ToString());
        }
    }
}

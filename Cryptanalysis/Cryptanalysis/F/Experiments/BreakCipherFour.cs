using System;
using System.Collections.Generic;
using Cryptanalysis.Core;
using Cryptanalysis.F.Common;
using Cryptanalysis.F.Core;
using static Cryptanalysis.Core.DefaultCiphers;
using static Cryptanalysis.Core.Utils;
using static Cryptanalysis.F.Core.Verifiers;

namespace Cryptanalysis.F.Experiments {

    internal static partial class Attacks {
        public static int cipherFourFailCounter;

        public static int cipherFourSuccessCounter;

        private static readonly byte[][] filter = new byte[4][];

        public static void BreakCipherFour() {
            int precision = 5000; //Negative number - all pairs, otherwise determines number of pairs

            var mainPrinter = new ConsolePrinter();
            var verbosePrinter = new DummyPrinter();
            var cipherFour = GetCipherFour(verbosePrinter);
            PrintKeys(cipherFour, mainPrinter);

            //Hardcoded difference
            string diff = "0000000000100000";
            byte[] diff_byte = ConvertToByteArr("0000000000100000");

            //Preparing test pairs, keys, end-of-the-cipher parts
            var allDiffs = GenerateKeyPairsWithGivenDifference(diff, precision);

            var sbox = DefaultFlowChangers.GetSbox4_1();

            var sboxRow = new Sbox4x4(sbox);

            var possibleKeyParts = GenerateAllPossibleKeys(4);
            var possibleKeys = FillZerosBeforeAndAfter(8, 4, possibleKeyParts);
            int[] score = new int[possibleKeys.Count];

            var allCiphertetxs = new List<(byte[] c1, byte[] c2)>();

            //Filtering
            mainPrinter.WriteLine("Start of Filtering ");
            InitializeFiltering();
            foreach (var (a, b) in allDiffs) {
                var c1 = cipherFour.Encode(a);
                var c2 = cipherFour.Encode(b);
                if (!Filtering(c1, c2))
                    allCiphertetxs.Add((c1, c2));
            }
            //Filtering results print
            {
                mainPrinter.WriteLine("Filtering done");

                int
                    a = allDiffs.Count,
                    b = allCiphertetxs.Count;
                mainPrinter.Write("Filtered " + (a - b).ToString() + " out of " + a + " (");
                mainPrinter.WriteLine(((a - b) * 100 / a).ToString() + " %)");
                mainPrinter.WriteLine("Remains to test: " + b.ToString() + "\n");
            }
            //Trying all keys
            for (int i = 0; i < possibleKeys.Count; i++) {
                foreach (var (c1, c2) in allCiphertetxs) {
                    var d1 = XORs(possibleKeys[i], c1);
                    var d2 = XORs(possibleKeys[i], c2);
                    sboxRow.ApplyInverse(ref d1);
                    sboxRow.ApplyInverse(ref d2);
                    if (AreEqual(diff_byte, XORs(d1, d2)))
                        score[i]++;
                }
                mainPrinter.Write("key with part ");
                mainPrinter.Write(possibleKeyParts[i]);
                mainPrinter.WriteLine(": " + score[i]);
            }

            //Getting maximal value of the array
            int t = 0, index = 0;
            for (int i = 0; i < score.Length; i++) {
                if (score[i] > t) {
                    t = score[i];
                    index = i;
                }
            }

            //Printing result - most probable key part
            mainPrinter.Write("Expected key part result is: ");
            mainPrinter.WriteLine(possibleKeyParts[index]);

            //Comparation with real keys
            var realKeys = GetKeys(cipherFour);
            if (IsThirdPartTheSame(realKeys[5], possibleKeys[index])) {
                mainPrinter.WriteLine("Success! Key part correctly guessed.");
                cipherFourSuccessCounter++;
            }
            else {
                mainPrinter.WriteLine("Failed! Key parts are different.");
                cipherFourFailCounter++;
            }
            mainPrinter.WriteLine(GetHyphens(38) + "\n");
        }

        public static void BreakCipherFourRepeatedly(int numberOfIterations) {
            cipherFourFailCounter = 0;
            cipherFourSuccessCounter = 0;
            for (int i = 0; i < numberOfIterations; i++)
                BreakCipherFour();
            IPrinter p = new ConsolePrinter();
            int hyp = 15;
            p.WriteLine(GetHyphens(hyp));
            p.WriteLine("Total succ: " + cipherFourSuccessCounter.ToString());
            p.WriteLine("Total fail: " + cipherFourFailCounter.ToString());
            p.WriteLine(GetHyphens(hyp));
        }

        private static IList<byte[]> FillZerosBeforeAndAfter(int before, int after, IList<byte[]> inputList) {
            var list = new List<byte[]>();
            int added = before + after;
            foreach (var arr in inputList) {
                byte[] t = new byte[added + arr.Length];
                for (int i = 0; i < arr.Length; i++) {
                    t[before + i] = arr[i];
                }
                list.Add(t);
            }
            return list;
        }

        private static bool Filtering(byte[] c1, byte[] c2) {
            for (int i = 0; i < filter.Length; i++) {
                if (AreEqual(filter[i], XORs(c1, c2)))
                    return false;
            }
            return true;
        }

        private static IList<byte[]> GenerateAllPossibleKeys(int length) {
            if (length <= 0)
                throw new ArgumentException("Length cannot be less than one.");
            if (length >= 29)
                throw new ArgumentException("This length is too big, it is not supported.");
            int total = (int)Math.Pow(2, length);
            var list = new List<byte[]>();
            for (int i = 0; i < total; i++)
                list.Add(ConvertToBinary(i, length));
            return list;
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="diff">Desired difference of bit strings.</param>
        /// <param name="total">Total number of pairs. If negative, all possible pairs will be generated</param>
        /// <returns>List of all possible pairs with given difference</returns>
        private static IList<(byte[] a, byte[] b)> GenerateKeyPairsWithGivenDifference(string diff, int total = 0) {
            if (diff == null)
                throw new ArgumentNullException(nameof(diff));

            int length = diff.Length;
            if (total <= 0)
                total = (int)Math.Pow(2, length);

            var list = new List<(byte[] a, byte[] b)>();
            byte[] diff_byte = ConvertToByteArr(diff);

            //TODO - Not efficient, all pairs are doubled (i.e. for each (t1,t2) there is also (t2,t1) generated
            for (int i = 0; i < total; i++) {
                byte[] t1 = ConvertToBinary(i, length);
                byte[] t2 = XORs(t1, diff_byte);
                list.Add((t1, t2));
            }
            return list;
        }

        private static void InitializeFiltering() {
            filter[0] = ConvertToByteArr("0000000000010000");
            filter[1] = ConvertToByteArr("0000000000100000");
            filter[2] = ConvertToByteArr("0000000010010000");
            filter[3] = ConvertToByteArr("0000000010100000");
        }

        private static bool IsThirdPartTheSame(byte[] key1, byte[] key2) {
            for (int i = 8; i < 12; i++) {
                if (key1[i] != key2[i])
                    return false;
            }
            return true;
        }
    }
}

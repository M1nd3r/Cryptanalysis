using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Cryptanalysis.Core;
using static Cryptanalysis.Core.DefaultCiphers;
using static Cryptanalysis.Core.Utils;
using static Cryptanalysis.Experiments.Analysis;
using static Cryptanalysis.Experiments.AttackUtils;

namespace Cryptanalysis.Experiments {

    internal class AttackOnCipherA : Attack {

        public override bool BreakCipher() => BreakCipherA(16);

        public bool BreakCipherA(int totalPlaintexts) {
            SetMainPrinter(new ConsolePrinter());
            SetVerbosePrinter(new DummyPrinter());
            SetCipher(GetCipherA(verbosePrinter));

            var masks = GetSBoxMasksForCipherA();
            var plaintexts = GetPlaintexts(totalPlaintexts, 4);
            var ciphertexts = GetCiphertexts(cipher, in plaintexts);

            PrintKeys();

            var key = IdentifyAndGetKey(plaintexts, ciphertexts, masks);
            PrintRecoveredKeys(mainPrinter, key);
            return CompareKeysAndHandleResult(cipher, key, mainPrinter);
        }

        public void BreakCipherAHundredTimes()
            => BreakCipherRepeatedly(100);

        private static bool CompareKeysAndHandleResult(Cipher cipher, byte[] guess, IPrinter printer) {
            var succ = CompareKeysCipherA(GetKeys(cipher), guess);
            printer.WriteLine(GetSuccessOrFailString(succ));
            return succ;
        }

        private static bool CompareKeysCipherA(List<byte[]> realKeys, byte[] guess) {
            for (int i = 0; i < 4; i++) {
                if (realKeys[0][i] != guess[i])
                    return false;
                if (realKeys[1][i] != guess[i + 4])
                    return false;
            }
            return true;
        }

        private static byte GetAddValueFromProbability(int prob) {
            if (prob < 8)
                return 1;
            return 0;
        }

        private static byte[][] GetCiphertexts(Cipher c, in byte[][] plaintexts) {
            var r = new byte[plaintexts.GetLength(0)][];
            for (int i = 0; i < plaintexts.GetLength(0); i++) {
                byte[] t = new byte[plaintexts[i].Length];
                Array.Copy(plaintexts[i], t, t.Length);
                r[i] = c.Encode(t);
            }
            return r;
        }

        private static int GetChangeOfCounter(byte resultOfMultiplication) {
            if (resultOfMultiplication == 0)
                return -1;
            else if (resultOfMultiplication == 1)
                return +1;
            throw new ArgumentException("Argument should be 0 or 1", nameof(resultOfMultiplication));
        }

        private static byte[] GetPlaintext(int length, int index)
            => ConvertToBinary(index, length);

        private static byte[][] GetPlaintexts(int total, int length) {
            var r = new byte[total][];
            for (int i = 0; i < total; i++)
                r[i] = GetPlaintext(length, i);
            return r;
        }

        private static byte GetResultBit(MaskProbability mp, byte[][] plaintexts, byte[][] ciphertexts) {
            var mask1 = mp.Mask.SubArray(0, 4);
            var mask2 = mp.Mask.SubArray(4, 4);
            int counter = 0;

            for (int i = 0; i < plaintexts.GetLength(0); i++) {
                var mul1 = Mult(mask1, plaintexts[i]);
                var mul2 = Mult(mask2, ciphertexts[i]);
                var x = Xor(mul1, mul2);
                counter += GetChangeOfCounter(x);
            }

            byte add = GetAddValueFromProbability(mp.Probability);
            if (counter > 0)
                return Xor(1, add);
            return Xor(0, add);
        }

        private static List<MaskProbability> GetSBoxMasksForCipherA() {
            var masks = GetSboxMasks(Cryptanalysis.Core.DefaultFlowChangers.GetSbox4_A());
            masks.Sort(new ProbabilityComparatorA());
            return masks;
        }

        private static byte[] IdentifyAndGetKey(byte[][] plaintexts, byte[][] ciphertexts, List<MaskProbability> masks) {
            var solutions = new List<Solution>();
            for (int i = 0; i < masks.Count; i++) {
                byte result = GetResultBit(masks[i], plaintexts, ciphertexts);
                solutions.Add(new Solution(masks[i].Mask, result));
                if (Solver.TrySolve(solutions, out byte[] key))
                    return key;
            }
            throw new Exception("Key not found!"); //Should not happen
        }

        // Heuristically, 7 plaintexts is enough.
        private static void PrintRecoveredKeys(IPrinter p, byte[] keys) {
            p.WriteLine("Discovered keys:");
            p.WriteLine(keys.SubArray(0, 4));
            p.WriteLine(keys.SubArray(4, 4));
        }

        private class ProbabilityComparatorA : IComparer<MaskProbability> {

            public int Compare([AllowNull] MaskProbability x, [AllowNull] MaskProbability y) {
                int
                    X = (x.Probability - 8) * (x.Probability - 8),
                    Y = (y.Probability - 8) * (y.Probability - 8);
                if (X < Y)
                    return 1;
                if (X > Y)
                    return -1;
                return 0;
            }
        }
    }
}

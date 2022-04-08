using System;
using System.Collections.Generic;
using Cryptanalysis.F.Core;
using static Cryptanalysis.Core.DefaultCiphers;
using static Cryptanalysis.Core.Utils;

namespace Cryptanalysis.F.Experiments {

    internal static partial class Attacks {

        public static void BreakCipherA(int totalPlaintexts) {
            var mainPrinter = new ConsolePrinter();
            var verbosePrinter = new ConsolePrinter();
            var cipherA = GetCipherA(verbosePrinter);
            PrintKeys(cipherA, mainPrinter);
            var masks = Analysis.GetSboxMasks(Cryptanalysis.Core.DefaultFlowChangers.GetSbox4_A());
            masks.Sort();
            byte[] key = null; //Null is assigned to supress error when comparing keys
            var solutions = new List<Solution>();

            var plaintexts = GetPlaintexts(totalPlaintexts, 4);
            var ciphertexts = GetCiphertexts(cipherA, in plaintexts);

            for (int i = 0; i < masks.Count; i++) {
                //Solve over given mask / all plaintexts and ciphertext  pairs
                //    -> get resulting bit for the given mask
                byte result = 2; //TODO - change to meaningful value

                solutions.Add(new Solution(masks[i].Mask, result));
                if (Solver.TrySolve(solutions, out key))
                    break;
            }
            if (CompareKeysCipherA(GetKeys(cipherA), key))
                mainPrinter.WriteLine("Succes!");
            else
                mainPrinter.WriteLine("Fail");
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

        private static byte[][] GetCiphertexts(Cipher c, in byte[][] plaintexts) {
            var r = new byte[plaintexts.GetLength(0)][]; //TODO test if dim 0 or dim 1
            for (int i = 0; i < plaintexts.GetLength(0); i++) {
                byte[] t = new byte[plaintexts[i].Length];
                Array.Copy(plaintexts[i], t, t.Length);
                r[i] = c.Encode(t);
            }
            return r;
        }

        private static byte[] GetPlaintext(int length) {
            var r = new byte[length];
            for (int i = 0; i < length; i++)
                r[i] = (byte)RAND.Next(0, 2);
            return r;
        }

        private static byte[][] GetPlaintexts(int total, int length) {
            var r = new byte[total][];
            for (int i = 0; i < total; i++)
                r[i] = GetPlaintext(length);
            return r;
        }
    }
}

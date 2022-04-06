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
            byte[] key = null; //Null assigned to supress error when comparing keys
            var solutions = new List<Solution>();

            for (int i = 0; i < totalPlaintexts; i++) {
                //TODO - Get array of chosen plaintexts and resulting ciphertexts
            }

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
    }
}

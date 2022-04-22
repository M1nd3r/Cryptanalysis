using System;
using System.Collections.Generic;
using Cryptanalysis.F.Common;
using Cryptanalysis.F.Core;
using static Cryptanalysis.Core.Utils;
using static Cryptanalysis.F.Core.Verifiers;

namespace Cryptanalysis.F.Experiments {

    internal static partial class Attacks {

        public static void BreakCipherRepeatedly(int numberOfIterations, Action breakCipher) {
            int
                cipherFailCounter = 0,
                cipherSuccessCounter = 0;
            for (int i = 0; i < numberOfIterations; i++) {
                breakCipher();
                if (succ == true)
                    cipherSuccessCounter++;
                if (succ == false)
                    cipherFailCounter++;
            }
            IPrinter p = new ConsolePrinter();
            int hyp = 15;
            p.WriteLine(GetHyphens(hyp));
            p.WriteLine("Total succ: " + cipherSuccessCounter.ToString());
            p.WriteLine("Total fail: " + cipherFailCounter.ToString());
            p.WriteLine(GetHyphens(hyp));
        }

        internal static List<byte[]> GetKeys(Cipher cipher) {
            List<AChanger> listRefl =
                ((List<AChanger>)cipher.GetType()
                .GetField(
                    "changers",
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
                .GetValue(cipher)).FindAll(x => x is XORwithKey);
            List<byte[]> ret = new List<byte[]>();
            foreach (var xorKey in listRefl) {
                var key = (byte[])xorKey.GetType().GetField("key", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance).GetValue(xorKey);
                ret.Add(key);
            }
            return ret;
        }

        private static bool NotContains(this IList<byte[]> list, byte[] value) {
            foreach (var item in list) {
                if (AreEqual(item, value))
                    return false;
            }
            return true;
        }
    }
}

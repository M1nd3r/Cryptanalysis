using System.Collections.Generic;
using Cryptanalysis.Core;
using static Cryptanalysis.Core.DefaultCiphers;
using static Cryptanalysis.Core.Utils;
using static Cryptanalysis.Core.Verifiers;

namespace Cryptanalysis.Experiments {

    internal class AttackOnCipherOne : Attack {

        public override bool BreakCipher() {
            SetMainPrinter(new ConsolePrinter());
            SetVerbosePrinter(new DummyPrinter());
            SetCipher(GetCipherOne(verbosePrinter));
            PrintKeys();

            var sbox = DefaultFlowChangers.GetSbox4_1();
            List<byte[]> candK1 = null;
            byte[]
                input1 = null,
                input2,
                output1 = null,
                output2;
            while (candK1 == null || candK1.Count > 1) {
                var candK1Temp = new List<byte[]>();
                input1 = GetRndInput(4);
                input2 = GetRndInput(4);
                while (AreEqual(input1, input2))
                    input2 = GetRndInput(4);

                verbosePrinter.Write("Input_1: ");
                verbosePrinter.WriteLine(input1);
                output1 = cipher.Encode(input1);
                verbosePrinter.Write("Output_1: ");
                verbosePrinter.WriteLine(output1);
                verbosePrinter.WriteLine("");

                verbosePrinter.Write("Input_2: ");
                verbosePrinter.WriteLine(input2);
                output2 = cipher.Encode(input2);
                verbosePrinter.Write("Output_2: ");
                verbosePrinter.WriteLine(output2);
                verbosePrinter.WriteLine("");

                var diff = XORs(input1, input2);
                verbosePrinter.Write("Input diff: ");
                verbosePrinter.WriteLine(diff);

                for (int i = 0; i < 16; i++) {
                    var t = ConvertToBinary(i, 4);
                    byte[]
                        val1 = XORs(t, output1),
                        val2 = XORs(t, output2);
                    sbox.ApplyInverse(ref val1);
                    sbox.ApplyInverse(ref val2);
                    if (AreEqual(XORs(val1, val2), diff))
                        candK1Temp.Add(t);
                }
                foreach (var item in candK1Temp) {
                    verbosePrinter.Write("key_1 candidate from this round: ");
                    verbosePrinter.WriteLine(item);
                }
                verbosePrinter.WriteLine(GetHyphens(18));
                if (candK1 == null)
                    candK1 = candK1Temp;
                else {
                    var x = candK1Temp;
                    candK1.RemoveAll(candK1Temp.NotContains);
                }
            }
            if (candK1.Count != 1) {
                verbosePrinter.WriteLine("Failure! No key candidate was found!");
                return false;
            }

            var key1 = candK1[0];
            byte[] key0_part = XORs(output1, key1);
            sbox.ApplyInverse(ref key0_part);
            var key0 = XORs(input1, key0_part);
            mainPrinter.Write("Result: key_0=");
            mainPrinter.WriteLine(key0);
            mainPrinter.Write("Result: key_1=");
            mainPrinter.WriteLine(key1);

            return true;
        }
    }
}

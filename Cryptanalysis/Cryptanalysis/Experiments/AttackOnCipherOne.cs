using System.Collections.Generic;
using Cryptanalysis.Common;
using Cryptanalysis.Core;
using static Cryptanalysis.Core.DefaultCiphers;
using static Cryptanalysis.Core.Utils;
using static Cryptanalysis.Core.Verifiers;

namespace Cryptanalysis.Experiments {

    internal class AttackOnCipherOne : Attack {

        private byte[]
            output1 = null,
            output2,
            input1 = null,
            input2;

        private Sbox4 sbox;

        public override bool BreakCipher() {
            SetMainPrinter(new ConsolePrinter());
            SetVerbosePrinter(new DummyPrinter());
            SetCipher(GetCipherOne(verbosePrinter));
            SetSBox();
            PrintKeys();

            List<byte[]> candK1 = null;
            while (candK1 == null || candK1.Count > 1) {
                var candK1Temp = new List<byte[]>();
                GetTwoDistinctRandomInputs();
                ComputeOutputs();

                PrintInputsAndOutputs();

                var diff = XORs(input1, input2);
                PrintTextAndArr("Input diff: ", diff);

                AttackRound(diff, ref candK1Temp);
                foreach (var item in candK1Temp)
                    PrintTextAndArr("key_1 candidate from this round: ", item);

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
            PrintResultKeys(key0, key1);
            return true;
        }

        private void AttackRound(byte[] inputDiff, ref List<byte[]> candidate) {
            for (int i = 0; i < 16; i++) {
                var t = ConvertToBinary(i, 4);
                byte[]
                    val1 = XORs(t, output1),
                    val2 = XORs(t, output2);
                sbox.ApplyInverse(ref val1);
                sbox.ApplyInverse(ref val2);
                if (AreEqual(XORs(val1, val2), inputDiff))
                    candidate.Add(t);
            }
        }

        private void ComputeOutputs() {
            output1 = cipher.Encode(input1);
            output2 = cipher.Encode(input2);
        }

        private void GetTwoDistinctRandomInputs() {
            input1 = GetRndInput(4);
            input2 = GetRndInput(4);
            while (AreEqual(input1, input2))
                input2 = GetRndInput(4);
        }

        private void PrintEmptyLine()
            => verbosePrinter.WriteLine("");

        private void PrintInput(byte[] input, int id)
            => PrintTextAndArr(string.Format("Input_{0}: ", id), input);

        private void PrintInputsAndOutputs() {
            PrintInput(input1, 1);
            PrintOutput(output1, 1);
            PrintEmptyLine();
            PrintInput(input2, 2);
            PrintOutput(output2, 2);
        }

        private void PrintOutput(byte[] output, int id)
            => PrintTextAndArr(string.Format("Output_{0}: ", id), output);

        private void PrintResultKeys(byte[] key0, byte[] key1) {
            mainPrinter.Write("Result: key_0=");
            mainPrinter.WriteLine(key0);
            mainPrinter.Write("Result: key_1=");
            mainPrinter.WriteLine(key1);
        }

        private void PrintTextAndArr(string text, byte[] arr) {
            verbosePrinter.Write(text);
            verbosePrinter.WriteLine(arr);
        }

        private void SetSBox()
            => sbox = DefaultFlowChangers.GetSbox4_1();
    }
}

using System.Collections.Generic;
using Cryptanalysis.F.Common;
using Cryptanalysis.F.Core;
using static Cryptanalysis.Core.Utils;
namespace Cryptanalysis.F.Experiments {
    static class Attacks {
        public static void BreakCipherFour() {
            var consolePrint = new ConsolePrinter();
            var dummyPrint = new DummyPrinter();
            var printerUsed = consolePrint;

            //Definition of cipher elements
            var keys_byte = new byte[6][];
            keys_byte[0] = ConvertToBinary(23442, 16);
            keys_byte[1] = ConvertToBinary(1611, 16);
            keys_byte[2] = ConvertToBinary(7683, 16);
            keys_byte[3] = ConvertToBinary(42335, 16);
            keys_byte[4] = ConvertToBinary(60605, 16);
            keys_byte[5] = ConvertToBinary(31909, 16);

            var keys = new XORwithKey[6]; //TODO fill in Values
            for (int i = 0; i < keys.Length; i++)
                keys[i] = new XORwithKey(keys_byte[i]);
            var perm = new Permutation(ParseParmutationTable("0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15"));
            var sbox = new Sbox4(CreateTransitionTableSbox4("64C5072E1F3D8A9B"));
            sbox.SetPrinter(printerUsed);
            var sboxRow = new Sbox4x4(sbox);

            List<AChanger> l = new List<AChanger>();
            for (int i = 0; i < 4; i++) {
                l.Add(keys[i]);
                l.Add(sboxRow);
                l.Add(perm);
            }
            l.Add(keys[4]);
            l.Add(sboxRow);
            l.Add(keys[5]);
            SetPrinter(l, printerUsed);

            Cipher cipherFour = new Cipher(l);

            var input = ConvertToByteArr("0001001000110100");
            var res = cipherFour.Encode(input);
            consolePrint.WriteLine(res);
            var ser = cipherFour.Decode(res);
            consolePrint.WriteLine(ser);
            consolePrint.WriteLine(input);
        }
        private static void SetPrinter(List<AChanger> l, IPrinter pr) {
            foreach (var gate in l)
                gate.SetPrinter(pr);
        }
    }
}

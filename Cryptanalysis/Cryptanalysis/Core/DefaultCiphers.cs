using System.Collections.Generic;
using Cryptanalysis.F.Common;
using Cryptanalysis.F.Core;
using static Cryptanalysis.Core.Utils;

namespace Cryptanalysis.Core {

    internal static class DefaultCiphers {

        internal static Cipher GetCipherFour(IPrinter printer) {
            //Definition of cipher elements
            XORwithKey[] keys = new XORwithKey[6];
            keys[0] = new XORwithKey(ConvertToBinary(23442, 16));
            keys[1] = new XORwithKey(ConvertToBinary(1611, 16));
            keys[2] = new XORwithKey(ConvertToBinary(7683, 16));
            keys[3] = new XORwithKey(ConvertToBinary(42335, 16));
            keys[4] = new XORwithKey(ConvertToBinary(60605, 16));
            keys[5] = new XORwithKey(ConvertToBinary(31909, 16));

            var perm = new Permutation(ParseParmutationTable("0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15"));
            var sbox = DefaultFlowChangers.GetSbox4_1();

            sbox.SetPrinter(printer);
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
            SetPrinter(l, printer);
            return new Cipher(l);
        }

        internal static Cipher GetCipherOne(IPrinter printer) {
            XORwithKey
                key0 = new(GetRndKey(4)),
                key1 = new(GetRndKey(4));
            var sbox = DefaultFlowChangers.GetSbox4_1();
            List<AChanger> l = new List<AChanger> {
                key0,
                sbox,
                key1
            };
            SetPrinter(l, printer);
            return new Cipher(l);
        }
    }
}

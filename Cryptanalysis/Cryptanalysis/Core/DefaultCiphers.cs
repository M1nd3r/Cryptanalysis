using System.Collections.Generic;
using Cryptanalysis.F.Common;
using Cryptanalysis.F.Core;
using static Cryptanalysis.Core.Utils;

namespace Cryptanalysis.Core {

    internal static class DefaultCiphers {

        internal static Cipher GetCipherA(IPrinter printer)
            => GetBasicCipher(DefaultFlowChangers.GetSbox4_A(), printer);

        internal static Cipher GetCipherFour(IPrinter printer) {
            //Definition of cipher elements

            XORwithKey[] keys = GetRandomKeys();

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

        internal static Cipher GetCipherOne(IPrinter printer)
            => GetBasicCipher(DefaultFlowChangers.GetSbox4_1(), printer);

        internal static Cipher GetCipherTwo(IPrinter printer) {
            var keys = new XORwithKey[] {
                new(GetRndKey(4)),
                new(GetRndKey(4)),
                new(GetRndKey(4))
            };
            var sbox = DefaultFlowChangers.GetSbox4_1();
            var l = new List<AChanger> {
                keys[0],
                sbox,
                keys[1],
                sbox,
                keys[2]
            };
            SetPrinter(l, printer);
            return new Cipher(l);
        }

        private static Cipher GetBasicCipher(Sbox4 sbox, IPrinter printer) {
            XORwithKey
                key0 = new(GetRndKey(4)),
                key1 = new(GetRndKey(4));
            var l = new List<AChanger> {
                key0,
                sbox,
                key1
            };
            SetPrinter(l, printer);
            return new Cipher(l);
        }

        private static XORwithKey[] GetDefaultKeys() {
            XORwithKey[] keys = new XORwithKey[] {
                new (ConvertToBinary(23442, 16)),
                new (ConvertToBinary(1611, 16)),
                new (ConvertToBinary(7683, 16)),
                new (ConvertToBinary(42335, 16)),
                new (ConvertToBinary(60605, 16)),
                new (ConvertToBinary(31909, 16)),
            };
            return keys;
        }

        private static XORwithKey[] GetRandomKeys() {
            XORwithKey[] keys = new XORwithKey[6];
            for (int i = 0; i < keys.Length; i++)
                keys[i] = new(GetRndKey(16));
            return keys;
        }
    }
}

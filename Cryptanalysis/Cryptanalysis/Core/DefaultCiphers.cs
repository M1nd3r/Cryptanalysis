using System.Collections.Generic;
using Cryptanalysis.Common;
using static Cryptanalysis.Core.Utils;

namespace Cryptanalysis.Core {

    internal static class DefaultCiphers {

        internal static Cipher CreateCipherFromLFSR(LFSRchanger lfsr) {
            var l = new List<AChanger> {
                lfsr
            };
            return new Cipher(l);
        }

        internal static Cipher GetCipherA(IPrinter printer)
                    => GetBasicCipher(DefaultFlowChangers.GetSbox4_A(), printer);

        internal static Cipher GetCipherD(IPrinter printer)
              => GetSofisticatedCipher(printer, DefaultFlowChangers.GetSbox4_A());

        internal static Cipher GetCipherFour(IPrinter printer)
            => GetSofisticatedCipher(printer, DefaultFlowChangers.GetSbox4_1());

        internal static Cipher GetCipherOne(IPrinter printer)
            => GetBasicCipher(DefaultFlowChangers.GetSbox4_1(), printer);

        internal static Cipher GetCipherTwo(IPrinter printer) {
            var keys = new XORwithKey[] {
                new XORwithKey(GetRndKey(4)),
                new XORwithKey(GetRndKey(4)),
                new XORwithKey(GetRndKey(4))
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

        internal static Cipher GetFinalCipher(byte[] key7x, byte[] key11y, byte[] key15z, byte[] key11t) {
            var l = new List<AChanger> {
                new FinalCipher(key7x,key11y,key15z,key11t)
            };
            return new Cipher(l);
        }

        internal static Cipher GetFinalCipher() {
            var l = new List<AChanger> {
                new FinalCipher()
            };
            return new Cipher(l);
        }

        internal static Cipher GetLFSRCipher() {
            var l = new List<AChanger> {
                new LFSR3Mix()
            };
            return new Cipher(l);
        }

        internal static Cipher GetSofisticatedCipher(IPrinter printer, Sbox4 sbox) {
            // Definition of cipher elements
            XORwithKey[] keys = GetRandomKeys();

            var perm = new Permutation(ParseParmutationTable("0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15"));

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

        private static Cipher GetBasicCipher(Sbox4 sbox, IPrinter printer) {
            XORwithKey
                key0 = new XORwithKey(GetRndKey(4)),
                key1 = new XORwithKey(GetRndKey(4));
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
                new XORwithKey(ConvertToBinary(23442, 16)),
                new XORwithKey(ConvertToBinary(1611, 16)),
                new XORwithKey(ConvertToBinary(7683, 16)),
                new XORwithKey(ConvertToBinary(42335, 16)),
                new XORwithKey(ConvertToBinary(60605, 16)),
                new XORwithKey(ConvertToBinary(31909, 16)),
            };
            return keys;
        }

        private static XORwithKey[] GetRandomKeys() {
            XORwithKey[] keys = new XORwithKey[6];
            for (int i = 0; i < keys.Length; i++)
                keys[i] = new XORwithKey(GetRndKey(16));
            return keys;
        }
    }
}

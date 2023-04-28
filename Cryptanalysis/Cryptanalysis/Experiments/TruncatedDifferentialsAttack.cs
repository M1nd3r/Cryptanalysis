using System;
using System.Collections.Generic;
using System.Linq;
using Cryptanalysis.Common;
using Cryptanalysis.Core;
using static Cryptanalysis.Core.DefaultCiphers;
using static Cryptanalysis.Core.Utils;
using static Cryptanalysis.Experiments.AttackUtils;

namespace Cryptanalysis.Experiments {

    internal class TruncatedDifferentialsAttack : Attack {
        private readonly IList<byte[]> bitstrings = GenerateAllPossibleKeys(4);
        private readonly Sbox4 sbox = DefaultFlowChangers.GetSbox4_1();
        private Dictionary<byte[], IList<BitstringPair>> dic = new Dictionary<byte[], IList<BitstringPair>>();

        public override bool BreakCipher() {
            int precision = 16; // Negative number - all pairs, otherwise determines number of pairs

            SetMainPrinter(new ConsolePrinter());
            SetVerbosePrinter(new DummyPrinter());
            SetCipher(GetCipherFour(verbosePrinter));
            PrintKeys();

            // Number of runs generating message pairs (1 run is 16 message pairs);
            int runs = (int)Math.Ceiling(precision / 16d);

            var possibleKey0Nibbles = GenerateAllPossibleKeys(4);

            // Find pairs with difference 0010 after first round

            foreach (var keyNibble in possibleKey0Nibbles)
                dic.Add(keyNibble, GetMessagePairs(keyNibble, runs));

            // Recovering correct key0 nibble
            foreach (byte[] keyNibble in dic.Keys) {
                if (IsImpossibleKey(keyNibble))
                    dic.Remove(keyNibble);
            }

            if (dic.Count == 1) {
                mainPrinter.Write("Guessed key0 nibble is: ");
                mainPrinter.WriteLine(dic.Keys.First());

                // Comparation with real keys
                return HandleResult();
            }

            mainPrinter.WriteLine("Failed to determine key0 nibble!");
            return false;
        }

        private static bool IsKeyNibbleCorrectlyGuessed(byte[] nibble, byte[] key0) {
            for (int i = 0; i < 4; i++) {
                if (nibble[i] != key0[i + 8])
                    return false;
            }
            return true;
        }

        private byte[] Combine(params byte[][] arrays) {
            byte[] r = new byte[arrays.Sum(a => a.Length)];
            int offset = 0;
            foreach (byte[] array in arrays) {
                Buffer.BlockCopy(array, 0, r, offset, array.Length);
                offset += array.Length;
            }
            return r;
        }

        private IList<BitstringPair> GetCiphertextPairs(IList<BitstringPair> messagePairs) {
            var l = new List<BitstringPair>();
            foreach (var pair in messagePairs) {
                l.Add(new BitstringPair(cipher.Encode(pair.bs1), cipher.Encode(pair.bs2)));
            }
            return l;
        }

        private IList<BitstringPair> GetMessagePairs(byte[] key0Nibble, int runs = 1) {
            if (key0Nibble is null)
                throw new ArgumentNullException(nameof(key0Nibble));
            if (runs < 1)
                throw new ArgumentException(nameof(runs) + " must be greater than 0");

            var l = new List<BitstringPair>();
            while (runs > 0) {
                runs--;
                for (int i = 0; i < bitstrings.Count; i++)
                    l.Add(GetMessagePairWithRandomNibbles(bitstrings[i], key0Nibble));
            }
            return l;
        }

        private BitstringPair GetMessagePairWithRandomNibbles(byte[] m1, byte[] key0Nibble) {
            if (m1 is null)
                throw new ArgumentNullException(nameof(m1));

            if (key0Nibble is null)
                throw new ArgumentNullException(nameof(key0Nibble));

            if (m1.Length != 4)
                throw new ArgumentException("Wrong length of " + nameof(m1));

            if (key0Nibble.Length != 4)
                throw new ArgumentException("Wrong length of " + nameof(key0Nibble));

            byte[]
                nibble1 = GetRndKey(4),
                nibble2 = GetRndKey(4),
                nibble4 = GetRndKey(4);

            var m2 = XORs(m1, key0Nibble);
            sbox.Apply(ref m2);
            m2[2] = GetSwitchedByte(m2[2]);
            sbox.ApplyInverse(ref m2);
            m2 = XORs(m2, key0Nibble);

            byte[]
                msg1 = Combine(nibble1, nibble2, m1, nibble4),
                msg2 = Combine(nibble1, nibble2, m2, nibble4);
            return new BitstringPair(msg1, msg2);
        }

        private byte GetSwitchedByte(byte b) {
            if (b == 0)
                return 1;
            if (b == 1)
                return 0;
            throw new ArgumentException(nameof(b) + " is not 0 or 1");
        }

        private bool HandleResult() {
            var realKeys = GetKeys(cipher);
            if (IsKeyNibbleCorrectlyGuessed(dic.Keys.First(), realKeys[0])) {
                mainPrinter.WriteLine("Success! Key part correctly guessed.");
                mainPrinter.WriteLine(GetHyphens(38) + "\n");
                return true;
            }

            mainPrinter.WriteLine("Failed! Key parts are different.");
            mainPrinter.WriteLine(GetHyphens(38) + "\n");
            return false;
        }

        private bool HasPossibleKey5(IList<BitstringPair> ciphertextPairs) {
            for (int i = 0; i < 4; i++) {
                if (!HasPossibleKey5NibbleOnPosition(ciphertextPairs, i))
                    return false;
            }
            return true;
        }

        private bool HasPossibleKey5NibbleOnPosition(IList<BitstringPair> ciphertextPairs, int position) {
            var key5Nibbles = GenerateAllPossibleKeys(4);
            foreach (var nib in key5Nibbles) {
                if (IsKey5NibblePossible(ciphertextPairs, nib, position))
                    return true;
            }
            return false;
        }

        private bool IsImpossibleKey(byte[] key0Nibble) {
            var messagePairs = dic.GetValueOrDefault(key0Nibble);
            var ciphertextPairs = GetCiphertextPairs(messagePairs);
            return !HasPossibleKey5(ciphertextPairs);
        }

        private bool IsKey5NibblePossible(IList<BitstringPair> ciphertextPairs, byte[] key5nibble, int position) {
            foreach (var pair in ciphertextPairs) {
                byte[]
                    first = XORs(pair.bs1.SubArray(position * 4, 4), key5nibble),
                    second = XORs(pair.bs2.SubArray(position * 4, 4), key5nibble);
                sbox.ApplyInverse(ref first);
                sbox.ApplyInverse(ref second);
                if (Xor(first[1], second[1]) != 0)
                    return false;
            }
            return true;
        }

        private class BitstringPair {

            private readonly byte[]
                first, second;

            public BitstringPair(byte[] first, byte[] second) {
                this.first = first;
                this.second = second;
            }

            public byte[] bs1 => first;
            public byte[] bs2 => second;
        }
    }
}

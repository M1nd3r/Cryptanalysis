using System;
using System.Collections.Generic;
using Cryptanalysis.F.Common;
using Cryptanalysis.F.Core;
using static Cryptanalysis.Core.Utils;

namespace Cryptanalysis.F.Experiments {

    internal static class Analysis {

        internal static List<MaskProbability> GetSboxMasks(Sbox4 sbox) {
            int size = 256; //2^8
            var masks = new List<byte[]>(size);
            int[] probability = new int[size];
            for (int i = 0; i < size; i++) {
                masks.Add(ConvertToBinary(i, 8));
            }
            var r = new List<MaskProbability>(size);
            throw new NotImplementedException();
        }

        private static int ComputeProbability(Sbox4 sbox, byte[] mask) {
            int p = 0;
            for (int i = 0; i < 16; i++) {
                var x = ConvertToBinary(i, 4);
                byte left = Mult(x, mask.SubArray(0, 4));
                sbox.Apply(ref x);
                byte right = Mult(x, mask.SubArray(4, 4));
                if (left == right) {
                    p++;
                }
            }
            return p;
        }

        internal class MaskProbability : IComparable {
            private readonly byte[] mask;
            private readonly int probability;

            public MaskProbability(byte[] mask, int probability) {
                this.mask = mask ?? throw new ArgumentNullException(nameof(mask));
                this.probability = probability;
            }

            public int Length => mask.Length;
            public byte[] Mask => mask;
            public int Probability => probability;

            public int CompareTo(object obj) {
                if (obj is not MaskProbability mp)
                    throw new ArgumentException("Object is not a " + nameof(MaskProbability), nameof(obj));
                if (mask.Length < mp.mask.Length)
                    return -1;
                if (mask.Length > mp.mask.Length)
                    return 1;
                return probability.CompareTo(mp.probability);
            }
        }
    }
}

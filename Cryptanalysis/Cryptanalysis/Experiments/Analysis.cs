using System;
using System.Collections.Generic;
using Cryptanalysis.Common;
using Cryptanalysis.Core;
using static Cryptanalysis.Core.Utils;

namespace Cryptanalysis.Experiments {

    internal static class Analysis {

        internal static List<MaskProbability> GetSboxMasks(Sbox4 sbox) {
            int size = 256; // 2^8
            var r = new List<MaskProbability>(size);
            for (int i = 1; i < size; i++) {
                byte[] mask = (ConvertToBinary(i, 8));
                int probability = ComputeProbability(sbox, mask);
                r.Add(new MaskProbability(mask, probability));
            }
            return r;
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

        internal class MaskProbability {
            private readonly byte[] mask;
            private readonly int probability;

            public MaskProbability(byte[] mask, int probability) {
                this.mask = mask ?? throw new ArgumentNullException(nameof(mask));
                this.probability = probability;
            }

            public int Length => mask.Length;
            public byte[] Mask => mask;
            public int Probability => probability;
        }
    }
}

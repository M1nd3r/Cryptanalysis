using System;
using System.Collections.Generic;
using Cryptanalysis.F.Common;

namespace Cryptanalysis.F.Experiments {

    internal static class Analysis {

        internal static List<MaskProbability> GetSboxMasks(Sbox4 sbox) {
            throw new NotImplementedException(); //TODO
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

using System;
using static Cryptanalysis.Core.Utils;

namespace Cryptanalysis.F.Core {

    internal class Solution : ICloneable {
        private readonly byte[] mask;
        private readonly byte result;

        public Solution(byte[] mask, byte result) {
            this.mask = mask;
            this.result = result;
        }

        public int Length => mask.Length;
        public byte[] Mask => mask;
        public byte Result => result;

        public static Solution operator +(Solution a, Solution b) {
            if (a == null)
                throw new ArgumentNullException(nameof(a));
            if (b == null)
                throw new ArgumentNullException(nameof(b));
            if (a.mask.Length != b.mask.Length)
                throw new ArgumentException("Solutions do not have the same dimensions.");
            var mask = XORs(a.mask, b.mask);
            var result = Xor(a.result, b.result);
            return new Solution(mask, result);
        }

        public object Clone() {
            return new Solution(mask, result);
        }
    }
}

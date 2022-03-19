using Cryptanalysis.F.Core;
using static Cryptanalysis.Core.Utils;
using static Cryptanalysis.F.Core.Verifiers;

namespace Cryptanalysis.F.Common {

    internal class XORwithKey : AChanger {
        private readonly byte[] key;

        public XORwithKey(byte[] key) {
            this.key = key;
        }

        protected override void ApplyInternal(ref byte[] arr) {
            CheckAreEqual(arr.Length, key.Length);
            arr = XORs(arr, key);
        }

        protected override void ApplyInverseInternal(ref byte[] arr) {
            CheckAreEqual(arr.Length, key.Length);
            arr = XORs(arr, key);
        }
    }
}

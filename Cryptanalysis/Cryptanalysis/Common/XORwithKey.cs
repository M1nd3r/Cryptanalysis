using Cryptanalysis.Core;
using static Cryptanalysis.Core.Utils;
using static Cryptanalysis.Core.Verifiers;

namespace Cryptanalysis.Common {

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

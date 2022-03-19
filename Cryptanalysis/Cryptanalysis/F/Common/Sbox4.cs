using System;
using Cryptanalysis.F.Core;
using static Cryptanalysis.Core.Utils;

namespace Cryptanalysis.F.Common {
    class Sbox4 : AChanger {
        private (int source, int target)[] table;
        public Sbox4((int source, int target)[] table) {
            this.table = table;
        }
        protected override void ApplyInternal(ref byte[] arr) {
            int test = ConvertToInt(arr);
            foreach (var (source, target) in table) {
                if (source == test) {
                    arr = ConvertToBinary(target, arr.Length);
                    return;
                }
            }
            throw new ArgumentException("The table in this class does not contain the value for the argument given");
        }

        protected override void ApplyInverseInternal(ref byte[] arr) {
            int test = ConvertToInt(arr);
            foreach (var (source, target) in table) {
                if (target == test) {
                    arr = ConvertToBinary(source, arr.Length);
                    return;
                }
            }
            throw new ArgumentException("The table in this class does not contain the value for the argument given");
        }
    }
}

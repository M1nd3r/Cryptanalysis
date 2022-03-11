using System;
using static Cryptanalysis.Core.Utils;

namespace Cryptanalysis.Core.Common {
    class Key : Gate {
        public Key(string name, byte[] key) : base(name) {
            for (int i = 0; i < key.Length; i++) {
                if (!IsBinOrUndefined(key[i]))
                    throw new ArgumentException();
                outputs.Add(new OutSlot(key[i]));
            }
        }
        private Key(Key key) : base(key.Name, key) {
        }

        public override Gate Duplicate() {
            return new Key(this);
        }

        public override void Run() {
        }
    }
}

using static Cryptanalysis.Core.Utils;

namespace Cryptanalysis.Core.Common {
    class Sbox4 : ASbox {
        public Sbox4(string name, string s) : base(name, CreateTransitionTableSbox4(s)) {
        }
        public Sbox4(string name, (int source, int target)[] table) : base(name, table) {
        }
        public Sbox4(Sbox4 sbox4) : this(sbox4.Name, sbox4.table) {
        }
        public override Gate Duplicate() {
            return new Sbox4(this);
        }
        public Sbox4 Invert() {
            return new Sbox4("inverted_" + Name, table.Invert());
        }
    }
}

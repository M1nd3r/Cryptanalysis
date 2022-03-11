using static Cryptanalysis.Core.Utils;

namespace Cryptanalysis.Core.Common {
    class Sbox4 : ASbox {
        private string inputString;
        public Sbox4(string name, string s) : base(name, CreateTransitionTableSbox4(s)) {
            this.inputString = s;
        }
        public Sbox4(Sbox4 sbox4) : this(sbox4.Name, sbox4.inputString) {

        }
        public override Gate Duplicate() {
            return new Sbox4(this);
        }
    }
}

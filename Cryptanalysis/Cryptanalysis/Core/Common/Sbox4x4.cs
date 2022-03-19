using System.Collections.Generic;


namespace Cryptanalysis.Core.Common {
    class Sbox4x4 : Model {
        private Sbox4 sboxType;
        public Sbox4x4(string name, Sbox4 sbox) : base(name) {
            sboxType = sbox;
            gates = new List<Gate>();
            const int numberOfSBoxes = 4;
            for (int i = 0; i < numberOfSBoxes; i++) {
                gates.Add((Sbox4)sbox.Duplicate());
            }
            for (int i = 0; i < numberOfSBoxes; i++) {
                for (int y = 0; y < gates[i].InputsCount; y++) {
                    inputs.Add(gates[i].GetInput(y));
                }
                for (int y = 0; y < gates[i].OutputsCount; y++) {
                    outputs.Add(gates[i].GetOutput(y));
                }
            }
        }
        public Sbox4x4(Sbox4x4 sbox4x4) : this(sbox4x4.Name, sbox4x4.sboxType) { }

        public override Gate Duplicate() {
            return new Sbox4x4(this);
        }

    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


using Cryptanalysis.Core;
using Cryptanalysis.Core.Common;
using static Cryptanalysis.Core.Utils;
using static Cryptanalysis.Core.ConnectionHelper;

namespace Cryptanalysis.Ciphers {

    class CipherFour : Model {
        byte[][] keys_byte;

        private void SetKeysRandomly() {
            keys_byte = new byte[6][];
            for (int i = 0; i < keys_byte.Length; i++) {
                keys_byte[i] = GetRndKey(16);
            }
        }
        private void SetKeysSample() {
            keys_byte = new byte[6][];
            keys_byte[0] = ConvertToBinary(23442, 16);
            keys_byte[1] = ConvertToBinary(1611, 16);
            keys_byte[2] = ConvertToBinary(7683, 16);
            keys_byte[3] = ConvertToBinary(42335, 16);
            keys_byte[4] = ConvertToBinary(60605, 16);
            keys_byte[5] = ConvertToBinary(31909, 16);
        }
        public CipherFour() : base("CipherFour") {
            for (int i = 0; i < 16; i++) {
                inputs.Add(new InSlot());
                outputs.Add(new OutSlot());
            }

            //Keys creation
            SetKeysSample();

            //Gates and their definitions
            Sbox4 sbox = new Sbox4("sbox", "64C5072E1F3D8A9B");
            Sbox4x4 sbox4X4 = new Sbox4x4("sbox4x4", sbox);
            XOR xor = new XOR("xor", 16);
            Permutation p = new Permutation("permutation", Permutation.ParseParmutationTable("0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15"));
            Key[] key = new Key[6];
            for (int i = 0; i < key.Length; i++)
                key[i] = new Key("key_" + i.ToString(), keys_byte[i]);
            var sboxRows = new Sbox4x4[5];
            var perms = new Permutation[4];
            var XORs = new XOR[6];
            for (int i = 0; i < sboxRows.Length; i++)
                sboxRows[i] = (Sbox4x4)sbox4X4.Duplicate();
            for (int i = 0; i < perms.Length; i++)
                perms[i] = (Permutation)p.Duplicate();
            for (int i = 0; i < XORs.Length; i++)
                XORs[i] = (XOR)xor.Duplicate();
            var dg = new DummyGate("dummyInputGate", 16);

            //Connections
            a(ConnectModelInput(this, dg));
            a(Connect(dg, key[0], XORs[0]));
            for (int i = 0; i < 4; i++) {
                a(Connect(XORs[i], sboxRows[i]));
                a(Connect(sboxRows[i], perms[i]));
                a(Connect(perms[i], key[i + 1], XORs[i + 1]));
            }
            a(Connect(XORs[4], sboxRows[4]));
            a(Connect(sboxRows[4], key[5], XORs[5]));
            a(ConnectModelOutput(XORs[5], this));

            //Adding gates to the model - to be executed
            AddGate(dg);
            foreach (var gate in sboxRows)
                AddGate(gate);
            foreach (var gate in XORs)
                AddGate(gate);
            foreach (var gate in perms)
                AddGate(gate);
            foreach (var gate in key)
                AddGate(gate);
        }
        private void a(List<AbstractConnection> connections) {
            AddConnections(connections);
        }
    }
}

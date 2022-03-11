using System;
using System.Collections.Generic;

namespace Cryptanalysis.Core {
    class Model : Gate {
        private bool hasChanged = true;
        public Model(string name) : base(name) {
            gates = new List<Gate>();
            connections = new List<AbstractConnection>();
        }
        private Model(Model m) : this(m.Name) {
            foreach (var gate in m.gates)
                gates.Add(gate.Duplicate());
            foreach (var con in m.connections) {
                if (con is InternalConnection intCon)
                    AddInternalConnection(m, intCon);
                else if (con is Connection connection)
                    AddStandardConnection(m, connection);
            }
        }
        private void AddInternalConnection(Model m, InternalConnection intCon) {
            InSlot srcSlot = (InSlot)intCon.GetSource;
            OutSlot trgSlot = (OutSlot)intCon.GetTarget;
            InSlot newSource = null;
            OutSlot newTarget = null;
            for (int i = 0; i < gates.Count; i++) {
                for (int y = 0; y < gates[i].InputsCount; y++) {
                    if (m.gates[i].GetInput(y) == srcSlot)
                        newSource = gates[i].GetInput(y);
                }
                for (int y = 0; y < gates[i].OutputsCount; y++) {
                    if (m.gates[i].GetOutput(y) == trgSlot)
                        newTarget = gates[i].GetOutput(y);
                }
            }
            connections.Add(new InternalConnection(newSource, newTarget));
        }
        private void AddStandardConnection(Model m, Connection connection) {
            OutSlot
                srcSlot = (OutSlot)connection.GetSource,
                newSource = null;
            InSlot
                trgSlot = (InSlot)connection.GetTarget,
                newTarget = null;
            for (int i = 0; i < gates.Count; i++) {
                for (int y = 0; y < gates[i].InputsCount; y++) {
                    if (m.gates[i].GetInput(y) == trgSlot)
                        newTarget = gates[i].GetInput(y);
                }
                for (int y = 0; y < gates[i].OutputsCount; y++) {
                    if (m.gates[i].GetOutput(y) == srcSlot)
                        newSource = gates[i].GetOutput(y);
                }
            }
            connections.Add(new Connection(newSource, newTarget));
        }
        public void SetInputs(string s) {
            byte[] inputsConverted = Utils.ConvertToByteArr(s);
            if (inputsConverted.Length != inputs.Count)
                throw new ArgumentException("The number of inputs is not the same");
            for (int i = 0; i < inputs.Count; i++) {
                inputs[i].Set(inputsConverted[i]);
            }
        }
        protected List<Gate> gates;
        protected List<AbstractConnection> connections;
        public void AddGate(Gate gate) {
            gates.Add(gate);
        }
        public void AddGates(List<Gate> gates) {
            this.gates.AddRange(gates);
        }
        public void AddConnection(AbstractConnection connection) {
            connections.Add(connection);
        }
        public void AddConnections(List<AbstractConnection> connections) {
            this.connections.AddRange(connections);
        }
        public override void Run() {
            foreach (var gate in gates)
                gate.Run();
            hasChanged = false;
            foreach (var con in connections) {
                if (con.Transfer())
                    hasChanged = true;
            }
        }
        public override Gate Duplicate() {
            return new Model(this);
        }
        public bool HasChanged => hasChanged;
        public List<Gate> GetGates => gates;
        public List<AbstractConnection> GetConnections => connections;
    }
}

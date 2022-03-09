using System;
using System.Collections.Generic;

namespace Cryptanalysis.Core {
    abstract class AbstractConnection {
        private Slot from;
        private Slot to;
        public AbstractConnection(Slot source, Slot target) {
            this.from = source;
            this.to = target;
        }
        public bool Transfer() {
            var r = (to.Get == from.Get);
            to.Set(from.Get);
            return r;
        }
        public Slot GetTarget => this.to;
        public Slot GetSource => this.from;
    }
    class InternalConnection : AbstractConnection {
        public InternalConnection(InSlot source, OutSlot target) : base(source, target) { }
        public static void MakeInternalConnections(ref List<AbstractConnection> listToAppend, List<InSlot> sources, List<OutSlot> targets) {
            if (sources.Count != targets.Count)
                throw new ArgumentException();
            for (int i = 0; i < sources.Count; i++) {
                listToAppend.Add(new InternalConnection(sources[i], targets[i]));
            }
        }
    }
    class Connection : AbstractConnection {
        public Connection(OutSlot source, InSlot target) : base(source, target) { }
        public static void MakeConnections(ref List<AbstractConnection> listToAppend, List<OutSlot> sources, List<InSlot> targets) {
            if (sources.Count != targets.Count)
                throw new ArgumentException();
            for (int i = 0; i < sources.Count; i++) {
                listToAppend.Add(new Connection(sources[i], targets[i]));
            }
        }
    }
    internal static class ConnectionHelper {
        private class UniversalConnection : AbstractConnection {
            public UniversalConnection(Slot source, Slot target) : base(source, target) { }
            public static void MakeConnections(ref List<AbstractConnection> listToAppend, List<Slot> sources, List<Slot> targets) {
                if (sources.Count != targets.Count)
                    throw new ArgumentException();
                for (int i = 0; i < sources.Count; i++) {
                    listToAppend.Add(new UniversalConnection(sources[i], targets[i]));
                }
            }
        }
        public static List<AbstractConnection> Connect(Gate source, Gate target) {
            var a = new List<Gate>();
            var b = new List<Gate>();
            a.Add(source);
            b.Add(target);
            return Connect(a, b);
        }
        public static List<AbstractConnection> Connect(Gate source1, Gate source2, Gate target) {
            var a = new List<Gate>();
            var b = new List<Gate>();
            a.Add(source1);
            a.Add(source2);
            b.Add(target);
            return Connect(a, b);
        }
        public static List<AbstractConnection> Connect(List<Gate> sources, List<Gate> targets) {
            var from = new List<Slot>();
            var to = new List<Slot>();
            for (int i = 0; i < sources.Count; i++) {
                for (int y = 0; y < sources[i].OutputsCount; y++) {
                    from.Add(sources[i].GetOutput(y));
                }
            }
            for (int i = 0; i < targets.Count; i++) {
                for (int y = 0; y < targets[i].InputsCount; y++) {
                    to.Add(targets[i].GetInput(y));
                }
            }
            if (from.Count != to.Count)
                throw new ArgumentException();
            return MakeConnection(from, to);
        }
        public static List<AbstractConnection> ConnectModelInput(Model m, Gate target) {
            var l = new List<Gate>();
            l.Add(target);
            return ConnectModelInput(m, l);
        }
        public static List<AbstractConnection> ConnectModelInput(Model m, List<Gate> targets) {
            var from = new List<Slot>();
            var to = new List<Slot>();
            for (int y = 0; y < m.InputsCount; y++) {
                from.Add(m.GetInput(y));
            }

            for (int i = 0; i < targets.Count; i++) {
                for (int y = 0; y < targets[i].InputsCount; y++) {
                    to.Add(targets[i].GetInput(y));
                }
            }
            if (from.Count != to.Count)
                throw new ArgumentException();
            return MakeConnection(from, to);
        }
        public static List<AbstractConnection> ConnectModelOutput(Gate source, Model m) {
            var l = new List<Gate>();
            l.Add(source);
            return ConnectModelOutput(l, m);
        }
        public static List<AbstractConnection> ConnectModelOutput(List<Gate> sources, Model m) {
            var from = new List<Slot>();
            var to = new List<Slot>();
            for (int i = 0; i < sources.Count; i++) {
                for (int y = 0; y < sources[i].OutputsCount; y++) {
                    from.Add(sources[i].GetOutput(y));
                }
            }
            for (int y = 0; y < m.OutputsCount; y++) {
                to.Add(m.GetOutput(y));
            }            
            if (from.Count != to.Count)
                throw new ArgumentException();
            return MakeConnection(from, to);
        }

        private static List<AbstractConnection> MakeConnection(List<Slot> from, List<Slot> to) {
            var r = new List<AbstractConnection>();
            for (int i = 0; i < from.Count; i++) {
                r.Add(new UniversalConnection(from[i], to[i]));
            }
            return r;
        } 
    }
}

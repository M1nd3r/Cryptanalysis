using Cryptanalysis.Core;
using System;
using static Cryptanalysis.Core.Utils;

namespace Cryptanalysis.UI {
    interface IDisplay {
        public void PrintGate(Gate g);
        public void PrintModel(Model m);

    }
    class ConsoleDisplay:IDisplay {
        private static ConsoleDisplay display = null;
        private ConsoleDisplay() { }
        public static ConsoleDisplay GetConsoleDisplay() {
            if (display == null)
                display = new ConsoleDisplay();
            return display;
        }
        public void PrintGate(Gate g) {
            var separatingLine = GetHyphens(Math.Max(g.InputsCount, g.OutputsCount) * 2);
            Console.WriteLine(separatingLine);
            Console.WriteLine("Gate - " + g.ToString() + ": " + g.Name);
            Console.Write("input:  ");
            for (int i = 0; i < g.InputsCount; i++) {
                Console.Write("{0}", g.GetInput(i).Get);
            }
            Console.WriteLine();
            Console.Write("output: ");
            for (int i = 0; i < g.OutputsCount; i++) {
                Console.Write("{0}", g.GetOutput(i).Get);
            }
            Console.WriteLine();
            Console.WriteLine(separatingLine);
        }
        public void PrintModel(Model m) {
            PrintGate(m);
            foreach (var gate in m.GetGates) {
                PrintGate(gate);
            }
        }
    }
}

using Cryptanalysis.Ciphers;
using Cryptanalysis.Core;
using Cryptanalysis.UI;

namespace Cryptanalysis.Experiments {
    class CipherRunner {
        private Model model;
        private IDisplay display;
        public CipherRunner() {
            this.model = new CipherFour();
            this.display = ConsoleDisplay.GetConsoleDisplay();
        }
        public void Run(int times = 1) {
            for (int i = 0; i < times; i++) {
                model.Run();
            }
        }
        public void Print() {
            display.PrintGate(model);
        }
        public void PrintVerbose() {
            display.PrintModel(model);
        }
        public void SetInputs(string s) {
            model.SetInputs(s);
        }
    }
}

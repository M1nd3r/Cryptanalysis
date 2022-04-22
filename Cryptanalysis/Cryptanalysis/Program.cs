using System;
using Cryptanalysis.F.Experiments;

namespace Cryptanalysis {

    internal class Program {

        private static void Main(string[] args) {
            RunExperiment(Attacks.BreakCipherAHundredTimes);
        }

        private static void RunExperiment(Action experiment) {
            ExperimentSelector es = ExperimentSelector.GetExperimentSelectorInstance();
            if (experiment != null)
                es.SetSelectedExperiment(experiment);
            es.RunSelected();
        }
    }
}

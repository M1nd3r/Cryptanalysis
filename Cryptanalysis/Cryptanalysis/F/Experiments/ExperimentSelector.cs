using System;

namespace Cryptanalysis.F.Experiments {

    internal class ExperimentSelector {
        public readonly Action DefaultExperiment = Attacks.BreakCipherOne;
        private static ExperimentSelector singleton;

        private ExperimentSelector() {
            SelectedExperiment = DefaultExperiment;
        }

        public Action SelectedExperiment { get; private set; }

        public static ExperimentSelector GetExperimentSelectorInstance() {
            if (singleton == null)
                singleton = new ExperimentSelector();
            return singleton;
        }

        public void RunSelected() => SelectedExperiment();

        public void SetSelectedExperiment(Action experiment)
                    => SelectedExperiment = experiment;
    }
}

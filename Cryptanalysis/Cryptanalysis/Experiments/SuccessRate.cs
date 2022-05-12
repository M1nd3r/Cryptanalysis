using System;

namespace Cryptanalysis.Experiments {

    internal struct SuccessRate {

        private readonly int
            succ,
            fail,
            total;

        public SuccessRate(int successCount, int failCount) {
            if (successCount < 0)
                throw new ArgumentException("Success count must be greater than or equal to 0!", nameof(successCount));
            if (failCount < 0)
                throw new ArgumentException("Fail count must be greater than or equal to 0!", nameof(failCount));

            this.succ = successCount;
            this.fail = failCount;
            this.total = succ + fail;
        }

        public int GetFailCount() => fail;

        public float GetFailRatio() => (float)((float)fail) / ((float)total);

        public int GetSuccessCount() => succ;

        public float GetSuccessRatio() => (float)((float)succ) / ((float)total);

        public int GetTotalCount() => total;
    }
}

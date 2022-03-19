using System;
using System.Runtime.Serialization;

namespace Cryptanalysis.F.Core {
    class Custom : Exception {
        public Custom() {
        }
        public Custom(string message) : base(message) {
        }
        public Custom(string message, Exception innerException) : base(message, innerException) {
        }
        protected Custom(SerializationInfo info, StreamingContext context) : base(info, context) {
        }
    }
    internal class CheckException : Custom {
        public CheckException() {
        }
        public CheckException(string message) : base(message) {
        }
        public CheckException(string message, Exception innerException) : base(message, innerException) {
        }
        protected CheckException(SerializationInfo info, StreamingContext context) : base(info, context) {
        }
    }
}

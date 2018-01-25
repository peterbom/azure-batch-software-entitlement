using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Azure.Batch.SoftwareEntitlement.Common;

namespace Microsoft.Azure.Batch.SoftwareEntitlement.Tests
{
    public class FakeCertificateStore : ICertificateStore
    {
        private readonly string _notFoundError;
        private readonly Dictionary<string, X509Certificate2> _certLookup;

        public FakeCertificateStore(
            string notFoundError,
            params (CertificateThumbprint Thumbprint, X509Certificate2 Certificate)[] certificates)
        {
            _notFoundError = notFoundError;
            _certLookup = certificates.ToDictionary(pair => pair.Thumbprint.ToString(), pair => pair.Certificate);
        }

        public IEnumerable<X509Certificate2> FindAll()
        {
            return _certLookup.Values;
        }

        public Errorable<X509Certificate2> FindByThumbprint(string purpose, CertificateThumbprint thumbprint)
        {
            return _certLookup.ContainsKey(thumbprint.ToString())
                ? Errorable.Success(_certLookup[thumbprint.ToString()])
                : Errorable.Failure<X509Certificate2>(_notFoundError);
        }
    }
}

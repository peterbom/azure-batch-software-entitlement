using System.Collections.Concurrent;

namespace Microsoft.Azure.Batch.SoftwareEntitlement.Server
{
    /// <summary>
    /// An in-memory store of entitlement IDs and the corresponding host ID values
    /// with which they have been used. For ensuring that every entitlement is only
    /// used by a single host.
    /// </summary>
    public class EntitlementStore
    {
        private readonly ConcurrentDictionary<string, string> _lookup = new ConcurrentDictionary<string, string>();

        /// <summary>
        /// Stores the host ID against the entitlement ID, or does nothing if it's already
        /// stored. Performs a check to verify that the entitlement was not previously
        /// associated with a different host.
        /// </summary>
        /// <param name="entitlementId">The entitlement ID</param>
        /// <param name="hostId">The host ID</param>
        /// <returns>
        /// True if the entitlement is new or previously associated with the same host,
        /// false if it was previously associated with a different host.
        /// </returns>
        public bool StoreAndCheck(string entitlementId, string hostId)
        {
            var storedHostId = _lookup.GetOrAdd(entitlementId, hostId);
            return storedHostId == hostId;
        }
    }
}

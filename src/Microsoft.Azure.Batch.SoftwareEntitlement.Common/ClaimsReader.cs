using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace Microsoft.Azure.Batch.SoftwareEntitlement.Common
{
    public static class ClaimsReader
    {
        public static ClaimsReader<T> WithClaimsReader<T>(this Errorable<T> errorable, ClaimsPrincipal principal)
        {
            return new ClaimsReader<T>(principal, errorable);
        }
    }

    public class ClaimsReader<T>
    {
        private readonly ClaimsPrincipal _principal;

        public Errorable<T> Result { get; }

        public ClaimsReader(ClaimsPrincipal principal, Errorable<T> result)
        {
            _principal = principal;
            Result = result;
        }

        public ClaimsReader<T> ReadOptional(string claimId, Func<T, string, T> setClaimValue)
        {
            return ReadOptional(claimId, val => Errorable.Success(val), setClaimValue);
        }

        public ClaimsReader<T> ReadOptional<TValue>(
            string claimId,
            Func<string, Errorable<TValue>> parseClaim,
            Func<T, TValue, T> setClaimValue)
        {
            var claim = _principal.FindFirst(claimId);
            var result = claim != null
                ? Result.Bind(t => parseClaim(claim.Value).Bind(val => setClaimValue(t, val)))
                : Result;

            return new ClaimsReader<T>(_principal, result);
        }

        public ClaimsReader<T> ReadMultiple(
            string claimId,
            Func<T, IEnumerable<string>, T> setClaimValues)
        {
            return ReadMultiple(claimId, val => Errorable.Success(val), setClaimValues);
        }

        public ClaimsReader<T> ReadMultiple<TValue>(
            string claimId,
            Func<string, Errorable<TValue>> parseClaim,
            Func<T, IEnumerable<TValue>, T> setClaimValues)
        {
            var valueResults = _principal.FindAll(claimId).Select(c => parseClaim(c.Value));

            var valuesResult = valueResults.Reduce();

            return new ClaimsReader<T>(_principal, Result.With(valuesResult).Map(setClaimValues));
        }
    }
}

using System;
using Microsoft.AspNetCore.Http;
using Microsoft.Azure.Batch.SoftwareEntitlement.Common;
using Microsoft.Azure.Batch.SoftwareEntitlement.Server.Model;
using Microsoft.Extensions.Logging;

namespace Microsoft.Azure.Batch.SoftwareEntitlement.Server.RequestHandlers
{
    public class ReleaseRequestHandler : RequestHandlerBase, IRequestHandler<string>
    {
        private readonly EntitlementStore _entitlementStore;

        public ReleaseRequestHandler(
            ILogger logger,
            EntitlementStore entitlementStore) : base(logger)
        {
            _entitlementStore = entitlementStore;
        }

        public Response Handle(
            HttpContext httpContext,
            string requestContext)
        {
            var entitlementId = requestContext;

            return FindEntitlement(entitlementId)
                .OnOk(_ =>
                {
                    var releaseTime = DateTime.UtcNow;
                    return StoreRelease(entitlementId, releaseTime);
                })
                .OnOk(_ => CreateSuccessResponse())
                .Merge();
        }

        private Result<EntitlementProperties, Response> FindEntitlement(string entitlementId) =>
            _entitlementStore.FindEntitlement(entitlementId)
                .OnError(errors => CreateNotFoundResponse(entitlementId));

        private Result<EntitlementProperties, Response> StoreRelease(string entitlementId, DateTime releaseTime) =>
            _entitlementStore.ReleaseEntitlement(entitlementId, releaseTime)
                .OnError(CreateInternalErrorResponse);

        private static Response CreateSuccessResponse() =>
            new Response(StatusCodes.Status204NoContent);
    }
}

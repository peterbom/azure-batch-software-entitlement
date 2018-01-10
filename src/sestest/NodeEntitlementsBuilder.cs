using Microsoft.Azure.Batch.SoftwareEntitlement.Common;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;

namespace Microsoft.Azure.Batch.SoftwareEntitlement
{
    /// <summary>
    /// A factory object that tries to create a <see cref="NodeEntitlements"/> instance when given 
    /// the <see cref="GenerateCommandLine"/> specified by the user.
    /// </summary>
    public class NodeEntitlementsBuilder
    {
        // Reference to the generate command line we wrap
        private readonly GenerateCommandLine _commandLine;

        // Reference to a parser to use for timestamps
        private readonly TimestampParser _timestampParser = new TimestampParser();

        // A steady reference for "now"
        private readonly DateTimeOffset _now = DateTimeOffset.Now;

        /// <summary>
        /// Build an instance of <see cref="NodeEntitlements"/> from the information supplied on the 
        /// command line by the user
        /// </summary>
        /// <param name="commandLine">Command line parameters supplied by the user.</param>
        /// <returns>Either a usable (and completely valid) <see cref="NodeEntitlements"/> or a set 
        /// of errors.</returns>
        public static Errorable<NodeEntitlements> Build(GenerateCommandLine commandLine)
        {
            var builder = new NodeEntitlementsBuilder(commandLine);
            return builder.Build();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="GenerateCommandLine"/> class
        /// </summary>
        /// <param name="commandLine">Options provided on the command line.</param>
        private NodeEntitlementsBuilder(GenerateCommandLine commandLine)
        {
            _commandLine = commandLine ?? throw new ArgumentNullException(nameof(commandLine));
        }

        /// <summary>
        /// Build an instance of <see cref="NodeEntitlements"/> from the information supplied on the 
        /// command line by the user
        /// </summary>
        /// <returns>Either a usable (and completely valid) <see cref="NodeEntitlements"/> or a set 
        /// of errors.</returns>
        private Errorable<NodeEntitlements> Build()
        {
            return MultiErrorableBuilder.Start(new NodeEntitlements())
                .Apply(SetVirtualMachineId)
                .Apply(SetNotBefore)
                .Apply(SetNotAfter)
                .Apply(SetAudience)
                .Apply(SetIssuer)
                .Apply(SetCpuCoreCount)
                .Apply(SetBatchAccountId)
                .Apply(SetPoolId)
                .Apply(SetJobId)
                .Apply(SetTaskId)
                .Apply(SetAddresses)
                .Apply(SetApplications)
                .AsErrorable();
        }

        private Errorable<NodeEntitlements> SetVirtualMachineId(NodeEntitlements entitlement)
        {
            if (string.IsNullOrEmpty(_commandLine.VirtualMachineId))
            {
                // If user doesn't specify a virtual machine identifier, we default to null (not empty string)
                return Errorable.Success(entitlement);
            }

            return Errorable.Success(entitlement.WithVirtualMachineId(_commandLine.VirtualMachineId));
        }

        private Errorable<NodeEntitlements> SetNotBefore(NodeEntitlements entitlement)
        {
            if (string.IsNullOrEmpty(_commandLine.NotBefore))
            {
                // If the user does not specify a start instant for the token, we default to 'now'
                return Errorable.Success(entitlement.FromInstant(_now));
            }

            return _timestampParser.TryParse(_commandLine.NotBefore, "NotBefore")
                .Then(notBefore => Errorable.Success(entitlement.FromInstant(notBefore)));
        }

        private Errorable<NodeEntitlements> SetNotAfter(NodeEntitlements entitlement)
        {
            if (string.IsNullOrEmpty(_commandLine.NotAfter))
            {
                // If the user does not specify an expiry for the token, we default to 7days from 'now'
                return Errorable.Success(entitlement.UntilInstant(_now + TimeSpan.FromDays(7)));
            }

            return _timestampParser.TryParse(_commandLine.NotAfter, "NotAfter")
                .Then(notAfter => Errorable.Success(entitlement.UntilInstant(notAfter)));
        }

        private Errorable<NodeEntitlements> SetAudience(NodeEntitlements entitlement)
        {
            // if the user does not specify an audience, we use a default value to "self-sign"
            var audience = string.IsNullOrEmpty(_commandLine.Audience)
                ? Claims.DefaultAudience
                : _commandLine.Audience;

            return Errorable.Success(entitlement.WithAudience(audience));
        }

        private Errorable<NodeEntitlements> SetIssuer(NodeEntitlements entitlement)
        {
            // if the user does not specify an issuer, we use a default value to "self-sign"
            var issuer = string.IsNullOrEmpty(_commandLine.Issuer)
                ? Claims.DefaultIssuer
                : _commandLine.Issuer;

            return Errorable.Success(entitlement.WithIssuer(issuer));
        }

        private Errorable<NodeEntitlements> SetCpuCoreCount(NodeEntitlements entitlement)
        {
            // if the user does not specify a cpu core count, we default to the number of logical cores on the current machine
            var cpuCoreCount = _commandLine.CpuCoreCount ?? Environment.ProcessorCount;
            return Errorable.Success(entitlement.WithCpuCoreCount(cpuCoreCount));
        }

        private Errorable<NodeEntitlements> SetBatchAccountId(NodeEntitlements entitlement)
        {
            if (_commandLine.BatchAccountId == null)
            {
                return Errorable.Success(entitlement);
            }

            return Errorable.Success(entitlement.WithBatchAccountId(_commandLine.BatchAccountId));
        }

        private Errorable<NodeEntitlements> SetPoolId(NodeEntitlements entitlement)
        {
            if (_commandLine.PoolId == null)
            {
                return Errorable.Success(entitlement);
            }

            return Errorable.Success(entitlement.WithPoolId(_commandLine.PoolId));
        }

        private Errorable<NodeEntitlements> SetJobId(NodeEntitlements entitlement)
        {
            if (_commandLine.JobId == null)
            {
                return Errorable.Success(entitlement);
            }

            return Errorable.Success(entitlement.WithJobId(_commandLine.JobId));
        }

        private Errorable<NodeEntitlements> SetTaskId(NodeEntitlements entitlement)
        {
            if (_commandLine.TaskId == null)
            {
                return Errorable.Success(entitlement);
            }

            return Errorable.Success(entitlement.WithTaskId(_commandLine.TaskId));
        }

        private Errorable<NodeEntitlements> SetAddresses(NodeEntitlements entitlement)
        {
            var result = MultiErrorableBuilder.Start(entitlement);

            var addressResults = _commandLine.Addresses?.Count > 0
                ? _commandLine.Addresses.Select(TryParseIPAddress)
                : ListMachineIpAddresses();

            foreach (var addressResult in addressResults)
            {
                result = result.Apply(
                    e => addressResult.Then(addr => Errorable.Success(e.AddIpAddress(addr))));
            }

            return result.AsErrorable();
        }


        private static IEnumerable<Errorable<IPAddress>> ListMachineIpAddresses()
        {
            // No IP addresses specified by the user, default to using all from the current machine
            foreach (var i in NetworkInterface.GetAllNetworkInterfaces())
            {
                var properties = i.GetIPProperties();
                var unicast = properties.UnicastAddresses;
                if (unicast != null)
                {
                    foreach (var info in unicast)
                    {
                        // Strip out the ScopeId for any local IPv6 addresses
                        // (Can't just assign 0 to ScopeId, that doesn't work)
                        var bytes = info.Address.GetAddressBytes();
                        var ip = new IPAddress(bytes);

                        yield return Errorable.Success(ip);
                    }
                }
            }
        }

        private static Errorable<IPAddress> TryParseIPAddress(string address)
        {
            if (IPAddress.TryParse(address, out var ip))
            {
                return Errorable.Success(ip);
            }

            return Errorable.Failure<IPAddress>($"IP address '{address}' is not in an expected format (IPv4 and IPv6 supported).");
        }

        private Errorable<NodeEntitlements> SetApplications(NodeEntitlements entitlement)
        {
            var apps = _commandLine.ApplicationIds?.ToList();
            if (apps == null || apps.Count == 0)
            {
                return Errorable.Failure<NodeEntitlements>("No applications specified.");
            }

            foreach (var app in apps)
            {
                entitlement = entitlement.AddApplication(app);
            }

            return Errorable.Success(entitlement);
        }
    }

    public static class MultiErrorableBuilder
    {
        public static MultiErrorableBuilder<T> Start<T>(T value)
        {
            return MultiErrorableBuilder<T>.Start(value);
        }
    }

    public class MultiErrorableBuilder<T>
    {
        public T Value { get; }

        public IEnumerable<string> Errors { get; }

        private MultiErrorableBuilder(T value, IEnumerable<string> errors)
        {
            Value = value;
            Errors = errors;
        }

        public static MultiErrorableBuilder<T> Start(T value)
        {
            return new MultiErrorableBuilder<T>(value, new List<string>());
        }

        public MultiErrorableBuilder<T> Apply(
            Func<T, Errorable<T>> transformation) => transformation(Value).Match(
                whenSuccessful: value => new MultiErrorableBuilder<T>(value, Errors),
                whenFailure: errors => new MultiErrorableBuilder<T>(Value, Errors.Concat(errors)));

        public Errorable<T> AsErrorable() => Errors.Any()
            ? Errorable.Failure<T>(Errors)
            : Errorable.Success(Value);
    }
}

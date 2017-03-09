﻿using CommandLine;
using Microsoft.Extensions.Logging;

namespace Microsoft.Azure.Batch.SoftwareEntitlement
{
    public class OptionsBase
    {
        [Option("log-level", HelpText = "Specify the level of logging output (one of error, warning, information or debug; defaults to information)")]
        public LogLevel LogLevel { get; set; } = LogLevel.Information;
    }
}

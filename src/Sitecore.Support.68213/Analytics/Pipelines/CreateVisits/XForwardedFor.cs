using System;
using System.Linq;
using System.Net;
using Sitecore.Analytics.Configuration;
using Sitecore.Diagnostics;
using Sitecore.Analytics.Pipelines.CreateVisits;

namespace Sitecore.Support.Analytics.Pipelines.CreateVisits
{
  /// <summary>
  ///  Parses X-Forwarded-For header and updates IP on the visit.
  /// <para>
  /// Should be used only in scenarios where environment is located behind a load balancer that is <b>known to update this header</b>. Otherwise the header is spoofed easily and cannot be trusted.
  /// The processor extracts the <b>last</b> IP from the header, which is the public IP used to access the website. All other information is discarded.
  /// </para>
  /// </summary>
  public class XForwardedFor : CreateVisitProcessor
  {
    /// <summary>
    /// Gets or sets the header IP index.
    /// </summary>
    /// <value>
    /// The header IP index.
    /// </value>
    public int HeaderIpIndex { get; set; }

    /// <summary>
    /// Runs the processor.
    /// </summary>
    /// <param name="args">The arguments.</param>
    public override void Process(CreateVisitArgs args)
    {
      Assert.ArgumentNotNull(args, "args");

      string headerKey = AnalyticsSettings.ForwardedRequestHttpHeader;
      if (string.IsNullOrEmpty(headerKey))
      {
        return;
      }

      string header = args.Request.Headers[headerKey];
      if (string.IsNullOrEmpty(header))
      {
        return;
      }

      string ip = this.GetIpFromHeader(header);

      if (string.IsNullOrEmpty(ip))
      {
        LogWrongIp(headerKey, header);
        return;
      }

      IPAddress address;
      try
      {
        address = IPAddress.Parse(ip);
      }
      catch (FormatException)
      {
        LogWrongIp(headerKey, header);
        return;
      }

      args.Visit.Ip = address.GetAddressBytes();
    }

    /// <summary>
    /// Logs the wrong ip.
    /// </summary>
    /// <param name="headerKey">The header key.</param>
    /// <param name="header">The header.</param>
    private void LogWrongIp([CanBeNull] string headerKey, [CanBeNull] string header)
    {
      Log.Warn(string.Format("{0} header does not store a valid IP address ({1})", headerKey, header), this);
    }

    /// <summary>
    /// Gets IP from header.
    /// </summary>
    /// <param name="header">
    /// The header.
    /// </param>
    /// <returns>
    /// The <see cref="string"/>.
    /// </returns>
    [CanBeNull]
    protected virtual string GetIpFromHeader([NotNull] string header)
    {
      Assert.ArgumentNotNull(header, "header");

      string[] ips = header.Split(',');

      int index = this.HeaderIpIndex;
      string ip = index < ips.Length ? ips[index] : ips.LastOrDefault();
      if (string.IsNullOrEmpty(ip))
      {
        return null;
      }

      return ip.Trim();
    }
  }
}

// This file is part of Arad.SnmpSharp.
// 
// Arad.SnmpSharp is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// Arad.SnmpSharp is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with Arad.SnmpSharp.  If not, see <http://www.gnu.org/licenses/>.
// 

namespace Arad.SnmpSharp.Security;

/// <summary>
/// SNMP class translates SNMP version 3 report errors into error strings.
/// </summary>
public sealed class SNMPV3ReportError
{
    private SNMPV3ReportError()
    {
    }

    /// <summary>
    /// Search variable bindings list in the passed packet for usm error OIDs and return
    /// error string value.
    /// </summary>
    /// <param name="packet">Packet to search for error OIDs</param>
    /// <returns>Error string if found in the packet, otherwise an empty string.</returns>
    public static string TranslateError(SnmpV3Packet packet)
    {
        foreach (Vb v in packet.Pdu.VbList)
        {
            if (v.Oid.Compare(SnmpConstants.usmStatsUnsupportedSecLevels) == 0)
            {
                return $"usmStatsUnsupportedSecLevels: {v.Value}";
            }
            else if (v.Oid.Compare(SnmpConstants.usmStatsNotInTimeWindows) == 0)
            {
                return $"usmStatsNotInTimeWindows: {v.Value}";
            }
            else if (v.Oid.Compare(SnmpConstants.usmStatsUnknownSecurityNames) == 0)
            {
                return $"usmStatsUnknownSecurityNames: {v.Value}";
            }
            else if (v.Oid.Compare(SnmpConstants.usmStatsUnknownEngineIDs) == 0)
            {
                return $"usmStatsUnknownEngineIDs: {v.Value}";
            }
            else if (v.Oid.Compare(SnmpConstants.usmStatsWrongDigests) == 0)
            {
                return $"usmStatsWrongDigests: {v.Value}";
            }
            else if (v.Oid.Compare(SnmpConstants.usmStatsDecryptionErrors) == 0)
            {
                return $"usmStatsDecryptionErrors: {v.Value}";
            }
            else if (v.Oid.Compare(SnmpConstants.snmpUnknownSecurityModels) == 0)
            {
                return $"snmpUnknownSecurityModels: {v.Value}";
            }
            else if (v.Oid.Compare(SnmpConstants.snmpInvalidMsgs) == 0)
            {
                return $"snmpInvalidMsgs: {v.Value}";
            }
            else if (v.Oid.Compare(SnmpConstants.snmpUnknownPDUHandlers) == 0)
            {
                return $"snmpUnknownPDUHandlers: {v.Value}";
            }
        }
        return "";
    }
}
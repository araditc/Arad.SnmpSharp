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

namespace Arad.SnmpSharp;

/// <summary>
/// SNMP Version number enumeration
/// </summary>
public enum SnmpVersion
{
    /// <summary>
    /// SNMP version 1
    /// </summary>
    Ver1 = 0,
    /// <summary>
    /// SNMP version 2c
    /// </summary>
    Ver2 = 1,
    /// <summary>
    /// SNMP version 3
    /// </summary>
    Ver3 = 3
}
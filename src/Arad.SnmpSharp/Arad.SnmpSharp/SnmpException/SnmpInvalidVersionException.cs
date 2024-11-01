﻿// This file is part of Arad.SnmpSharp.
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

namespace Arad.SnmpSharp.SnmpException;

/// <summary>
/// Exception thrown when invalid SNMP version was encountered in the packet
/// </summary>
public class SnmpInvalidVersionException: SnmpException
{
    /// <summary>
    /// Standard constructor
    /// </summary>
    /// <param name="msg">Exception error message</param>
    public SnmpInvalidVersionException(string msg)
        : base(msg)
    {
		}
}
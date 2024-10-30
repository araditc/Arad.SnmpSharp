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

namespace Arad.SnmpSharp.Types;

/// <summary>SNMPv2 NoSuchObject error</summary>
/// <remarks>
/// NoSuchObject is returned by the agent in response to a SNMP version 2 request 
/// when requested object does not exist in its MIB.
/// This value is returned as a <seealso cref="Vb.Value"/> with data of length 0
/// 
/// For example:
/// <code lang="cs">
/// // [... prepare for a get operation ...]
/// Pdu response = target.Request(outpdu, params);
/// foreach(Vb vb in response.VbList) {
///		if( vb.Value is NoSuchObject ) {
///			return "Requested MIB variable does not exist on the agent.";
///		}
///	}
/// </code>
/// </remarks>
[Serializable]
public class NoSuchObject:V2Error, ICloneable
{		
		
    /// <summary>Constructor.</summary>
    public NoSuchObject():base()
    {
			_asnType = SnmpConstants.SMI_NOSUCHOBJECT;
		}
    /// <summary>
    /// Constructor
    /// </summary>
    /// <param name="second">
    /// Source for data to initialize this instance with.
    /// 
    /// Irrelevant for this type since no data is stored in the class.
    /// </param>
    public NoSuchObject(NoSuchObject second):base(second)
    {
		}

    /// <summary> Returns a duplicate object of self.</summary>
    /// <returns> A duplicate of self</returns>
    public override Object Clone()
    {
			// just create a new object. it doesn't hold any data anyway
			return new NoSuchObject();
		}

    /// <summary>Decode ASN.1 encoded no-such-object SNMP version 2 MIB value</summary>
    /// <param name="buffer">The encoded buffer</param>
    /// <param name="offset">The offset of the first byte of encoded data</param>
    /// <returns>Buffer position after the decoded value</returns>
    public override int decode(byte[] buffer, int offset)
    {
			int headerLength;
			byte asnType = ParseHeader(buffer, ref offset, out headerLength);
			if (asnType != Type)
				throw new SnmpException.SnmpException("Invalid ASN.1 type");

			if (headerLength != 0)
				throw new SnmpException.SnmpException("Invalid ASN.1 length");

			return offset;
		}

    /// <summary>
    /// ASN.1 encode no-such-object SNMP version 2 MIB value
    /// </summary>
    /// <param name="buffer">MutableByte reference to append encoded variable to</param>
    public override void encode(MutableByte buffer)
    {
			BuildHeader(buffer, Type, 0);
		}
		
    /// <summary> Returns the string representation of the object.</summary>
    /// <returns>string representation of the class</returns>
    public override string ToString()
    {
			return "SNMP No-Such-Object";
		}
}
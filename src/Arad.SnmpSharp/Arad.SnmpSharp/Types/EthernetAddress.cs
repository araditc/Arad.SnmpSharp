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

/// <summary>EthernetAddress class encapsulates a 6 byte Octetstring
/// representing an Ethernet MAC address.
/// </summary>
/// <remarks>THis class doesn't not represent a distinct ASN.1 data type. It is a helper
/// class to allow users to perform MAC address specific operations on Octetstring values.</remarks>
[Serializable]
public class EthernetAddress : Octetstring, ICloneable
{
    /// <summary>Constructor. Initialize the class to 0000.0000.0000
    /// </summary>
    public EthernetAddress()
        : base(new byte[] { 0, 0, 0, 0, 0, 0 })
    {
		}
		
    /// <summary>
    /// Constructor. Initialize the class with the value of the byte array.
    /// </summary>
    /// <param name="data">Byte array whose value is used to initialize the class.
    /// </param>
    public EthernetAddress(byte[] data)
        :base(data)
    {
			if (data.Length < 6)
				throw new System.ArgumentException("Buffer underflow error converting IP address");
			else if (data.Length > 6)
				throw new System.ArgumentException("Buffer overflow error converting IP address");
			base.Set(data);
		}
		
    /// <summary>
    /// Constructor. Initialize the class with the value from the argument class.
    /// </summary>
    /// <param name="second">Class whose value is copied to initialize this class.
    /// </param>
    public EthernetAddress(EthernetAddress second)
        : base()
    {
			base.Set(second.ToArray());
		}
		
    /// <summary>Constructor. Initialize the class with the value from the <see cref="Octetstring"/> argument.
    /// </summary>
    /// <param name="second">Class whose value is used to initialize this class.
    /// </param>
    public EthernetAddress(Octetstring second)
        : this()
    {
			if (second.Length < 6)
				throw new System.ArgumentException("Buffer underflow error converting IP address");
			else if (Length > 6)
				throw new System.ArgumentException("Buffer overflow error converting IP address");
			base.Set(second);
		}
		
    /// <summary> Create a new object that is a duplicate of the
    /// current object.
    /// </summary>
    /// <returns> A newly created duplicate object.
    /// </returns>
    public override System.Object Clone()
    {
			return new EthernetAddress(this);
		}

    /// <summary>Parses hex string representing an Ethernet MAC address to the enternal format. Ethernet
    /// address has to contain 12 hex characters (1-9 or A-F) to be parsed correctly. Special formatting is
    /// ignored so both 0000.0010.0000 and 00-00-00-10-00-00 will be parsed ok.
    /// </summary>
    /// <param name="value">Ethernet address represented as a string.
    /// </param>
    public override void Set(string value)
    {
			if( value == null || value.Length <= 0 )
				throw new ArgumentException("Invalid argument. string is empty.");
			string workstring = (string)value.Clone();
			for (int cnt = 0; cnt < value.Length; cnt++)
			{
				if (!Char.IsNumber(workstring[cnt]) && Char.ToUpper(workstring[cnt]) != 'A' &&
					Char.ToUpper(workstring[cnt]) != 'B' && Char.ToUpper(workstring[cnt]) != 'C' &&
					Char.ToUpper(workstring[cnt]) != 'D' && Char.ToUpper(workstring[cnt]) != 'E' &&
					Char.ToUpper(workstring[cnt]) != 'F')
				{
					workstring.Remove(cnt, 1);
					cnt -= 1;
				}
			}
			if (workstring.Length != 12)
			{
				throw new ArgumentException("Invalid Ethernet address format.");
			}
			int pos = 0;
			int bufpos = 0;
			while (pos + 2 < workstring.Length)
			{
				string val = workstring.Substring(pos, 2);
				byte v = Byte.Parse(val, NumberStyles.HexNumber);
				_data[bufpos++] = v;
				pos += 2;
			}
		}
		
    /// <summary>
    /// Return Ethernet MAC address as a string formatted as: xxxx.xxxx.xxxx
    /// </summary>
    /// <returns>string representation of the object value.</returns>
    public override string ToString()
    {
			return string.Format(CultureInfo.CurrentCulture,"{0:x2}{1:x2}.{2:x2}{3:x2}.{4:x2}{5:x2}", _data[0], _data[1], _data[2], _data[3], _data[4], _data[5]);
		}
}
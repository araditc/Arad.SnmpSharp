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

namespace Arad.SnmpSharp.Security
{
	/// <summary>
	/// Privacy class for AES 192-bit encryption. This is a helper class. Full functionality is implemented
	/// in <see cref="PrivacyAES"/> parent class.
	/// </summary>
	public class PrivacyAES192 : PrivacyAES
	{
		/// <summary>
		/// Standard constructor initializes encryption key size in the parent <see cref="PrivacyAES"/> class to 24 bytes (192 bit).
		/// </summary>
		public PrivacyAES192()
			: base(24)
		{
		}

		/// <summary>
		/// Returns privacy protocol name "AES192".
		/// </summary>
		public override string Name
		{
			get
			{
				return "AES192";
			}
		}
	}
}

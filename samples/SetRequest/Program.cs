using System;
using System.Net;

using Arad.SnmpSharp;
using Arad.SnmpSharp.Types;


namespace SetRequest;

internal class Program
{
    static void Main(string[] args)
    {
        // Prepare target
        UdpTarget target = new((IPAddress)new IpAddress("host-name"));
        // Create a SET PDU
        Pdu pdu = new(PduType.Set);
        // Set sysLocation.0 to a new string
        pdu.VbList.Add(new("1.3.6.1.2.1.1.6.0"), new Octetstring("Some other value"));
        // Set a value to integer
        pdu.VbList.Add(new("1.3.6.1.2.1.67.1.1.1.1.5.0"), new Integer32(500));
        // Set a value to unsigned integer
        pdu.VbList.Add(new("1.3.6.1.2.1.67.1.1.1.1.6.0"), new UInteger32(101));
        // Set Agent security parameters
        AgentParameters aparam = new(SnmpVersion.Ver2, new("private"));
        // Response packet
        SnmpV2Packet response;
        try
        {
            // Send request and wait for response
            response = target.Request(pdu, aparam) as SnmpV2Packet;
        }
        catch (Exception ex)
        {
            // If exception happens, it will be returned here
            Console.WriteLine($"Request failed with exception: {ex.Message}");
            target.Close();
            return;
        }
        // Make sure we received a response
        if (response == null)
        {
            Console.WriteLine("Error in sending SNMP request.");
        }
        else
        {
            // Check if we received an SNMP error from the agent
            if (response.Pdu.ErrorStatus != 0)
            {
                Console.WriteLine("SNMP agent returned ErrorStatus {0} on index {1}", response.Pdu.ErrorStatus, response.Pdu.ErrorIndex);
            }
            else
            {
                // Everything is ok. Agent will return the new value for the OID we changed
                Console.WriteLine("Agent response {0}: {1}", response.Pdu[0].Oid, response.Pdu[0].Value);
            }
        }
    }
}
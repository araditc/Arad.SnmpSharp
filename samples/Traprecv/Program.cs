using System;
using System.Net.Sockets;
using System.Net;

using Arad.SnmpSharp;

namespace Traprecv;

internal class Program
{
    static void Main(string[] args)
    {
        // Construct a socket and bind it to the trap manager port 162
        Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        IPEndPoint ipep = new(IPAddress.Any, 162);
        EndPoint ep = ipep;
        socket.Bind(ep);
        // Disable timeout processing. Just block until packet is received
        socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, 0);
        bool run = true;
        int inlen = -1;
        while (run)
        {
            byte[] indata = new byte[16 * 1024];
            // 16KB receive buffer int inlen = 0;
            IPEndPoint peer = new(IPAddress.Any, 0);
            EndPoint inep = peer;
            try
            {
                inlen = socket.ReceiveFrom(indata, ref inep);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception {0}", ex.Message);
                inlen = -1;
            }
            if (inlen > 0)
            {
                // Check protocol version int
                int ver = SnmpPacket.GetProtocolVersion(indata, inlen);
                if (ver == (int)SnmpVersion.Ver1)
                {
                    // Parse SNMP Version 1 TRAP packet
                    SnmpV1TrapPacket pkt = new();
                    pkt.decode(indata, inlen);
                    Console.WriteLine("** SNMP Version 1 TRAP received from {0}:", inep);
                    Console.WriteLine("*** Trap generic: {0}", pkt.Pdu.Generic);
                    Console.WriteLine("*** Trap specific: {0}", pkt.Pdu.Specific);
                    Console.WriteLine("*** Agent address: {0}", pkt.Pdu.AgentAddress);
                    Console.WriteLine("*** Timestamp: {0}", pkt.Pdu.TimeStamp.ToString());
                    Console.WriteLine("*** VarBind count: {0}", pkt.Pdu.VbList.Count);
                    Console.WriteLine("*** VarBind content:");
                    foreach (Vb v in pkt.Pdu.VbList)
                    {
                        Console.WriteLine("**** {0} {1}: {2}", v.Oid, SnmpConstants.GetTypeName(v.Value.Type), v.Value);
                    }
                    Console.WriteLine("** End of SNMP Version 1 TRAP data.");
                }
                else
                {
                    // Parse SNMP Version 2 TRAP packet
                    SnmpV2Packet pkt = new();
                    pkt.decode(indata, inlen);
                    Console.WriteLine("** SNMP Version 2 TRAP received from {0}:", inep);
                    if (pkt.Pdu.Type != PduType.V2Trap)
                    {
                        Console.WriteLine("*** NOT an SNMPv2 trap ****");
                    }
                    else
                    {
                        Console.WriteLine("*** Community: {0}", pkt.Community);
                        Console.WriteLine("*** VarBind count: {0}", pkt.Pdu.VbList.Count);
                        Console.WriteLine("*** VarBind content:");
                        foreach (Vb v in pkt.Pdu.VbList)
                        {
                            Console.WriteLine("**** {0} {1}: {2}",
                                              v.Oid, SnmpConstants.GetTypeName(v.Value.Type), v.Value);
                        }
                        Console.WriteLine("** End of SNMP Version 2 TRAP data.");
                    }
                }
            }
            else
            {
                if (inlen == 0)
                    Console.WriteLine("Zero length packet received.");
            }
        }
    }
}
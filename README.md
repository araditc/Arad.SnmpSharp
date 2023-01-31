# Arad.SnmpSharp
Simple Network Management Protocol (SNMP) .Net library written in C# . DotNet implementation of SNMP protocol V1,V2 and V3

### NuGet 
You can download this package from [NuGet](https://www.nuget.org/packages/Arad.SnmpSharp/)

## Features
* SNMP v1 Get, Get-Next, Set, Trap
* SNMP v2c Get, Get-Next, Get-Bulk, Set, Trap, Inform
* SNMP v3 Get, Get-Next, Get-Bulk, Set, Trap, Inform
* SNMP v3 privacy DES, AES-128, AES-192, AES-256, Triple-DES
* SNMP v3 authentication MD5, SHA-1

Support for Get, Get-Next, Get-Bulk and Set requests, Response and Report replies and Trap, V2Trap and Inform Notifications is implemented. SNMP version 1 Traps have a dedicated packet class SnmpV1TrapPacket because they are substantially different from other SNMP version 1 packets. SNMP version 2 and 3 V2Trap parsing is included in the general request/response parsing class for each protocol. Inform handling for both SNMP version 2 and 3 is included and tested. In version 3, V2Trap and Inform support for authentication and privacy is included.

SNMP version 3 currently support noAuthNoPriv (no privacy and no authentication) security model, authNoPriv using MD5 and SHA-1 authentication and authPriv using, again, MD5 and SHA-1 authentication with DES, AES-128, AES-192, AES-256 and TripleDES privacy encryption.

Library is fully self contained. This means that it does not depend on any classes or libraries, other then available as part of the .Net framework. Encryption functionality is implemented using System.Security.Cryptography name space. I have decided to use .NET provided crypto to avoid having to worry about international distribution of the library. In other words, if your .NET distribution supports System.Security.Cryptography namespace with MD5, SHA-1, DES, Rijndael and TripleDES classes, you are good to go.

#  EXAMPLES

## RECEIVE SNMP V1 AND 2C TRAPS
SNMP Traps are used by SNMP agents to notify managers of events.

```C# 
 static void Main(string[] args)
        {
            // Construct a socket and bind it to the trap manager port 162
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            IPEndPoint ipep = new IPEndPoint(IPAddress.Any, 162);
            EndPoint ep = (EndPoint)ipep;
            socket.Bind(ep);
            // Disable timeout processing. Just block until packet is received
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, 0);
            bool run = true;
            int inlen = -1;
            while (run)
            {
                byte[] indata = new byte[16 * 1024];
                // 16KB receive buffer int inlen = 0;
                IPEndPoint peer = new IPEndPoint(IPAddress.Any, 0);
                EndPoint inep = (EndPoint)peer;
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
                        SnmpV1TrapPacket pkt = new SnmpV1TrapPacket();
                        pkt.decode(indata, inlen);
                        Console.WriteLine("** SNMP Version 1 TRAP received from {0}:", inep.ToString());
                        Console.WriteLine("*** Trap generic: {0}", pkt.Pdu.Generic);
                        Console.WriteLine("*** Trap specific: {0}", pkt.Pdu.Specific);
                        Console.WriteLine("*** Agent address: {0}", pkt.Pdu.AgentAddress.ToString());
                        Console.WriteLine("*** Timestamp: {0}", pkt.Pdu.TimeStamp.ToString());
                        Console.WriteLine("*** VarBind count: {0}", pkt.Pdu.VbList.Count);
                        Console.WriteLine("*** VarBind content:");
                        foreach (Vb v in pkt.Pdu.VbList)
                        {
                            Console.WriteLine("**** {0} {1}: {2}", v.Oid.ToString(), SnmpConstants.GetTypeName(v.Value.Type), v.Value.ToString());
                        }
                        Console.WriteLine("** End of SNMP Version 1 TRAP data.");
                    }
                    else
                    {
                        // Parse SNMP Version 2 TRAP packet
                        SnmpV2Packet pkt = new SnmpV2Packet();
                        pkt.decode(indata, inlen);
                        Console.WriteLine("** SNMP Version 2 TRAP received from {0}:", inep.ToString());
                        if ((PduType)pkt.Pdu.Type != PduType.V2Trap)
                        {
                            Console.WriteLine("*** NOT an SNMPv2 trap ****");
                        }
                        else
                        {
                            Console.WriteLine("*** Community: {0}", pkt.Community.ToString());
                            Console.WriteLine("*** VarBind count: {0}", pkt.Pdu.VbList.Count);
                            Console.WriteLine("*** VarBind content:");
                            foreach (Vb v in pkt.Pdu.VbList)
                            {
                                Console.WriteLine("**** {0} {1}: {2}",
                                   v.Oid.ToString(), SnmpConstants.GetTypeName(v.Value.Type), v.Value.ToString());
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
```

## HOW – SNMP SET REQUEST

How to make an SNMP Set request
When making an SNMP Set request, you need to supply a pair of values in your Pdu, OID that you wish to change, and the value to change it to. To be able to change an OID value, first that OID needs to be read-write (you can find this out by reading the MIB files and checking the ACCESS value) and you will need to know what kind of value that OID will accept. It is important to send the right kind of value to the agent to perform a Set operation. If you send a wrong value, for example a OctetString to an OID that accepts Integer32 values, agent will return WrongType error in the SnmpPacket.Pdu.ErrorStatus variable.

In this example we are changing sysLocation.0 MIB variable value. sysLocation.0 takes a value of type OctetString plus two random OIDs set to integer and unsigned integer to demonstrate setting numeric values.

```C#
 static void Main(string[] args)
        {
            // Prepare target
            UdpTarget target = new UdpTarget((IPAddress)new IpAddress("host-name"));
            // Create a SET PDU
            Pdu pdu = new Pdu(PduType.Set);
            // Set sysLocation.0 to a new string
            pdu.VbList.Add(new Oid("1.3.6.1.2.1.1.6.0"), new Octetstring("Some other value"));
            // Set a value to integer
            pdu.VbList.Add(new Oid("1.3.6.1.2.1.67.1.1.1.1.5.0"), new Integer32(500));
            // Set a value to unsigned integer
            pdu.VbList.Add(new Oid("1.3.6.1.2.1.67.1.1.1.1.6.0"), new UInteger32(101));
            // Set Agent security parameters
            AgentParameters aparam = new AgentParameters(SnmpVersion.Ver2, new Octetstring("private"));
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
                Console.WriteLine(string.Format("Request failed with exception: {0}", ex.Message));
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
                    Console.WriteLine(string.Format("SNMP agent returned ErrorStatus {0} on index {1}",
                        response.Pdu.ErrorStatus, response.Pdu.ErrorIndex));
                }
                else
                {
                    // Everything is ok. Agent will return the new value for the OID we changed
                    Console.WriteLine(string.Format("Agent response {0}: {1}",
                        response.Pdu[0].Oid.ToString(), response.Pdu[0].Value.ToString()));
                }
            }
        }
```


To re-assure anybody concerned, this project is open source and will remain open source and free to all. 

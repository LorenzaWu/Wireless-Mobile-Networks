/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
// Default Network Topology
//
// Wifi 10.1.1.0
// AP
// * *
// | |
// n1 n0
//
//Consider a Wifi access point (AP) and a base station (STA), which are both static.
//The STA can communicate with the AP only when it is within a certain distance
//from the AP. Beyond that range, the two nodes can't receive each others signals.
// 
// Given below is a code to simulate the said scenario with ns3.
// STA sends a packet to the AP; AP echoes it back to the base station.
// The AP is located at position (x, y) = (0, 0). STA is at (xDistance, 0)
// (all distances in meter). Default value of xDistance is set to 10. [Lines #76, #131]
//  
//  Increase the value of xDistance in the code and find out the maximum distance upto which two way communication is possible. This can be verified from the output of the code, which will show the STA has received reply from the AP (indicated by IP address).
// Node #0 is the AP, #1 is a base station
// #1 sends UDP echo mesg to the AP; AP sends a UDP response back to the node
// Communication is possible only when the station is within a certain distance from the AP

// Mobility model is used for calculating propagation loss and propagation delay.
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/applications-module.h"
#include "ns3/network-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/config-store-module.h"

using namespace ns3;
NS_LOG_COMPONENT_DEFINE ("Lab_project");
void
PrintLocations (NodeContainer nodes, std::string header)
{
    std::cout << header << std::endl;
    for(NodeContainer::Iterator iNode = nodes.Begin (); iNode != nodes.End (); ++iNode)
    {
        Ptr<Node> object = *iNode;
        Ptr<MobilityModel> position = object->GetObject<MobilityModel> ();
        NS_ASSERT (position != 0);
        Vector pos = position->GetPosition ();
        std::cout << "(" << pos.x << ", " << pos.y << ", " << pos.z << ")" << std::endl;
    }
    std::cout << std::endl;
}
void
PrintAddresses(Ipv4InterfaceContainer container, std::string header)
{
    std::cout << header << std::endl;
    uint32_t nNodes = container.GetN ();
    for (uint32_t i = 0; i < nNodes; ++i)
    {
        std::cout << container.GetAddress(i, 0) << std::endl;
    }
    std::cout << std::endl;
}

int
main (int argc, char *argv[])
{
    bool verbose = true;
    bool enable_flow_monitor = true;
    uint32_t nWifi = 5;
    /** Change this parameter and verify the output */
    double xDistance = 110.0;
    unsigned maximum_packets = 50;
    int packet_size = 1024;
    
    
    CommandLine cmd;
    cmd.AddValue ("xDistance", "Distance between two nodes along x-axis", xDistance);
    cmd.AddValue ("maximum_packets", "Maximum number of packets to be send by clients.", maximum_packets);
    cmd.AddValue ("packet_size", "Size of each packet clients will send.", packet_size);
    
    cmd.Parse (argc,argv);
    if (verbose)
    {
        LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
        LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);
    }
    // 1. Create the nodes and hold them in a container
    NodeContainer wifiStaNodes,
    wifiApNode;
    
    wifiStaNodes.Create (nWifi);
    wifiApNode = wifiStaNodes.Get (0);
    // 2. Create channel for communication
    YansWifiChannelHelper channel = YansWifiChannelHelper::Default ();
    YansWifiPhyHelper phy = YansWifiPhyHelper::Default ();
    phy.SetChannel (channel.Create ());
    WifiHelper wifi = WifiHelper::Default ();
    wifi.SetRemoteStationManager ("ns3::AarfWifiManager");
    
    NqosWifiMacHelper mac = NqosWifiMacHelper::Default ();
    // 3a. Set up MAC for base stations
    Ssid ssid = Ssid ("ns-3-ssid");
    mac.SetType ("ns3::StaWifiMac",
                 "Ssid", SsidValue (ssid),
                 "ActiveProbing", BooleanValue (false));
    //create a device for each wireless station node
    NetDeviceContainer staDevices;
    staDevices = wifi.Install (phy, mac, wifiStaNodes.Get(1));
    staDevices.Add(wifi.Install (phy, mac, wifiStaNodes.Get(2)));
    staDevices.Add(wifi.Install (phy, mac, wifiStaNodes.Get(3)));
    staDevices.Add( wifi.Install (phy, mac, wifiStaNodes.Get(4)));
    // 3b. Set up MAC for AP
    mac.SetType ("ns3::ApWifiMac",
                 "Ssid", SsidValue (ssid),
                 "BeaconGeneration", BooleanValue (true),
                 "BeaconInterval", TimeValue (Seconds (5)));
    NetDeviceContainer apDevice;
    apDevice = wifi.Install (phy, mac, wifiApNode);
    // 4. Set mobility of the nodes
    MobilityHelper mobility;
    // All space coordinates in meter
    ///116 is the maximum distance apart for both side to communicate correctly
    Ptr<ListPositionAllocator> position_alloc = CreateObject<ListPositionAllocator> ();
  
    position_alloc->Add (Vector (0.0, 0.0, 0.0)); //E
    position_alloc->Add (Vector (-59.0, 57.0, 0.0)); //A
    position_alloc->Add (Vector (59.0, 57.0, 0.0)); //B
    position_alloc->Add (Vector (59.0, -57.0, 0.0)); //C
    position_alloc->Add (Vector (-59.0, -57.0, 0.0)); //D
    mobility.SetPositionAllocator (position_alloc);
    ///This is like a rectangle topology with E in the middle
    
    mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
    mobility.Install (wifiStaNodes);

    // 5.Add Internet layers stack
    InternetStackHelper stack;
    stack.Install (wifiStaNodes);
    // 6. Assign IP address to each device
    Ipv4AddressHelper address;
    Ipv4InterfaceContainer wifiInterfaces,
    wifiApInterface;
    address.SetBase ("10.1.1.0", "255.255.255.0");
    wifiApInterface = address.Assign (apDevice);
    wifiInterfaces = address.Assign (staDevices);
   
    int udp_port1 = 9;
    int udp_port2 = 10;
    int A = 1;
    int B = 2;
    int C = 3;
    int D = 4;
    
    // Server 1 (C) and Client 1 (A) 
    // 7a. Create and setup applications (traffic sink)
    UdpEchoServerHelper echoServer (udp_port1); // Port # 9
    ApplicationContainer serverApps = echoServer.Install (wifiStaNodes.Get(C)); //C
    serverApps.Start (Seconds (1.0));
    serverApps.Stop (Seconds (53.0));
    //serverApps->SetAllowBroadcast(true);
    
    // 7b. Create and setup applications (traffic source)
    //UdpEchoClientHelper echoClient (wifiApInterface.GetAddress (0), 9);
    UdpEchoClientHelper echoClient (wifiInterfaces.GetAddress(C-1), udp_port1); //C
    echoClient.SetAttribute ("MaxPackets", UintegerValue (maximum_packets));
    echoClient.SetAttribute ("Interval", TimeValue (Seconds (1.)));
    echoClient.SetAttribute ("PacketSize", UintegerValue (packet_size));
    
    ApplicationContainer clientApps = echoClient.Install (wifiStaNodes.Get (A)); //A 
    clientApps.Start (Seconds (2.0));
    clientApps.Stop (Seconds (53.0));
    
    //server 2 (D) and client 2 (B)
    // 7a. Create and setup applications (traffic sink)
    UdpEchoServerHelper echoServer2 (udp_port2); // Port # 10
    ApplicationContainer serverApps2 = echoServer2.Install (wifiStaNodes.Get(D)); //D
    serverApps2.Start (Seconds (1.0));
    serverApps2.Stop (Seconds (53.0));
    // 7b. Create and setup applications (traffic source)
    UdpEchoClientHelper echoClient2 (wifiInterfaces.GetAddress(D-1), udp_port2); //D
    echoClient2.SetAttribute ("MaxPackets", UintegerValue (maximum_packets));
    echoClient2.SetAttribute ("Interval", TimeValue (Seconds (1.0)));
    echoClient2.SetAttribute ("PacketSize", UintegerValue (packet_size));
    
    ApplicationContainer clientApps2 = echoClient2.Install (wifiStaNodes.Get (B)); //B 
    clientApps2.Start (Seconds (2.4));
    clientApps2.Stop (Seconds (53.0));
    
    Ipv4GlobalRoutingHelper::PopulateRoutingTables ();
    Simulator::Stop (Seconds (54.0));
    
    // 8. Enable tracing (optional)
    phy.EnablePcapAll ("lab_project", true);
    
    AsciiTraceHelper ascii;
    phy.EnableAsciiAll (ascii.CreateFileStream ("lab_project.tr"));
    
    Ptr<FlowMonitor> flow_monitor;
    if (enable_flow_monitor)
    {
      FlowMonitorHelper flow_monitor_helper;
      flow_monitor = flow_monitor_helper.InstallAll();
    }
    
    PrintAddresses(wifiInterfaces, "IP addresses of base stations");
    PrintAddresses(wifiApInterface, "IP address of AP");
    PrintLocations(wifiStaNodes, "Location of all nodes");
    
    Simulator::Run ();
    if (enable_flow_monitor)
    {
      flow_monitor->CheckForLostPackets();
      flow_monitor->SerializeToXmlFile("project-part1.xml", true, true);
    }
    Simulator::Destroy ();
    
    return 0;
}

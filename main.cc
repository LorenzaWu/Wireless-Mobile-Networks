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
NS_LOG_COMPONENT_DEFINE ("Lab_project_part2");
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

class MyApp : public Application 
{
public:

  MyApp ();
  virtual ~MyApp();

  void Setup (Ptr<Socket> socket, Address address, uint32_t packetSize, uint32_t nPackets, DataRate dataRate);

private:
  virtual void StartApplication (void);
  virtual void StopApplication (void);

  void ScheduleTx (void);
  void SendPacket (void);

  Ptr<Socket>     m_socket;
  Address         m_peer;
  uint32_t        m_packetSize;
  uint32_t        m_nPackets;
  DataRate        m_dataRate;
  EventId         m_sendEvent;
  bool            m_running;
  uint32_t        m_packetsSent;
};

MyApp::MyApp ()
  : m_socket (0), 
    m_peer (), 
    m_packetSize (0), 
    m_nPackets (0), 
    m_dataRate (0), 
    m_sendEvent (), 
    m_running (false), 
    m_packetsSent (0)
{
}

MyApp::~MyApp()
{
  m_socket = 0;
}

void
MyApp::Setup (Ptr<Socket> socket, Address address, uint32_t packetSize, uint32_t nPackets, DataRate dataRate)
{
  m_socket = socket;
  m_peer = address;
  m_packetSize = packetSize;
  m_nPackets = nPackets;
  m_dataRate = dataRate;
}

void
MyApp::StartApplication (void)
{
  m_running = true;
  m_packetsSent = 0;
  m_socket->Bind ();
  m_socket->Connect (m_peer);
  SendPacket ();
}

void 
MyApp::StopApplication (void)
{
  m_running = false;

  if (m_sendEvent.IsRunning ())
    {
      Simulator::Cancel (m_sendEvent);
    }

  if (m_socket)
    {
      m_socket->Close ();
    }
}

void 
MyApp::SendPacket (void)
{
  Ptr<Packet> packet = Create<Packet> (m_packetSize);
  m_socket->Send (packet);

  if (++m_packetsSent < m_nPackets)
    {
      ScheduleTx ();
    }
}

void 
MyApp::ScheduleTx (void)
{
  if (m_running)
    {
      Time tNext (Seconds (m_packetSize * 8 / static_cast<double> (m_dataRate.GetBitRate ())));
      m_sendEvent = Simulator::Schedule (tNext, &MyApp::SendPacket, this);
    }
}

int packet_received_count = 0;

void
ReceivePacket(Ptr<const Packet> packet, const Address & addr)
{
  packet_received_count += 1;
	std::cout << Simulator::Now ().GetSeconds () << "\t" << "Packet number: " << packet_received_count << "\t" << packet->GetSize() << "\t from " << addr << "\n";
}

void
DevTxTrace (std::string context, Ptr<const Packet> p, const Address & addr)
{
  std::cout << "TX to= " << addr << "packet: " << *p << std::endl;
}

int
main (int argc, char *argv[])
{
    bool verbose = true;
    bool enable_flow_monitor = true;
    uint32_t nWifi = 5;
    /** Change this parameter and verify the output */
    double xDistance = 110.0;
    int maximum_packets = 50;
    unsigned packet_size = 1024; 
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
    std::cout << "Node A:\t" << staDevices.Get(0)->GetAddress() << std::endl;
    std::cout << "Node B:\t" << staDevices.Get(1)->GetAddress() << std::endl;
    std::cout << "Node C:\t" << staDevices.Get(2)->GetAddress() << std::endl;
    std::cout << "Node D:\t" << staDevices.Get(3)->GetAddress() << std::endl;
    // 3b. Set up MAC for AP
    mac.SetType ("ns3::ApWifiMac",
                 "Ssid", SsidValue (ssid),
                 "BeaconGeneration", BooleanValue (true),
                 "BeaconInterval", TimeValue (Seconds (5)));
    NetDeviceContainer apDevice;
    apDevice = wifi.Install (phy, mac, wifiApNode);
    std::cout << "Node E:\t" << apDevice.Get(0)->GetAddress() << std::endl;
    // 4. Set mobility of the nodes
    MobilityHelper mobility;
    // All space coordinates in meter
    ///116 is the maximum distance apart for both side to communicate correctly
    Ptr<ListPositionAllocator> position_alloc = CreateObject<ListPositionAllocator> ();
  
    position_alloc->Add (Vector (0.0, 0.0, 0.0)); //E
    position_alloc->Add (Vector (-59.0, 50.0, 0.0)); //A
    position_alloc->Add (Vector (59.0, 50.0, 0.0)); //B
    position_alloc->Add (Vector (59.0, -50.0, 0.0)); //C
    position_alloc->Add (Vector (-59.0, -50.0, 0.0)); //D
    mobility.SetPositionAllocator (position_alloc);
    
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
    
    //wifiApInterface.SetBroadcast(true);
    int udp_port1 = 9;
    int udp_port2 = 10;
    //int E = 0;
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
    echoClient.SetAttribute ("Interval", TimeValue (Seconds (1.0)));
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
    
    /*
    // A --> E -->)))) C
    //create packet sink, we can think of this as server
    Address sink_address(InetSocketAddress (wifiApInterface.GetAddress(0), udp_port1)); //interface for E
    PacketSinkHelper packet_sink_helper ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny(), udp_port1));
    ApplicationContainer sink_apps = packet_sink_helper.Install(wifiStaNodes.Get(E)); // E is the sink (server)
    sink_apps.Start(Seconds(1.0));
    sink_apps.Stop(Seconds(100.0));
    
    //create source, we can think of this as the client
    Ptr<Socket> ns3_udp_socket = Socket::CreateSocket(wifiStaNodes.Get(A), UdpSocketFactory::GetTypeId()); //source at A
    
    // Create UDP application at A
    Ptr<MyApp> app = CreateObject<MyApp> ();
    app->Setup (ns3_udp_socket, sink_address, packet_size, npackets, DataRate("1Mbps")); 
    wifiStaNodes.Get(A)->AddApplication (app);
    app->SetStartTime (Seconds(2.0));
    app->SetStopTime (Seconds(100.0));
    */
    // B --> E -->)))) D
    //create packet sink, we can think of this as server
    /*
    Address sink_address2(InetSocketAddress (wifi_interfaces.GetAddress(B), udp_port2)); //interface for D
    PacketSinkHelper packet_sink_helper2 ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny(), udp_port2));
    ApplicationContainer sink_apps2 = packet_sink_helper2.Install(wifi_nodes.Get(B)); // D is the sink (server)
    sink_apps2.Start(Seconds(1.0));
    sink_apps2.Stop(Seconds(100.0));
    */
    /*
    //create source, we can think of this as the client
    Ptr<Socket> ns3_udp_socket2 = Socket::CreateSocket(wifiStaNodes.Get(B), UdpSocketFactory::GetTypeId()); //source at B
    
    // Create UDP application at B
    Ptr<MyApp> app2 = CreateObject<MyApp> ();
    app2->Setup (ns3_udp_socket2, sink_address, packet_size, npackets, DataRate("1.3Mbps")); 
    wifiStaNodes.Get(B)->AddApplication (app2);
    app2->SetStartTime (Seconds(2.1));
    app2->SetStopTime (Seconds(100.0));
    */
    //packet_sink_helper.SetAllowBroadcast(true);    
    
    //trace received packets
    //Config::ConnectWithoutContext ("/NodeList/*/ApplicationList/*/$ns3::PacketSink/Rx", MakeCallback (&ReceivePacket));
    //Config::Connect("/NodeList/*/DeviceList/*/$ns3::Mac/MacTx", MakeCallback (&DevTxTrace));
    Ipv4GlobalRoutingHelper::PopulateRoutingTables ();
    Simulator::Stop (Seconds (54.0));
    
    // 8. Enable tracing (optional)
    phy.EnablePcapAll ("lab_project", true);
    
    AsciiTraceHelper ascii;
    phy.EnableAsciiAll (ascii.CreateFileStream ("lab_project2.tr"));
    
    // flow monitor to keep track of the numbers of packets
    // that arrived successfully, dropped, or missed
    // Can use this to analyze the throughput later on
    Ptr<FlowMonitor> flow_monitor;
    if (enable_flow_monitor)
    {
      FlowMonitorHelper flow_monitor_helper;
      flow_monitor = flow_monitor_helper.InstallAll();
    }
    
    PrintAddresses(wifiInterfaces, "IP addresses of base stations");
    PrintAddresses(wifiApInterface, "IP address of AP");
    PrintLocations(wifiStaNodes, "Location of all nodes");
    
    //enable printing of packet metadata
    //Packet::EnablePrinting();
    //Packet::EnableChecking();
    
    Simulator::Run ();
    if (enable_flow_monitor)
    {
      flow_monitor->CheckForLostPackets();
      flow_monitor->SerializeToXmlFile("project-part2.xml", true, true);
    }
    Simulator::Destroy ();
    
    return 0;
}

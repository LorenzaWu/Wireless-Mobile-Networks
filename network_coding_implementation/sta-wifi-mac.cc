/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2006, 2009 INRIA
 * Copyright (c) 2009 MIRKO BANCHI
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Mathieu Lacage <mathieu.lacage@sophia.inria.fr>
 * Author: Mirko Banchi <mk.banchi@gmail.com>
 */
#include "sta-wifi-mac.h"

#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/string.h"
#include "ns3/pointer.h"
#include "ns3/boolean.h"
#include "ns3/trace-source-accessor.h"

#include "qos-tag.h"
#include "mac-low.h"
#include "dcf-manager.h"
#include "mac-rx-middle.h"
#include "mac-tx-middle.h"
#include "wifi-mac-header.h"
#include "msdu-aggregator.h"
#include "amsdu-subframe-header.h"
#include "mgt-headers.h"

NS_LOG_COMPONENT_DEFINE ("StaWifiMac");


/*
 * The state machine for this STA is:
 --------------                                          -----------
 | Associated |   <--------------------      ------->    | Refused |
 --------------                        \    /            -----------
    \                                   \  /
     \    -----------------     -----------------------------
      \-> | Beacon Missed | --> | Wait Association Response |
          -----------------     -----------------------------
                \                       ^
                 \                      |
                  \    -----------------------
                   \-> | Wait Probe Response |
                       -----------------------
 */

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED (StaWifiMac);

TypeId
StaWifiMac::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::StaWifiMac")
    .SetParent<RegularWifiMac> ()
    .AddConstructor<StaWifiMac> ()
    .AddAttribute ("ProbeRequestTimeout", "The interval between two consecutive probe request attempts.",
                   TimeValue (Seconds (0.05)),
                   MakeTimeAccessor (&StaWifiMac::m_probeRequestTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("AssocRequestTimeout", "The interval between two consecutive assoc request attempts.",
                   TimeValue (Seconds (0.5)),
                   MakeTimeAccessor (&StaWifiMac::m_assocRequestTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("MaxMissedBeacons",
                   "Number of beacons which much be consecutively missed before "
                   "we attempt to restart association.",
                   UintegerValue (10),
                   MakeUintegerAccessor (&StaWifiMac::m_maxMissedBeacons),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("ActiveProbing", "If true, we send probe requests. If false, we don't. NOTE: if more than one STA in your simulation is using active probing, you should enable it at a different simulation time for each STA, otherwise all the STAs will start sending probes at the same time resulting in collisions. See bug 1060 for more info.",
                   BooleanValue (false),
                   MakeBooleanAccessor (&StaWifiMac::SetActiveProbing),
                   MakeBooleanChecker ())
    .AddTraceSource ("Assoc", "Associated with an access point.",
                     MakeTraceSourceAccessor (&StaWifiMac::m_assocLogger))
    .AddTraceSource ("DeAssoc", "Association with an access point lost.",
                     MakeTraceSourceAccessor (&StaWifiMac::m_deAssocLogger))
  ;
  return tid;
}

StaWifiMac::StaWifiMac ()
  : m_state (BEACON_MISSED),
    m_probeRequestEvent (),
    m_assocRequestEvent (),
    m_beaconWatchdogEnd (Seconds (0.0))
{
  NS_LOG_FUNCTION (this);

  // Let the lower layers know that we are acting as a non-AP STA in
  // an infrastructure BSS.
  SetTypeOfStation (STA);
}

StaWifiMac::~StaWifiMac ()
{
  NS_LOG_FUNCTION (this);
}

void
StaWifiMac::SetMaxMissedBeacons (uint32_t missed)
{
  NS_LOG_FUNCTION (this << missed);
  m_maxMissedBeacons = missed;
}

void
StaWifiMac::SetProbeRequestTimeout (Time timeout)
{
  NS_LOG_FUNCTION (this << timeout);
  m_probeRequestTimeout = timeout;
}

void
StaWifiMac::SetAssocRequestTimeout (Time timeout)
{
  NS_LOG_FUNCTION (this << timeout);
  m_assocRequestTimeout = timeout;
}

void
StaWifiMac::StartActiveAssociation (void)
{
  NS_LOG_FUNCTION (this);
  TryToEnsureAssociated ();
}

void
StaWifiMac::SetActiveProbing (bool enable)
{
  NS_LOG_FUNCTION (this << enable);
  if (enable)
    {
      Simulator::ScheduleNow (&StaWifiMac::TryToEnsureAssociated, this);
    }
  else
    {
      m_probeRequestEvent.Cancel ();
    }
}

void
StaWifiMac::SendProbeRequest (void)
{
  NS_LOG_FUNCTION (this);
  WifiMacHeader hdr;
  hdr.SetProbeReq ();
  hdr.SetAddr1 (Mac48Address::GetBroadcast ());
  hdr.SetAddr2 (GetAddress ());
  hdr.SetAddr3 (Mac48Address::GetBroadcast ());
  hdr.SetDsNotFrom ();
  hdr.SetDsNotTo ();
  Ptr<Packet> packet = Create<Packet> ();
  MgtProbeRequestHeader probe;
  probe.SetSsid (GetSsid ());
  probe.SetSupportedRates (GetSupportedRates ());
  packet->AddHeader (probe);

  // The standard is not clear on the correct queue for management
  // frames if we are a QoS AP. The approach taken here is to always
  // use the DCF for these regardless of whether we have a QoS
  // association or not.
  m_dca->Queue (packet, hdr);

  m_probeRequestEvent = Simulator::Schedule (m_probeRequestTimeout,
                                             &StaWifiMac::ProbeRequestTimeout, this);
}

void
StaWifiMac::SendAssociationRequest (void)
{
  NS_LOG_FUNCTION (this << GetBssid ());
  WifiMacHeader hdr;
  hdr.SetAssocReq ();
  hdr.SetAddr1 (GetBssid ());
  hdr.SetAddr2 (GetAddress ());
  hdr.SetAddr3 (GetBssid ());
  hdr.SetDsNotFrom ();
  hdr.SetDsNotTo ();
  Ptr<Packet> packet = Create<Packet> ();
  MgtAssocRequestHeader assoc;
  assoc.SetSsid (GetSsid ());
  assoc.SetSupportedRates (GetSupportedRates ());
  packet->AddHeader (assoc);

  // The standard is not clear on the correct queue for management
  // frames if we are a QoS AP. The approach taken here is to always
  // use the DCF for these regardless of whether we have a QoS
  // association or not.
  m_dca->Queue (packet, hdr);

  m_assocRequestEvent = Simulator::Schedule (m_assocRequestTimeout,
                                             &StaWifiMac::AssocRequestTimeout, this);
}

void
StaWifiMac::TryToEnsureAssociated (void)
{
  NS_LOG_FUNCTION (this);
  switch (m_state)
    {
    case ASSOCIATED:
      return;
      break;
    case WAIT_PROBE_RESP:
      /* we have sent a probe request earlier so we
         do not need to re-send a probe request immediately.
         We just need to wait until probe-request-timeout
         or until we get a probe response
       */
      break;
    case BEACON_MISSED:
      /* we were associated but we missed a bunch of beacons
       * so we should assume we are not associated anymore.
       * We try to initiate a probe request now.
       */
      m_linkDown ();
      SetState (WAIT_PROBE_RESP);
      SendProbeRequest ();
      break;
    case WAIT_ASSOC_RESP:
      /* we have sent an assoc request so we do not need to
         re-send an assoc request right now. We just need to
         wait until either assoc-request-timeout or until
         we get an assoc response.
       */
      break;
    case REFUSED:
      /* we have sent an assoc request and received a negative
         assoc resp. We wait until someone restarts an
         association with a given ssid.
       */
      break;
    }
}

void
StaWifiMac::AssocRequestTimeout (void)
{
  NS_LOG_FUNCTION (this);
  SetState (WAIT_ASSOC_RESP);
  SendAssociationRequest ();
}

void
StaWifiMac::ProbeRequestTimeout (void)
{
  NS_LOG_FUNCTION (this);
  SetState (WAIT_PROBE_RESP);
  SendProbeRequest ();
}

void
StaWifiMac::MissedBeacons (void)
{
  NS_LOG_FUNCTION (this);
  if (m_beaconWatchdogEnd > Simulator::Now ())
    {
      m_beaconWatchdog = Simulator::Schedule (m_beaconWatchdogEnd - Simulator::Now (),
                                              &StaWifiMac::MissedBeacons, this);
      return;
    }
  NS_LOG_DEBUG ("beacon missed");
  SetState (BEACON_MISSED);
  TryToEnsureAssociated ();
}

void
StaWifiMac::RestartBeaconWatchdog (Time delay)
{
  NS_LOG_FUNCTION (this << delay);
  m_beaconWatchdogEnd = std::max (Simulator::Now () + delay, m_beaconWatchdogEnd);
  if (Simulator::GetDelayLeft (m_beaconWatchdog) < delay
      && m_beaconWatchdog.IsExpired ())
    {
      NS_LOG_DEBUG ("really restart watchdog.");
      m_beaconWatchdog = Simulator::Schedule (delay, &StaWifiMac::MissedBeacons, this);
    }
}

bool
StaWifiMac::IsAssociated (void) const
{
  return m_state == ASSOCIATED;
}

bool
StaWifiMac::IsWaitAssocResp (void) const
{
  return m_state == WAIT_ASSOC_RESP;
}

void
StaWifiMac::Enqueue (Ptr<const Packet> packet, Mac48Address to)
{
  NS_LOG_FUNCTION (this << packet << to);
  if (!IsAssociated ())
    {
      NotifyTxDrop (packet);
      TryToEnsureAssociated ();
      return;
    }
  WifiMacHeader hdr;

  // If we are not a QoS AP then we definitely want to use AC_BE to
  // transmit the packet. A TID of zero will map to AC_BE (through \c
  // QosUtilsMapTidToAc()), so we use that as our default here.
  uint8_t tid = 0;

  // For now, an AP that supports QoS does not support non-QoS
  // associations, and vice versa. In future the AP model should
  // support simultaneously associated QoS and non-QoS STAs, at which
  // point there will need to be per-association QoS state maintained
  // by the association state machine, and consulted here.
  if (m_qosSupported)
    {
      hdr.SetType (WIFI_MAC_QOSDATA);
      hdr.SetQosAckPolicy (WifiMacHeader::NORMAL_ACK);
      hdr.SetQosNoEosp ();
      hdr.SetQosNoAmsdu ();
      // Transmission of multiple frames in the same TXOP is not
      // supported for now
      hdr.SetQosTxopLimit (0);

      // Fill in the QoS control field in the MAC header
      tid = QosUtilsGetTidForPacket (packet);
      // Any value greater than 7 is invalid and likely indicates that
      // the packet had no QoS tag, so we revert to zero, which'll
      // mean that AC_BE is used.
      if (tid >= 7)
        {
          tid = 0;
        }
      hdr.SetQosTid (tid);
    }
  else
    {
      hdr.SetTypeData ();
    }

  hdr.SetAddr1 (GetBssid ());
  hdr.SetAddr2 (m_low->GetAddress ());
  hdr.SetAddr3 (to);
  hdr.SetDsNotFrom ();
  hdr.SetDsTo ();
  
  ///
  ///
  //create a copy of header
  WifiMacHeader hdr_copy;
  hdr_copy.SetTypeData ();
  hdr_copy.SetAddr1 (GetBssid ());
  hdr_copy.SetAddr2 (m_low->GetAddress ());
  hdr_copy.SetAddr3 (to);
  hdr_copy.SetDsNotFrom ();
  hdr_copy.SetDsTo ();
  //create a copy of the packet to send
  Ptr <Packet> packet_copy = packet->Copy();
  
  //add copies into queues
  queue_hdr.push(hdr_copy);
  queue_packets.push(packet_copy);
  ///
  ///
  if (m_qosSupported)
    {
      // Sanity check that the TID is valid
      NS_ASSERT (tid < 8);
      m_edca[QosUtilsMapTidToAc (tid)]->Queue (packet, hdr);
    }
  else
    {
      m_dca->Queue (packet, hdr);
    }
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///
///undo XOR function

Ptr<Packet>
StaWifiMac::undo_xor_packets (const Ptr<Packet> & xor_packet)
{
  
    //copy data of xor packet
    uint32_t buffer_size_xor = xor_packet->GetSize();
    uint8_t* buf_xor = new uint8_t[buffer_size_xor];
    
    int byte_read_xor = xor_packet->CopyData (buf_xor, buffer_size_xor);
    cerr << "Byte_read from XOR packet: " << byte_read_xor << endl;

    //copy data of original packet (op)
    uint32_t buffer_size_op = queue_packets_overheard.front()->GetSize();
    uint8_t* buf_op = new uint8_t[buffer_size_op];
    int byte_read_op = queue_packets_overheard.front()->CopyData (buf_op, buffer_size_op);
    cerr << "Byte_read from original packet: " << byte_read_op << endl;
    
    uint32_t maximum_size;
    //take the max between size of XOR and Original packet
    if (buffer_size_xor > buffer_size_op)
    {
      maximum_size = buffer_size_xor;
    }
    else
    {
      maximum_size = buffer_size_op;
    }
    //xor bit by bit
    uint8_t* xor_buf = new uint8_t[maximum_size];
    for (uint32_t i = 0; i < maximum_size; i++)
    {
      xor_buf[i] = buf_xor[i] ^ buf_op[i];
    }
    
    //create a new packet with the xor data, this should be the data from other node to this STA
    ///Format: Ptr<Packet> packet = Create<Packet> (uint8_t* buffer, uint32_t buffer_size);
    Ptr<Packet> packet = Create<Packet> (xor_buf, maximum_size);
    /// have to check if this goes out of scope, not sure since these
    /// are implemented with smart pointers
    //queue_packets.pop();
    queue_packets_overheard.pop();
    return packet;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///Helper function to compare 2 mac addresses

bool
mac_is_equal_2 (const Mac48Address & a, const Mac48Address & b)
{
  //m_address is a private member of Mac48Address, so we use copy function
  uint8_t buf_a[6];
  uint8_t buf_b[6];
  a.CopyTo(buf_a);
  b.CopyTo(buf_b);
  return memcmp(buf_a, buf_b, 6) == 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void
StaWifiMac::Receive (Ptr<Packet> packet, const WifiMacHeader *hdr)
{
  NS_LOG_FUNCTION (this << packet << hdr);
  NS_ASSERT (!hdr->IsCtl ());
  ///
  Mac48Address mac_address_a("00:00:00:00:00:01"); // use for comparison
  Mac48Address mac_address_b("00:00:00:00:00:02"); // use for comparison
  Mac48Address mac_address_c("00:00:00:00:00:03"); // use for comparison
  Mac48Address mac_address_d("00:00:00:00:00:04"); // use for comparison
  Mac48Address mac_address_e("00:00:00:00:00:05"); // use for comparison
  ///
  
  //cerr << Simulator::Now ().GetSeconds () << "\tMac " << GetAddress() << " received packet from " << hdr->GetAddr3() << "\tSent to " << hdr->GetAddr1() << "\tPrevious Current: " << hdr->GetAddr2() << endl;
  
  ///explicitly have C listen for just B's packet that is to D
  if (mac_is_equal_2(mac_address_c, GetAddress()) && mac_is_equal_2(mac_address_b, hdr->GetAddr3()) && hdr->IsData() && mac_is_equal_2(mac_address_d, hdr->GetAddr1()) && packet->GetSize() > 36)
  {
    //cerr << Simulator::Now().GetSeconds() << "\tOverheard a packet from Node B!" << "\tMac Address of listener: " << GetAddress() << "\tCurrently from: " << hdr->GetAddr3() << "\tDestination: " << hdr->GetAddr1() << "\tPrevious: " << hdr->GetAddr2() << endl;
    
    cerr << Simulator::Now().GetSeconds() << "\tOverheard a packet from Node B!" << "\tFrom: " << hdr->GetAddr3() << "\tDestination: " << hdr->GetAddr1() << "\tCurrent: " << hdr->GetAddr2() << "\tPacket Size: " << packet->GetSize() << endl;
    //create a copy of header
    WifiMacHeader hdr_copy;
    hdr_copy.SetTypeData ();
    hdr_copy.SetAddr1 (hdr->GetAddr1());
    hdr_copy.SetAddr2 (hdr->GetAddr2());
    hdr_copy.SetAddr3 (hdr->GetAddr3());
    hdr_copy.SetDsFrom (); //from the Destination
    hdr_copy.SetDsTo ();
    queue_hdr_overheard.push(hdr_copy);
    
    //add to over heard packet queue
    Ptr <Packet> packet_copy = packet->Copy();
    queue_packets_overheard.push(packet_copy);
  }
  
  ///explicitly have D listen for just A's packet that is to C
  if (mac_is_equal_2(mac_address_d, GetAddress()) && mac_is_equal_2(mac_address_a, hdr->GetAddr3()) && hdr->IsData() && mac_is_equal_2(mac_address_c, hdr->GetAddr1()) && packet->GetSize() > 36)
  {
    //cerr << Simulator::Now().GetSeconds() << "\tOverheard a packet from Node A!" << "\tMac Address of listener: " << GetAddress() << "\tCurrently from: " << hdr->GetAddr3() << "\tDestination: " << hdr->GetAddr1() << "\tPrevious: " << hdr->GetAddr2() << endl;
    cerr << Simulator::Now().GetSeconds() << "\tOverheard a packet from Node A!" << "\tFrom: " << hdr->GetAddr3() << "\tDestination: " << hdr->GetAddr1() << "\tCurrent: " << hdr->GetAddr1() << "\tPacket Size: " << packet->GetSize() << endl;
    
    //to overheard header queue
    //create a copy of header
    WifiMacHeader hdr_copy;
    hdr_copy.SetTypeData ();
    hdr_copy.SetAddr1 (hdr->GetAddr1());
    hdr_copy.SetAddr2 (hdr->GetAddr2());
    hdr_copy.SetAddr3 (hdr->GetAddr3());
    hdr_copy.SetDsNotFrom ();
    hdr_copy.SetDsTo ();
    queue_hdr_overheard.push(hdr_copy);
    
    //add to overheard packet queue
    Ptr <Packet> packet_copy = packet->Copy();
    queue_packets_overheard.push(packet_copy);
  }
  
  
  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // if this packet is data and it is a broadcast then it is the broadcast XOR packet from Node E and 
  // my own address is not a sender of xor packet (A's or B's) then receive it and decode packet content
  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  if (hdr->IsData() && (hdr->GetAddr1()).IsBroadcast() && !mac_is_equal_2(mac_address_a, GetAddress()) && !mac_is_equal_2(mac_address_b, GetAddress()) && mac_is_equal_2(mac_address_e, hdr->GetAddr3()))
  {
    if (queue_hdr_overheard.size() > 0 && queue_packets_overheard.size() > 0)
    {
      cerr << "Received xor packet from " << hdr->GetAddr3() << " at Node with mac address " << GetAddress() << endl;
      
      //here is where we undo the XOR operation to get the actual data
      /// Note that this packet is suppose to be the response from the destination
      /// Therefore, we set up the header as it would be from the destination
      /// The payload will be from the result of the XOR operation
      WifiMacHeader header;
      header.SetTypeData();
      header.SetAddr1 (GetAddress()); //to will be itself
      header.SetAddr2 (GetAddress()); //current will be itself
      //if I am Node D
      if (mac_is_equal_2(mac_address_d, GetAddress()))
      {
        //I am Node D
        //Therefore, I am expecting from Node B
        header.SetAddr3 (mac_address_b); // from the destination 
      }
      //if I am Node C
      else if (mac_is_equal_2(mac_address_c, GetAddress()))
      {  
        //I am Node C
        //Therefore, I am expecting from Node A
        header.SetAddr3 (mac_address_a); // from the destination
      }
      else
      {
         cerr << "Something went wrong! sta-wifi-mac received xor section"  << endl;
      }
      
      header.SetDsFrom();
      header.SetDsTo();
      //XOR the XOR packet to get the original data
      Ptr <Packet> received_packet = undo_xor_packets (packet);
      ///Format: ForwardUp (packet, from, to)
      ForwardUp(received_packet, header.GetAddr3(), header.GetAddr1());
      if (queue_hdr_overheard.size() > 0)
      {
        queue_hdr_overheard.pop();
      }
    }
    return;
  }
  //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  
  if (hdr->GetAddr3 () == GetAddress ())
    {
      NS_LOG_LOGIC ("packet sent by us.");
      //cerr << "To: " << hdr->GetAddr1() << "\tCurrent: " << hdr->GetAddr2() << "\tFrom: " << hdr->GetAddr3() << endl;
      return;
    }
  else if (hdr->GetAddr1 () != GetAddress ()
           && !hdr->GetAddr1 ().IsGroup ())
    {
      NS_LOG_LOGIC ("packet is not for us");
      
      ///
      ///
      ///
      //cerr << "Sta-wifi-mac, not part of group" << endl;
      ///
      NotifyRxDrop (packet);
      ///
      return;
    }
  else if (hdr->IsData ())
    {
      if (!IsAssociated ())
        {
          NS_LOG_LOGIC ("Received data frame while not associated: ignore");
          
          ///
          //cerr << "Sta-wifi-mac, NOT associated and is data" << endl;
          //cerr << "To: " << hdr->GetAddr1() << "\tCurrent: " << hdr->GetAddr2() << "\tFrom: " << hdr->GetAddr3() << endl;
          ///
          NotifyRxDrop (packet);
          return;
        }
      if (!(hdr->IsFromDs () && !hdr->IsToDs ()))
        {
          NS_LOG_LOGIC ("Received data frame not from the DS: ignore");
         
          ///
          //cerr << "Sta-wifi-mac, !(hdr->IsFromDs () && !hdr->IsToDs ()) " << "Current STA address: " << GetAddress() << endl;
          //cerr << "To: " << hdr->GetAddr1() << "\tCurrent: " << hdr->GetAddr2() << "\tFrom: " << hdr->GetAddr3() << endl;
          ///
          ForwardUp (packet, hdr->GetAddr3 (), hdr->GetAddr1 ());
          //NotifyRxDrop (packet);
          
          return;
        }
      if (hdr->GetAddr2 () != GetBssid ())
        {
          NS_LOG_LOGIC ("Received data frame not from the BSS we are associated with: ignore");
          
          ///
          //cerr << "To: " << hdr->GetAddr1() << "\tCurrent: " << hdr->GetAddr2() << "\tFrom: " << hdr->GetAddr3() << endl;
          NotifyRxDrop (packet);

          return;
        }

      if (hdr->IsQosData ())
        {
          if (hdr->IsQosAmsdu ())
            {
              NS_ASSERT (hdr->GetAddr3 () == GetBssid ());
              DeaggregateAmsduAndForward (packet, hdr);
              packet = 0;
            }
          else
            {
              ///Format: ForwardUp (packet, from, to)
              //cerr << "To: " << hdr->GetAddr1() << "\tCurrent: " << hdr->GetAddr2() << "\tFrom: " << hdr->GetAddr3() << endl;
              ForwardUp (packet, hdr->GetAddr3 (), hdr->GetAddr1 ());
            }
        }
      else
        {
          ///
          /*
          //only add to the queue if it is a data packet, this will exclude ACKs and ARP
          if (hdr->IsData ())
          {
              if (overheard_queue.size() > 0 && mac_queue.size() > 0 )
              {
                if (mac_queue.back() != hdr->GetAddr1())
                {
                  //instead of dropping the packet, now we add it into the queue of overheard
                  overheard_queue.push(packet);
                  mac_queue.push(hdr->GetAddr1());
                  cerr << "Added a new packet to overheard queue\n" << "To: " << hdr->GetAddr3() << "\tfrom: " << hdr->GetAddr1() << endl; 
                }
              }
              else 
              {
                //instead of dropping the packet, now we add it into the queue of overheard
                overheard_queue.push(packet);
                mac_queue.push(hdr->GetAddr1());
                cerr << "Added a new packet to overheard queue\n" << "To: " << hdr->GetAddr3() << "\tfrom: " << hdr->GetAddr1() << endl; 
              }
          }
          */
          ///
          //cerr << "To: " << hdr->GetAddr1() << "\tCurrent: " << hdr->GetAddr2() << "\tFrom: " << hdr->GetAddr3() << endl;
          ForwardUp (packet, hdr->GetAddr3 (), hdr->GetAddr1 ());
        }
      return;
    }
  else if (hdr->IsProbeReq ()
           || hdr->IsAssocReq ())
    {
      // This is a frame aimed at an AP, so we can safely ignore it.
      ///cerr << "To: " << hdr->GetAddr1() << "\tCurrent: " << hdr->GetAddr2() << "\tFrom: " << hdr->GetAddr3() << endl;
      NotifyRxDrop (packet);
      return;
    }
  else if (hdr->IsBeacon ())
    {
      //cerr << "To: " << hdr->GetAddr1() << "\tCurrent: " << hdr->GetAddr2() << "\tFrom: " << hdr->GetAddr3() << endl;
      MgtBeaconHeader beacon;
      packet->RemoveHeader (beacon);
      bool goodBeacon = false;
      if (GetSsid ().IsBroadcast ()
          || beacon.GetSsid ().IsEqual (GetSsid ()))
        {
          goodBeacon = true;
        }
      if ((IsWaitAssocResp () || IsAssociated ()) && hdr->GetAddr3 () != GetBssid ())
        {
          goodBeacon = false;
        }
      if (goodBeacon)
        {
          Time delay = MicroSeconds (beacon.GetBeaconIntervalUs () * m_maxMissedBeacons);
          RestartBeaconWatchdog (delay);
          SetBssid (hdr->GetAddr3 ());
        }
      if (goodBeacon && m_state == BEACON_MISSED)
        {
          SetState (WAIT_ASSOC_RESP);
          SendAssociationRequest ();
        }
      return;
    }
  else if (hdr->IsProbeResp ())
    {
      //cerr << "To: " << hdr->GetAddr1() << "\tCurrent: " << hdr->GetAddr2() << "\tFrom: " << hdr->GetAddr3() << endl;
      if (m_state == WAIT_PROBE_RESP)
        {
          MgtProbeResponseHeader probeResp;
          packet->RemoveHeader (probeResp);
          if (!probeResp.GetSsid ().IsEqual (GetSsid ()))
            {
              //not a probe resp for our ssid.
              return;
            }
          SetBssid (hdr->GetAddr3 ());
          Time delay = MicroSeconds (probeResp.GetBeaconIntervalUs () * m_maxMissedBeacons);
          RestartBeaconWatchdog (delay);
          if (m_probeRequestEvent.IsRunning ())
            {
              m_probeRequestEvent.Cancel ();
            }
          SetState (WAIT_ASSOC_RESP);
          SendAssociationRequest ();
        }
      return;
    }
  else if (hdr->IsAssocResp ())
    {
      //cerr << "To: " << hdr->GetAddr1() << "\tCurrent: " << hdr->GetAddr2() << "\tFrom: " << hdr->GetAddr3() << endl;
      if (m_state == WAIT_ASSOC_RESP)
        {
          MgtAssocResponseHeader assocResp;
          packet->RemoveHeader (assocResp);
          if (m_assocRequestEvent.IsRunning ())
            {
              m_assocRequestEvent.Cancel ();
            }
          if (assocResp.GetStatusCode ().IsSuccess ())
            {
              SetState (ASSOCIATED);
              NS_LOG_DEBUG ("assoc completed");
              SupportedRates rates = assocResp.GetSupportedRates ();
              for (uint32_t i = 0; i < m_phy->GetNModes (); i++)
                {
                  WifiMode mode = m_phy->GetMode (i);
                  if (rates.IsSupportedRate (mode.GetDataRate ()))
                    {
                      m_stationManager->AddSupportedMode (hdr->GetAddr2 (), mode);
                      if (rates.IsBasicRate (mode.GetDataRate ()))
                        {
                          m_stationManager->AddBasicMode (mode);
                        }
                    }
                }
              if (!m_linkUp.IsNull ())
                {
                  m_linkUp ();
                }
            }
          else
            {
              NS_LOG_DEBUG ("assoc refused");
              SetState (REFUSED);
            }
        }
      return;
    }

  // Invoke the receive handler of our parent class to deal with any
  // other frames. Specifically, this will handle Block Ack-related
  // Management Action frames.
  //cerr << "To: " << hdr->GetAddr1() << "\tCurrent: " << hdr->GetAddr2() << "\tFrom: " << hdr->GetAddr3() << endl;
  RegularWifiMac::Receive (packet, hdr);
}

SupportedRates
StaWifiMac::GetSupportedRates (void) const
{
  SupportedRates rates;
  for (uint32_t i = 0; i < m_phy->GetNModes (); i++)
    {
      WifiMode mode = m_phy->GetMode (i);
      rates.AddSupportedRate (mode.GetDataRate ());
    }
  return rates;
}

void
StaWifiMac::SetState (MacState value)
{
  if (value == ASSOCIATED
      && m_state != ASSOCIATED)
    {
      m_assocLogger (GetBssid ());
    }
  else if (value != ASSOCIATED
           && m_state == ASSOCIATED)
    {
      m_deAssocLogger (GetBssid ());
    }
  m_state = value;
}

} // namespace ns3

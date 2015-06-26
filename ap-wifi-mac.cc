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
#include "ap-wifi-mac.h"

#include "ns3/assert.h"
#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/string.h"
#include "ns3/pointer.h"
#include "ns3/boolean.h"

#include "qos-tag.h"
#include "wifi-phy.h"
#include "dcf-manager.h"
#include "mac-rx-middle.h"
#include "mac-tx-middle.h"
#include "mgt-headers.h"
#include "mac-low.h"
#include "amsdu-subframe-header.h"
#include "msdu-aggregator.h"

NS_LOG_COMPONENT_DEFINE ("ApWifiMac");

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED (ApWifiMac);

TypeId
ApWifiMac::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::ApWifiMac")
    .SetParent<RegularWifiMac> ()
    .AddConstructor<ApWifiMac> ()
    .AddAttribute ("BeaconInterval", "Delay between two beacons",
                   TimeValue (MicroSeconds (102400)),
                   MakeTimeAccessor (&ApWifiMac::GetBeaconInterval,
                                     &ApWifiMac::SetBeaconInterval),
                   MakeTimeChecker ())
    .AddAttribute ("BeaconGeneration", "Whether or not beacons are generated.",
                   BooleanValue (true),
                   MakeBooleanAccessor (&ApWifiMac::SetBeaconGeneration,
                                        &ApWifiMac::GetBeaconGeneration),
                   MakeBooleanChecker ())
  ;
  return tid;
}

ApWifiMac::ApWifiMac ()
{
  NS_LOG_FUNCTION (this);
  m_beaconDca = CreateObject<DcaTxop> ();
  m_beaconDca->SetAifsn (1);
  m_beaconDca->SetMinCw (0);
  m_beaconDca->SetMaxCw (0);
  m_beaconDca->SetLow (m_low);
  m_beaconDca->SetManager (m_dcfManager);

  // Let the lower layers know that we are acting as an AP.
  SetTypeOfStation (AP);

  m_enableBeaconGeneration = false;
}

ApWifiMac::~ApWifiMac ()
{
  NS_LOG_FUNCTION (this);
}

void
ApWifiMac::DoDispose ()
{
  NS_LOG_FUNCTION (this);
  m_beaconDca = 0;
  m_enableBeaconGeneration = false;
  m_beaconEvent.Cancel ();
  RegularWifiMac::DoDispose ();
}

void
ApWifiMac::SetAddress (Mac48Address address)
{
  // As an AP, our MAC address is also the BSSID. Hence we are
  // overriding this function and setting both in our parent class.
  RegularWifiMac::SetAddress (address);
  RegularWifiMac::SetBssid (address);
}

void
ApWifiMac::SetBeaconGeneration (bool enable)
{
  NS_LOG_FUNCTION (this << enable);
  if (!enable)
    {
      m_beaconEvent.Cancel ();
    }
  else if (enable && !m_enableBeaconGeneration)
    {
      m_beaconEvent = Simulator::ScheduleNow (&ApWifiMac::SendOneBeacon, this);
    }
  m_enableBeaconGeneration = enable;
}

bool
ApWifiMac::GetBeaconGeneration (void) const
{
  return m_enableBeaconGeneration;
}

Time
ApWifiMac::GetBeaconInterval (void) const
{
  return m_beaconInterval;
}

void
ApWifiMac::SetWifiRemoteStationManager (Ptr<WifiRemoteStationManager> stationManager)
{
  NS_LOG_FUNCTION (this << stationManager);
  m_beaconDca->SetWifiRemoteStationManager (stationManager);
  RegularWifiMac::SetWifiRemoteStationManager (stationManager);
}

void
ApWifiMac::SetLinkUpCallback (Callback<void> linkUp)
{
  NS_LOG_FUNCTION (this);
  RegularWifiMac::SetLinkUpCallback (linkUp);

  // The approach taken here is that, from the point of view of an AP,
  // the link is always up, so we immediately invoke the callback if
  // one is set
  linkUp ();
}

void
ApWifiMac::SetBeaconInterval (Time interval)
{
  NS_LOG_FUNCTION (this << interval);
  if ((interval.GetMicroSeconds () % 1024) != 0)
    {
      NS_LOG_WARN ("beacon interval should be multiple of 1024us, see IEEE Std. 802.11-2007, section 11.1.1.1");
    }
  m_beaconInterval = interval;
}

void
ApWifiMac::StartBeaconing (void)
{
  NS_LOG_FUNCTION (this);
  SendOneBeacon ();
}

void
ApWifiMac::ForwardDown (Ptr<const Packet> packet, Mac48Address from,
                        Mac48Address to)
{
  // If we are not a QoS AP then we definitely want to use AC_BE to
  // transmit the packet. A TID of zero will map to AC_BE (through \c
  // QosUtilsMapTidToAc()), so we use that as our default here.
  uint8_t tid = 0;

  // If we are a QoS AP then we attempt to get a TID for this packet
  if (m_qosSupported)
    {
      tid = QosUtilsGetTidForPacket (packet);
      // Any value greater than 7 is invalid and likely indicates that
      // the packet had no QoS tag, so we revert to zero, which'll
      // mean that AC_BE is used.
      if (tid >= 7)
        {
          tid = 0;
        }
    }

  ForwardDown (packet, from, to, tid);
}

void
ApWifiMac::ForwardDown (Ptr<const Packet> packet, Mac48Address from,
                        Mac48Address to, uint8_t tid)
{
  NS_LOG_FUNCTION (this << packet << from << to);
  WifiMacHeader hdr;

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
      hdr.SetQosTid (tid);
    }
  else
    {
      hdr.SetTypeData ();
    }
  /* Address 1 = to/destination
   * Address 2 = my_address/current_address
   * Address 3 = from
   */ 
  
  hdr.SetAddr1 (to);
  hdr.SetAddr2 (GetAddress ());
  hdr.SetAddr3 (from);
  
  hdr.SetDsFrom ();
  hdr.SetDsNotTo ();

  if (m_qosSupported)
    {
      // Sanity check that the TID is valid
      NS_ASSERT (tid < 8);
      m_edca[QosUtilsMapTidToAc (tid)]->Queue (packet, hdr);
    }
  else
    {
      
      m_dca->Queue (packet, hdr);
      //if (GetAddress() != from)
      //{  
        //cerr << "To: " << to << "\tFrom: " << from << "\tGet addr:" << GetAddress() <<  endl; 
      //}
      ///
    }
}

void
ApWifiMac::Enqueue (Ptr<const Packet> packet, Mac48Address to, Mac48Address from)
{
  NS_LOG_FUNCTION (this << packet << to << from);
  if (to.IsBroadcast () || m_stationManager->IsAssociated (to))
    {
      ForwardDown (packet, from, to);
    }
}

void
ApWifiMac::Enqueue (Ptr<const Packet> packet, Mac48Address to)
{
  // We're sending this packet with a from address that is our own. We
  // get that address from the lower MAC and make use of the
  // from-spoofing Enqueue() method to avoid duplicated code.
  Enqueue (packet, to, m_low->GetAddress ());
}

bool
ApWifiMac::SupportsSendFrom (void) const
{
  return true;
}

SupportedRates
ApWifiMac::GetSupportedRates (void) const
{
  // send the set of supported rates and make sure that we indicate
  // the Basic Rate set in this set of supported rates.
  SupportedRates rates;
  for (uint32_t i = 0; i < m_phy->GetNModes (); i++)
    {
      WifiMode mode = m_phy->GetMode (i);
      rates.AddSupportedRate (mode.GetDataRate ());
    }
  // set the basic rates
  for (uint32_t j = 0; j < m_stationManager->GetNBasicModes (); j++)
    {
      WifiMode mode = m_stationManager->GetBasicMode (j);
      rates.SetBasicRate (mode.GetDataRate ());
    }
  return rates;
}

void
ApWifiMac::SendProbeResp (Mac48Address to)
{
  NS_LOG_FUNCTION (this << to);
  WifiMacHeader hdr;
  hdr.SetProbeResp ();
  hdr.SetAddr1 (to);
  hdr.SetAddr2 (GetAddress ());
  hdr.SetAddr3 (GetAddress ());
  hdr.SetDsNotFrom ();
  hdr.SetDsNotTo ();
  Ptr<Packet> packet = Create<Packet> ();
  MgtProbeResponseHeader probe;
  probe.SetSsid (GetSsid ());
  probe.SetSupportedRates (GetSupportedRates ());
  probe.SetBeaconIntervalUs (m_beaconInterval.GetMicroSeconds ());
  packet->AddHeader (probe);

  // The standard is not clear on the correct queue for management
  // frames if we are a QoS AP. The approach taken here is to always
  // use the DCF for these regardless of whether we have a QoS
  // association or not.
  m_dca->Queue (packet, hdr);
}

void
ApWifiMac::SendAssocResp (Mac48Address to, bool success)
{
  NS_LOG_FUNCTION (this << to << success);
  WifiMacHeader hdr;
  hdr.SetAssocResp ();
  hdr.SetAddr1 (to);
  hdr.SetAddr2 (GetAddress ());
  hdr.SetAddr3 (GetAddress ());
  hdr.SetDsNotFrom ();
  hdr.SetDsNotTo ();
  Ptr<Packet> packet = Create<Packet> ();
  MgtAssocResponseHeader assoc;
  StatusCode code;
  if (success)
    {
      code.SetSuccess ();
    }
  else
    {
      code.SetFailure ();
    }
  assoc.SetSupportedRates (GetSupportedRates ());
  assoc.SetStatusCode (code);
  packet->AddHeader (assoc);

  // The standard is not clear on the correct queue for management
  // frames if we are a QoS AP. The approach taken here is to always
  // use the DCF for these regardless of whether we have a QoS
  // association or not.
  m_dca->Queue (packet, hdr);
  
}

void
ApWifiMac::SendOneBeacon (void)
{
  NS_LOG_FUNCTION (this);
  ///
  /// This should be similar to how to broadcast data
  /// Set hdr to datatype instead and then set the 3 addresses similarly
  ///
  WifiMacHeader hdr;
  hdr.SetBeacon ();
  hdr.SetAddr1 (Mac48Address::GetBroadcast ());
  hdr.SetAddr2 (GetAddress ());
  hdr.SetAddr3 (GetAddress ());
  hdr.SetDsNotFrom ();
  hdr.SetDsNotTo ();
  Ptr<Packet> packet = Create<Packet> ();
  ///
  MgtBeaconHeader beacon;
  beacon.SetSsid (GetSsid ());
  beacon.SetSupportedRates (GetSupportedRates ());
  beacon.SetBeaconIntervalUs (m_beaconInterval.GetMicroSeconds ());

  packet->AddHeader (beacon);

  // The beacon has it's own special queue, so we load it in there
  m_beaconDca->Queue (packet, hdr);
  ///
  /// Schedule broadcast of xor packet should be similar to this
  ///
  m_beaconEvent = Simulator::Schedule (m_beaconInterval, &ApWifiMac::SendOneBeacon, this);
  ///
}

void
ApWifiMac::TxOk (const WifiMacHeader &hdr)
{
  NS_LOG_FUNCTION (this);
  RegularWifiMac::TxOk (hdr);

  if (hdr.IsAssocResp ()
      && m_stationManager->IsWaitAssocTxOk (hdr.GetAddr1 ()))
    {
      NS_LOG_DEBUG ("associated with sta=" << hdr.GetAddr1 ());
      m_stationManager->RecordGotAssocTxOk (hdr.GetAddr1 ());
    }
}

void
ApWifiMac::TxFailed (const WifiMacHeader &hdr)
{
  NS_LOG_FUNCTION (this);
  RegularWifiMac::TxFailed (hdr);

  if (hdr.IsAssocResp ()
      && m_stationManager->IsWaitAssocTxOk (hdr.GetAddr1 ()))
    {
      NS_LOG_DEBUG ("assoc failed with sta=" << hdr.GetAddr1 ());
      m_stationManager->RecordGotAssocTxFailed (hdr.GetAddr1 ());
    }
}

//////////////////////////////////////////////////////////////////////////////////////////
///Helper function to compare 2 mac addresses
bool
mac_is_equal (const Mac48Address & a, const Mac48Address & b)
{
  //m_address is a private member of Mac48Address, so we use copy function
  uint8_t buf_a[6];
  uint8_t buf_b[6];
  a.CopyTo(buf_a);
  b.CopyTo(buf_b);
  return memcmp(buf_a, buf_b, 6) == 0;
}

///XOR function
Ptr<Packet>
ApWifiMac::xor_packets (const Ptr<Packet> & a, const Ptr<Packet> & b)
{
  //copy data of packet from A
  uint32_t buffer_size_a = a->GetSize();
  uint8_t* buf_a = new uint8_t[buffer_size_a];
  int byte_read_a = a->CopyData (buf_a, buffer_size_a);
  cerr << "Byte_read from A: " << byte_read_a << endl;
  
  //copy data of packet from B
  uint32_t buffer_size_b = b->GetSize();
  uint8_t* buf_b = new uint8_t[buffer_size_b];
  int byte_read_b = b->CopyData (buf_b, buffer_size_b);
  cerr << "Byte_read from B: " << byte_read_b << endl;
  
  uint32_t maximum_size;
  //take the max between size of A and B
  if (buffer_size_a > buffer_size_b)
  {
    maximum_size = buffer_size_a;
  }
  else
  {
    maximum_size = buffer_size_b;
  }
  //xor bit by bit
  uint8_t* xor_buf = new uint8_t[maximum_size];
  for (uint32_t i = 0; i < maximum_size; i++)
  {
    xor_buf[i] = buf_a[i] ^ buf_b[i];
  }
  //create a new packet with the xor data
  ///Format: Ptr<Packet> packet = Create<Packet> (uint8_t* buffer, uint32_t buffer_size);
  Ptr<Packet> packet = Create<Packet> (xor_buf, maximum_size);
  /// have to check if this goes out of scope, not sure since these
  /// are implemented with smart pointers
  queue_a.pop();
  queue_b.pop();
  return packet;
}

///initiate periodic broadcast of xor packets
void 
ApWifiMac::initiate_periodic_broadcast ()
{
  periodic_broadcast();
  ///schedule broadcast every m_broadcast_interval, the base unit is in nanoseconds
  Simulator::Schedule(m_broadcast_interval, &ApWifiMac::initiate_periodic_broadcast, this);
}

///broadcast XOR packet
void 
ApWifiMac::periodic_broadcast ()
{
    if (queue_a.size() > 0 && queue_b.size() > 0)
    {
      //create header for xor packet
      WifiMacHeader hdr;
      hdr.SetTypeData(); //set type to data
      hdr.SetAddr1 (Mac48Address::GetBroadcast ()); //set destination to just be broadcast
      hdr.SetAddr2 (GetAddress ()); // current address
      hdr.SetAddr3 (GetAddress ()); // where packet is from
      hdr.SetDsNotFrom ();
      hdr.SetDsNotTo ();
      //xor packet from A and B
      Ptr<Packet> xor_packet = xor_packets (queue_a.front(), queue_b.front());
      //copy packet and forward it up
      /// Format: Ptr<Packet> copy = packet->Copy ();
      Ptr<Packet> copy = xor_packet->Copy();
      /// Format: ForwardUp (copy, from, to);
      ForwardUp(copy, GetAddress(), Mac48Address::GetBroadcast ());
      
      broadcast_counter++;
      cerr << "\n" << Simulator::Now ().GetSeconds () << "\tBROADCASTING!\n" << "\tBroadcast # " << broadcast_counter << endl;
      
      //forward packet down to be queued by DCA manager to broadcast when channel is free
      ///Format: ForwardDown (packet, from, to)
      ForwardDown (xor_packet, GetAddress(), Mac48Address::GetBroadcast ());
    }
}
////////////////////////////////////////////////////////////////////////////////////////////////

void
ApWifiMac::Receive (Ptr<Packet> packet, const WifiMacHeader *hdr)
{
  NS_LOG_FUNCTION (this << packet << hdr);
  
  unsigned handshake_packet_size = 36;
  Mac48Address from = hdr->GetAddr2 ();
  Mac48Address mac_address_a("00:00:00:00:00:01"); // use for comparison
  Mac48Address mac_address_b("00:00:00:00:00:02"); // use for comparison
  Mac48Address mac_address_c("00:00:00:00:00:03"); // use for comparison
  Mac48Address mac_address_d("00:00:00:00:00:04"); // use for comparison
 
  //only do this once
  // if address of A is not set yet, the sender is address of A, and size of packet is larger than 100 bytes (packets 100 bytes or under is treated as non-payload packets)
  if (!previous_mac_flag && mac_is_equal(from, mac_address_a) && hdr->IsData() && handshake_count_a >= 2)// && mac_is_equal(hdr->GetAddr1(), mac_address_c))// && packet->GetSize() > 26)
  {
    cerr << "A's handshake setup is complete!" << endl;
    previous_mac_flag = 1;
    previous_mac = hdr->GetAddr2 ();
    mac_addr_a = hdr->GetAddr2 ();
    //cerr << "Setting up mac_addr_a, with mac address " << from << endl;
    mac_addr_a_flag = 1;
  }
  
  if (mac_is_equal(mac_address_a, from) && packet->GetSize() <= handshake_packet_size)
  {
    handshake_count_a++;
    //cerr << "incrementing handshake A" << endl;
  }
  ///
  if (hdr->IsData ())
    {
      Mac48Address bssid = hdr->GetAddr1 ();
      // if not from destination, is to destination, I am the BSSID, I am associated with sender
      if (!hdr->IsFromDs ()
          && hdr->IsToDs ()
          && bssid == GetAddress ()
          && m_stationManager->IsAssociated (from))
        {
          Mac48Address to = hdr->GetAddr3 ();
          if (to == GetAddress ())
            {
              NS_LOG_DEBUG ("frame for me from=" << from);
              if (hdr->IsQosData ())
                {
                  if (hdr->IsQosAmsdu ())
                    {
                      NS_LOG_DEBUG ("Received A-MSDU from=" << from << ", size=" << packet->GetSize ());
                      DeaggregateAmsduAndForward (packet, hdr);
                      packet = 0;
                    }
                  else
                    {
                      ForwardUp (packet, from, bssid);
                    }
                }
              else
                {
                  ForwardUp (packet, from, bssid);
                  //cerr << "Ap-wifi-mac forward" << std::endl;
                }
            }
            //if the destination is part of this Basic service set or the AP is associated with destination
            // then forward the packet to destination
          else if (to.IsGroup ()
                   || m_stationManager->IsAssociated (to))
            {
              NS_LOG_DEBUG ("forwarding frame from=" << from << ", to=" << to);
              Ptr<Packet> copy = packet->Copy ();

              // If the frame we are forwarding is of type QoS Data,
              // then we need to preserve the UP in the QoS control
              // header...
              if (hdr->IsQosData ())
                {
                  ForwardDown (packet, from, to, hdr->GetQosTid ());
                }
              else
                {
                   //we don't want to queue up ACKs to send, we want them to get through ASAP
                   if (hdr->IsAck())
                   {
                    //cerr << "Packet is an ACK" << endl; 
                    ForwardDown (packet, from, to);
                    return;
                   }
                   
                  
                  ///add to queue here and then when both queue has at least
                  ///1 packet, XOR to get new packet. Set that as broadcast and forward
                  ///down new packet with header stating 'from' and 'current' as yourself, the AP
                  ///the destination 'to' will be define as Mac48Address::GetBroadCast()
                  ///this is predefined in the Mac address files 

                  // for now there are two queues, one for node A and another for B
                  // ideally should make it work with just one queue
                 
                  //if B is not set up yet, packet is from B, and destination is to Node D
                  if (!mac_addr_b_flag && mac_is_equal(from, mac_address_b) && handshake_count_b >= 2)
                  {
                    cerr << "B's handshake setup is complete!" << endl;
                    mac_addr_b_flag = 1;
                    mac_addr_b = hdr->GetAddr2 ();
                  }
                  
                  //this is a handshake packet,  just increment the handshake counter
                  if (mac_is_equal(mac_address_b, from) && packet->GetSize() <= handshake_packet_size)
                  {
                    handshake_count_b++;
                  }
                    
                  //add to queue a
                  // if A's handshake process is completed, packet is from A, and packet is not a handshake packet
                  if (mac_addr_a_flag && mac_is_equal(mac_addr_a, from) && packet->GetSize() > handshake_packet_size)
                  {
                    queue_a.push(packet);
                    //cerr << "Received from A: " << from << "\tQueue size: " << queue_a.size() << "\tSize of packet: " << packet->GetSize() << endl;
                    cerr << "Received from A: " << from << "\tSize of packet: " << packet->GetSize() << endl;
                  }
                  //add to queue b if it was not from A, but we still check to make sure it's from B
                  //this is necessary if there is at least 1 more STA
                  // if B's handshake process is completed, packet is from B, and packet is not handshake
                  if (mac_addr_b_flag && mac_is_equal(mac_addr_b, from ) && packet->GetSize() > handshake_packet_size)
                  {
                    queue_b.push(packet);
                    //cerr << "Received from B: " << from << "\tQueue size: " << queue_b.size() << "\tSize of packet: " << packet->GetSize() << endl;
                    cerr << "Received from B: " << from << "\tSize of packet: " << packet->GetSize() << endl;
                  }
                  //enable periodic broadcasting once both queue has at least 1 element and handshake process is completed
                  if (!enable_periodic_broadcast && mac_addr_a_flag && mac_addr_b_flag && queue_a.size() > 0 && queue_b.size() > 0)
                  {
                    enable_periodic_broadcast = 1;
                    double broadcast_interval = 1000000000.0/1.5;
                    m_broadcast_interval = Time::Time(broadcast_interval); //base unit is 10^-9 (nanoseconds)
                    cerr << "Broadcast has been initiated with interval of " << broadcast_interval*(0.000000001) << " seconds." << endl;
                    initiate_periodic_broadcast ();
                  }
                   
                   
                   ///This is for cases where data arrives not in order specifically at the start
                   ///For example after sending a handshake on the STA, and receiving an ACK from AP,
                   ///the STA sends an ACK back, then immediately starts sending data. Due to different paths
                   ///the data packet may actually arrive first. Based on the structure of my design, I require
                   ///ACKs to be received first before queuing data packets for XOR operation.
                   ///BUT we also don't want to drop this data packet, so we will FORCE add it to queue 
                   if (!mac_addr_a_flag && packet->GetSize() > handshake_packet_size && mac_is_equal(mac_address_a, from))
                   {
                     // queue the data
                     queue_a.push(packet);
                   }
                   
                   if (!mac_addr_b_flag && packet->GetSize() > handshake_packet_size && mac_is_equal(mac_address_b, from))
                   {
                     // queue the data
                     queue_b.push(packet);
                   }
                   
                   //if either A or B is not set up then connection is still being established
                   if (!mac_addr_a_flag || !mac_addr_b_flag)
                   {
                     ForwardDown (packet, from, to);
                     return;
                   }
                   
                   //if by the end if either queue is empty that probably means one of the sender is done (A or B)
                   // therefore, we treat it as normal
                   if (queue_a.size() <= 0 || queue_b.size() <= 0)
                   {
                     ForwardDown (packet, from, to);
                     return;
                   }
                   
                   
                }
               /// We do not want to forward up this packet any more
               /// We want to foward up the xor packet later
              //ForwardUp (copy, from, to);
            }
          else
            {
              ///cerr << "Ap-wifi-mac-else\n";
              ForwardUp (packet, from, to);
            }
        }
      else if (hdr->IsFromDs ()
               && hdr->IsToDs ())
        {
          // this is an AP-to-AP frame
          // we ignore for now.
          //cerr << "Ap-wifi-mac-hdr is from ds\n";
          NotifyRxDrop (packet);
        }
      else
        {
          // we can ignore these frames since
          // they are not targeted at the AP
          //cerr << "Ap-wifi-mac-\n";
          NotifyRxDrop (packet);
        }
      ///
      ///
      previous_mac = hdr->GetAddr2 ();
      ///
      return;
    }
  else if (hdr->IsMgt ())
    {
      if (hdr->IsProbeReq ())
        {
          NS_ASSERT (hdr->GetAddr1 ().IsBroadcast ());
          SendProbeResp (from);
          ///
          ///
          previous_mac = hdr->GetAddr2 ();
          //cerr << "Ap-wifi-mac line 623" << endl;
          ///
          return;
        }
      else if (hdr->GetAddr1 () == GetAddress ())
        {
          if (hdr->IsAssocReq ())
            {
              // first, verify that the the station's supported
              // rate set is compatible with our Basic Rate set
              MgtAssocRequestHeader assocReq;
              packet->RemoveHeader (assocReq);
              SupportedRates rates = assocReq.GetSupportedRates ();
              bool problem = false;
              for (uint32_t i = 0; i < m_stationManager->GetNBasicModes (); i++)
                {
                  WifiMode mode = m_stationManager->GetBasicMode (i);
                  if (!rates.IsSupportedRate (mode.GetDataRate ()))
                    {
                      problem = true;
                      break;
                    }
                }
              if (problem)
                {
                  // one of the Basic Rate set mode is not
                  // supported by the station. So, we return an assoc
                  // response with an error status.
                  SendAssocResp (hdr->GetAddr2 (), false);
                }
              else
                {
                  // station supports all rates in Basic Rate Set.
                  // record all its supported modes in its associated WifiRemoteStation
                  for (uint32_t j = 0; j < m_phy->GetNModes (); j++)
                    {
                      WifiMode mode = m_phy->GetMode (j);
                      if (rates.IsSupportedRate (mode.GetDataRate ()))
                        {
                          m_stationManager->AddSupportedMode (from, mode);
                        }
                    }
                  m_stationManager->RecordWaitAssocTxOk (from);
                  // send assoc response with success status.
                  SendAssocResp (hdr->GetAddr2 (), true);
                }
              ///
              ///
              previous_mac = hdr->GetAddr2 ();
              ///
              return;
            }
          else if (hdr->IsDisassociation ())
            {
              m_stationManager->RecordDisassociated (from);
              ///
              ///
              previous_mac = hdr->GetAddr2 ();
              ///
              return;
            }
        }
    }

  // Invoke the receive handler of our parent class to deal with any
  // other frames. Specifically, this will handle Block Ack-related
  // Management Action frames.
  RegularWifiMac::Receive (packet, hdr);
  ///
  ///
  previous_mac = hdr->GetAddr2 ();
  ///
}

void
ApWifiMac::DeaggregateAmsduAndForward (Ptr<Packet> aggregatedPacket,
                                       const WifiMacHeader *hdr)
{
  MsduAggregator::DeaggregatedMsdus packets =
    MsduAggregator::Deaggregate (aggregatedPacket);

  for (MsduAggregator::DeaggregatedMsdusCI i = packets.begin ();
       i != packets.end (); ++i)
    {
      if ((*i).second.GetDestinationAddr () == GetAddress ())
        {
          ForwardUp ((*i).first, (*i).second.GetSourceAddr (),
                     (*i).second.GetDestinationAddr ());
        }
      else
        {
          Mac48Address from = (*i).second.GetSourceAddr ();
          Mac48Address to = (*i).second.GetDestinationAddr ();
          NS_LOG_DEBUG ("forwarding QoS frame from=" << from << ", to=" << to);
          ForwardDown ((*i).first, from, to, hdr->GetQosTid ());
        }
    }
}

void
ApWifiMac::DoStart (void)
{
  m_beaconDca->Start ();
  m_beaconEvent.Cancel ();
  if (m_enableBeaconGeneration)
    {
      m_beaconEvent = Simulator::ScheduleNow (&ApWifiMac::SendOneBeacon, this);
    }
  RegularWifiMac::DoStart ();
}

} // namespace ns3

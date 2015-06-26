# CS169---Wireless-Mobile-Networks

Network encoding implementation with NS3.
All files except for the MAC level files are the original legacy code.

The topology of the network is an infrastructure-based one.

                      A
                      |
                      |
                      V
           D <------- E <------ B
                      |
                      |
                      V
                      C
All the nodes are connected via wifi. Node E is the access point and Node A wishes to send data to Node C while Node B wishes to send data to Node D. 

There are two implentations: 1) store-and-forward and 2) Network Encoding

For the first implementation, Node E just forwards packet to the destination. This means the bottleneck becomes the speed at which Node E can forward packets.

For the second implementation, Node E performs an XOR operation on the packet it receives from Node A and B. Afterwards, Node E broadcast the XOR packet. When Node D and C receives the broadcast packet it decodes the packet by performing an XOR operation with the packet it overheard their neighbor sent. For Node C it uses what it overheard from Node B and for Node D it uses what it overheard from A.

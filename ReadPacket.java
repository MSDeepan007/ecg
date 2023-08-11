/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package dos;

import java.util.Vector;
import javax.swing.table.DefaultTableModel;
import jpcap.JpcapCaptor;
import jpcap.packet.ICMPPacket;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import jpcap.packet.UDPPacket;

/**
 *
 * @author Seabirds
 */
public class ReadPacket 
{
    AttackFrame mf;
    String path;

    ReadPacket(AttackFrame m,String s)
    {
        mf=m;
        path=s;
    }

    public void getPacketDetails()
    {
        try
        {
            JpcapCaptor captor=JpcapCaptor.openFile(path);
            while(true)
            {
		Packet pack=captor.getPacket();

                if(pack==null)
                    break;
                    
                IPPacket packet;
                    try
                    {
                         packet = (IPPacket) pack;
                    }
                    catch(Exception e)
                    {
                        continue;
                    }

                   // System.out.println("Flow label "+packet.flow_label);
                    String Proto="";
                    String srcip=packet.src_ip.toString().replace("/", "");
                    String dstip=packet.dst_ip.toString().replace("/", "");
                    int srcport=0;
                    int dstport=0;
                    int offset=0;
                    //int length=((Packet)packet).len;
                    //int iplen=packet.length;
                    int packlen=0;
                    int captlen=((Packet)packet).caplen;
                    byte data[]=((Packet)packet).data;
                    int ttl=packet.hop_limit;
                    String flags="";
                    String ss=new String(data);

                    byte header[] = ((Packet)packet).header;


		if(packet.protocol==6)
		{
                    Proto="TCP";
                    TCPPacket tp = (TCPPacket)packet;
                    srcport=tp.src_port;
                    dstport =tp.dst_port;
                    offset=tp.offset;
                    packlen=tp.length;
                    flags=tp.syn+"#"+tp.ack+"#"+tp.psh+"#"+tp.fin+"#"+tp.rst;
                    
                    //System.out.println("flag -->  "+tp.syn+" : "+tp.ack+" : "+tp.psh+" : "+tp.fin+" : "+tp.rst);
                    //System.out.println("tcp "+tp.length +" : "+ ss.length());

		}
		if(packet.protocol==17)
		{
                    Proto="UDP";
                    UDPPacket tp = (UDPPacket)packet;
                    srcport=tp.src_port;
                    dstport =tp.dst_port;
                    offset=tp.offset;
                    packlen=tp.length;
                    flags="-";
                    //System.out.println("udp "+tp.length+" : "+ ss.length());
		}
		if(packet.protocol==1)
		{
                    Proto="ICMP";
                    ICMPPacket icp=(ICMPPacket)packet;
                    flags="-";
                   // System.out.println(icp.recv_timestamp + " : "+icp.trans_timestamp);
		}
		if(packet.protocol==2)
		{
                    Proto="IGMP";
                    flags="-";
		}

                DefaultTableModel dm1=(DefaultTableModel)mf.jTable1.getModel();

                Vector v=new Vector();
                v.add(srcip);
                v.add(dstip);
                v.add(srcport);
                v.add(dstport);
                v.add(Proto);
                v.add(captlen);
                v.add(packlen);
                v.add(ttl);
                v.add(flags);

                dm1.addRow(v);
             }
           
           

        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }
}

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package dos;

import java.io.File;
import java.util.Vector;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import jpcap.JpcapCaptor;
import jpcap.JpcapWriter;
import jpcap.NetworkInterface;
import jpcap.PacketReceiver;
import jpcap.packet.Packet;

/**
 *
 * @author Seabirds
 */
public class Trace 
{
    long MAX_PACKETS_HOLD=10000;

    Vector packets = new Vector();

    JpcapCaptor jpcap=null;

    boolean isLiveCapture;
    boolean isSaved = false;

    AttackFrame mf;
    Trace(AttackFrame m)
    {
        mf=m;
    }

    public Vector getPackets()
    {
	return packets;
    }


    public void capturePacketsFromDevice()
    {
        try
        {
            NetworkInterface[] devices=JpcapCaptor.getDeviceList();
            if(jpcap!=null)
		jpcap.close();
            //jpcap = CaptureDialog.getJpcap(new JFrame());
        
            jpcap=JpcapCaptor.openDevice(devices[0],1514,true,50);
        	clear();

            if (jpcap != null)
            {
                isLiveCapture = true;
                startCaptureThread();
            }   
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }

    public void loadPacketsFromFile()
    {
        isLiveCapture = false;
	clear();

	JFileChooser ch1=new JFileChooser();
        int v=ch1.showOpenDialog(new JFrame());


	if (v == JFileChooser.APPROVE_OPTION)
        {
            String path = ch1.getSelectedFile().getPath();
            String filename = ch1.getSelectedFile().getName();

            mf.jTextField1.setText(filename);
            try
            {
		if(jpcap!=null)
                {
                    jpcap.close();
                }
		jpcap = JpcapCaptor.openFile(path);
            }
            catch (java.io.IOException e)
            {
		JOptionPane.showMessageDialog(new JFrame(),"Can't open file: " + path);
		e.printStackTrace();
		return;
            }

            startCaptureThread();
	}
    }

    private void clear()
    {
        packets.clear();
        for(int i=0;i<sframes.size();i++)
            ((StatFrame)sframes.get(i)).clear();
    }

    public void saveToFile()
    {
	if (packets == null)
		return;
        JFileChooser ch1=new JFileChooser();
        //int ret=ch1.showOpenDialog(new JFrame());
	int ret=ch1.showSaveDialog(new JFrame());
        
	if (ret == JFileChooser.APPROVE_OPTION)
        {
            File file = ch1.getSelectedFile();
            System.out.println("file path "+file.getPath());
            if (file.exists())
            {
		if (JOptionPane.showConfirmDialog(new JFrame(),"Overwrite " + file.getName() + "?","Overwrite?",JOptionPane.YES_NO_OPTION)== JOptionPane.NO_OPTION)
                {
                    return;
		}
            }
            try
            {
		//System.out.println("link:"+info.linktype);
		//System.out.println(lastJpcap);
		JpcapWriter writer = JpcapWriter.openDumpFile(jpcap,file.getPath());
               // JpcapWriter writer = JpcapWriter.openDumpFile(jpcap,"d:\\easter\\testcap.cap");

		for (int i = 0; i < packets.size(); i++)
                {
                    writer.writePacket((Packet) packets.elementAt(i));
		}

		writer.close();
		isSaved = true;
		//JOptionPane.showMessageDialog(frame,file+" was saved correctly.");
            }
            catch (java.io.IOException e)
            {
		e.printStackTrace();
		JOptionPane.showMessageDialog(new JFrame(),"Can't save file: " + file.getPath());
            }
	}
    }

    public void stopCapture()
    {
        System.out.println("pt size "+getPackets().size());
	stopCaptureThread();
    }

    public void saveIfNot()
    {
	if (isLiveCapture && !isSaved)
        {
            int ret =JOptionPane.showConfirmDialog(null, "Save this data?", "Save this data?",JOptionPane.YES_NO_OPTION);
            if (ret == JOptionPane.YES_OPTION)
				saveToFile();
	}
    }

    Vector sframes=new Vector();

    private Thread captureThread;

    private void startCaptureThread()
    {
        if (captureThread != null)
            return;

        captureThread = new Thread(new Runnable()
        {
            //body of capture thread
            public void run()
            {

                while (captureThread != null)
                {
                    if (jpcap.processPacket(1, handler) == 0 && !isLiveCapture)
                        stopCaptureThread();
                    Thread.yield();
                }

                jpcap.breakLoop();
                //jpcap = null;
            }
        });
        captureThread.setPriority(Thread.MIN_PRIORITY);

        for(int i=0;i<sframes.size();i++)
        {
            ((StatFrame)sframes.get(i)).startUpdating();
        }

            captureThread.start();
    }
    

	void stopCaptureThread()
        {
		captureThread = null;
                for(int i=0;i<sframes.size();i++)
                {
			((StatFrame)sframes.get(i)).stopUpdating();
		}
	}


	private PacketReceiver handler=new PacketReceiver()
        {
            public void receivePacket(Packet packet)
            {
            	packets.addElement(packet);
		while (packets.size() > MAX_PACKETS_HOLD)
                {
                    packets.removeElementAt(0);
		}
		if (!sframes.isEmpty())
                {
                    for (int i = 0; i < sframes.size(); i++)
                        ((StatFrame)sframes.get(i)).addPacket(packet);
                }
		isSaved = false;
            }
	};
}

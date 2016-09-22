import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.PcapPacket;

// to format data and get headers
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.application.Html;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.util.PcapPacketArrayList;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Rip;
// import org.jnetpcap.protocol.voip;
// import org.jnetpcap.protocol.vpn;
// import org.jnetpcap.protocol.wan;
import org.jnetpcap.packet.JRegistry;

// chapter 2.7

// chapter 3.1.2
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;

// For writing package data to file
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.io.File;
import java.io.FileWriter;
import java.util.Date;

import javax.xml.bind.DatatypeConverter;

import java.text.DateFormat;
import java.text.SimpleDateFormat;




public class PacketHandler {
	public static Ip4 ip = new Ip4();
	public static Ethernet eth = new Ethernet();
	public static Tcp tcp = new Tcp();
	public static Udp udp = new Udp();
	public static Arp arp = new Arp();
	public static Payload payload = new Payload();
	public static Http http=new Http();
	public static Html html=new Html();
	//public static Data data=new Data();
	public static byte[] dataContent;
	public static byte[] payloadContent;
	public static byte[] htmlContent;
	public static byte[] httpContent;
	public static boolean readdata = false;	public static byte[] myinet = new byte[3];
	public static byte[] mymac = new byte[5];

		public void nextPacket(JPacket pcappacket, PrintWriter pw) throws Exception {
			StringBuilder log = new StringBuilder();

			pw.print("Frame Number:\t"+pcappacket.getFrameNumber());

			if (pcappacket.hasHeader(ip)) {
				if (FormatUtils.ip(ip.source()) != FormatUtils.ip(myinet) &&
						FormatUtils.ip(ip.destination()) != FormatUtils.ip(myinet)) {
					pw.print("\nIP id:\t"+ip.id());
					pw.print("\nIP type:\t" + ip.typeEnum());
					pw.print("\nIP src:\t-\t" + FormatUtils.ip(ip.source()));
					pw.print("\nIP dst:\t-\t" + FormatUtils.ip(ip.destination()));
					pw.print("\nIP fragments:\t-\t" + ip.flags_MF());
					readdata = true;
				}
			}
			if (pcappacket.hasHeader(eth) &&
					readdata == true) {
				pw.print("\nEthernet type:\t" + eth.typeEnum());
				pw.print("\nEthernet src:\t" + FormatUtils.mac(eth.source()));
				pw.print("\nEthernet dst:\t" + FormatUtils.mac(eth.destination()));
			}
			if (pcappacket.hasHeader(tcp) &&
					readdata == true) {
				pw.print("\nTCP src port:\t" + tcp.source());
				pw.print("\nTCP dst port:\t" + tcp.destination());
			} else if (pcappacket.hasHeader(udp) &&
								 readdata == true) {
				pw.print("\nUDP src port:\t" + udp.source());
				pw.print("\nUDP dst port:\t" + udp.destination());
			}
			
			if (pcappacket.hasHeader(arp) &&
					readdata == true) {
							
				// pw.print("ARP decode header:\t" + arp.decodeHeader());
				// pw.print("ARP hardware type:\t" + arp. hardwareType());
				// pw.print("ARP hw type descr:\t" + arp.hardwareTypeDescription());
				// pw.print("ARP hw type enum:\t" + arp.hardwareTypeEnum());
				// pw.print("ARP hlen:\t-\t" + arp.hlen());
				// pw.print("ARP operation:\t-\t" + arp.operation());
				// pw.print("ARP plen:\t-\t" + arp.plen());
				// pw.print("ARP protocol type:\t" + arp.protocolType());
				// pw.print("ARP prtcl type descr:\t" + arp.protocolTypeDescription());
				// pw.print("ARP prtcl type enum:\t" + arp.protocolTypeEnum());
				// pw.print("ARP sha:\t-\t" + FormatUtils.mac(arp.sha()));
				// pw.print("ARP sha length:\t-\t" + arp.shaLength());
				// pw.print("ARP spa:\t-\t" + FormatUtils.ip(arp.spa()));
				// pw.print("ARP spa length:\t-\t" + arp.spaLength());
				// pw.print("ARP spa offset:\t-\t" + arp.spaOffset());
				// pw.print("ARP tha:\t-\t" + FormatUtils.mac(arp.tha()));
				// pw.print("ARP tha length:\t-\t" + arp.thaLength());
				// pw.print("ARP tha offset:\t-\t" + arp.thaOffset());
				// pw.print("ARP tpa:\t-\t" + FormatUtils.ip(arp.tpa()));
				// pw.print("ARP tpa length:\t-\t" + arp.tpaLength());
				// pw.print("ARP tpa offset:\t-\t" + arp.tpaOffset());
				pw.print("ARP Packet!");
				readdata = true;
			}
			if (pcappacket.hasHeader(payload) && 
					readdata == true) {
				payloadContent = payload.getPayload();
				pw.print("\nPayload:\n");
				//pw.println(payload.toString());
				
					pw.print(payload.toHexdump(payload.size(),  false, true, false));
				
			}
			/*if (pcappacket.hasHeader(data) && 
					readdata == true) {
				dataContent = data.getPayload();
				pw.print("\nData skjhsdfhbusfdbsavbvbalaz:\n");
				//pw.print(data.toString());
				for (int x = 0; x < dataContent.length; x++) {
					String hexdump = data.toHexdump(data.size(),  false, true, false);
					pw.print(hexdump);
 
					
			}}*/
			if (pcappacket.hasHeader(http) && 
					readdata == true) {
				httpContent = http.getPayload();
				pw.print("\nHTTP:\n");
				pw.print(http.toString());
				/*for (int x = 0; x < httpContent.length; x++) {
					//pw.print(http.toHexdump());
					
					String hexdump = http.toHexdump(http.size(),  false, true, false);
					pw.print(hexdump);
					
				}*/
			}
			if (pcappacket.hasHeader(html) && 
					readdata == true) {
				htmlContent = html.getPayload();
				pw.print("\nHTML:\n");
			String page= html.page();
			char[] ch=page.toCharArray();
			for (int i=0;i<ch.length;i++){
				if (((int)ch[i]<127)&&((int)ch[i]>0)){
					pw.print(ch[i])	;
				
				}

			}
			//System.out.println(ch.toString());
				/*for (int x = 0; x < htmlContent.length; x++) {
					String hexdump = html.toHexdump(html.size(),  false, true, false);
					pw.print(hexdump);
					
				}*/
			}
			if (readdata == true) pw.print("\n-\t-\t-\t-\t--\t-\t-\t-\t-\n");
			readdata = false;
			
			
		
		}
	}


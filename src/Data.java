import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeaderMap;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.HeaderLength;

@Header(name = "Data", nicname = "Payload")  

public class Data  
    extends JHeaderMap<Data> {  
    @Field(offset = 0, length = 4, format = "%d")  
    public int version() {  
        return getUByte(0) >> 4;  
    }  
    @HeaderLength  
    public static int headerLength(JBuffer buffer, int offset) {  
      return 0; // Ip4 style hlen  
    }  
  
    @Field(offset = 4, length = 4, format = "%d")  
    public int hlen() {  
        return getUByte(0) & 0x0F;  
    }  
  
/* more fields here, truncated for brevity */  
  
    @Field(offset = 12 * 8, length = 32, format = "#ip4#")  
    public byte[] source() {  
        return getByteArray(12, 4);  
    }  
  
    @Field(offset = 16 * 8, length = 32, format = "#ip4#")  
    public byte[] destination() {  
        return getByteArray(16, 4);  
    }  
}
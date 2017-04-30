package repair;

import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import javax.imageio.ImageIO;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.ChecksumException;
import com.google.zxing.FormatException;
import com.google.zxing.NotFoundException;
import com.google.zxing.Result;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.ResultPoint;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.common.DecoderResult;

public class Maxicode {
	private static final ResultPoint[] NO_POINTS = new ResultPoint[0];
	private static final int MATRIX_WIDTH = 30;
	private static final int MATRIX_HEIGHT = 33;

	private final static Decoder decoder = new Decoder();
	
	public static void main(String[] args) throws IOException, NotFoundException, ChecksumException, FormatException {
		String filePath = "c3.png";
		System.out.println(readCode(filePath));
	}
	
	public static String readCode(String filePath) throws FileNotFoundException, IOException, NotFoundException, ChecksumException, FormatException {
		BinaryBitmap image = new BinaryBitmap(new HybridBinarizer(new BufferedImageLuminanceSource(
						ImageIO.read(new FileInputStream(filePath)))));
		BitMatrix bits = extractPureBits(image.getBlackMatrix());
		DecoderResult decoderResult = decoder.decode(bits);
		
		Result result = new Result(decoderResult.getText(), decoderResult.getRawBytes(), NO_POINTS, BarcodeFormat.MAXICODE);

		return result.getText();
	}
	
	private static BitMatrix extractPureBits(BitMatrix image) throws NotFoundException, IOException {
	    
	    int[] enclosingRectangle = image.getEnclosingRectangle();
	    if (enclosingRectangle == null) {
	      throw NotFoundException.getNotFoundInstance();
	    }
	    
	    int left = enclosingRectangle[0];
	    int top = enclosingRectangle[1];
	    int width = enclosingRectangle[2];
	    int height = enclosingRectangle[3];

	    // Now just read off the bits
	    BitMatrix bits = new BitMatrix(MATRIX_WIDTH, MATRIX_HEIGHT);
	    for (int y = 0; y < MATRIX_HEIGHT; y++) {
	      int iy = top + (y * height + height / 2) / MATRIX_HEIGHT;
	      for (int x = 0; x < MATRIX_WIDTH; x++) {
	        int ix = left + (x * width + width / 2 + (y & 0x01) *  width / 2) / MATRIX_WIDTH;
	        if (image.get(ix, iy)) {
	          bits.set(x, y);
	        }
	      }
	    }
	    
	    BufferedWriter out = new BufferedWriter(new FileWriter("purebits.txt"));
		out.write(bits.toString());
		out.close();
		
	    return bits;
	  }
}

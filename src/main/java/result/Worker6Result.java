package result;

import java.math.BigInteger;

/**
 * 
 * @author wangnan
 *
 */
public class Worker6Result {

	private final BigInteger cipher;
	private final long time;

	public Worker6Result(BigInteger cipher, long time) {
		this.cipher = cipher;
		this.time = time;
	}
	
	public BigInteger getCipher() {
		return cipher;
	}

	public long getTime() {
		return time;
	}
}

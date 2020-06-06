package crypto;

import java.math.BigInteger;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import paillierp.Paillier;

/**
 * 
 * @author wangnan
 *
 */
public class Encrypter {

	private final Paillier paillier;
	private final BigInteger n;

	public Encrypter(Paillier paillier) {
		this.paillier = paillier;
		this.n = paillier.getPublicKey().getN();
	}

	public BigInteger encrypt(BigInteger m) {
		return this.paillier.encrypt(m.mod(this.n));
	}
	
	public BigInteger addCiphers(BigInteger c1, BigInteger c2) {
		if (c1 == null || c2 == null) {
			throw new IllegalArgumentException("Ciphers are empty!");
		}

		return this.paillier.add(c1, c2);
	}
	
	public BigInteger addCiphers(Collection<BigInteger> ciphers){
		Iterator<BigInteger> it = ciphers.iterator();
		BigInteger ret = it.next();

		while (it.hasNext()) {
			ret = addCiphers(ret, it.next());
		}
		
		return ret;
	}
	
	public BigInteger addCiphers(List<BigInteger> ciphers){
		Iterator<BigInteger> it = ciphers.iterator();
		BigInteger ret = it.next();
		while (it.hasNext()) {
			ret = addCiphers(ret, it.next());
		}
		
		return ret;
	}

	public BigInteger multiplyCiphers(BigInteger c, BigInteger m) {
		if (c == null || m == null) {
			throw new IllegalArgumentException("Ciphers are empty!");
		}

		return this.paillier.multiply(c, m);
	}
}

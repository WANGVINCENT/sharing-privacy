package crypto;

import java.math.BigInteger;
import java.util.List;

import com.google.common.collect.Iterables;

import paillierp.PaillierThreshold;
import paillierp.key.PaillierPrivateThresholdKey;
import paillierp.zkp.DecryptionZKP;

/**
 * 
 * @author wangnan
 *
 */
public class Decrypter {

	private final PaillierThreshold paillier;

	public Decrypter(PaillierPrivateThresholdKey key) {
		this.paillier = new PaillierThreshold(key);
	}

	public DecryptionZKP decryptProof(BigInteger c) {
		return this.paillier.decryptProof(c);
	}

	public BigInteger combineShares(List<DecryptionZKP> shares) {
		return this.paillier.combineShares(Iterables.toArray(shares, DecryptionZKP.class));
	}
}

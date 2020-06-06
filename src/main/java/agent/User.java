package agent;

import java.math.BigInteger;
import java.util.List;
import java.util.stream.Collectors;

import com.google.common.collect.Lists;

import crypto.Decrypter;
import crypto.Encrypter;
import paillierp.Paillier;
import paillierp.key.PaillierPrivateThresholdKey;
import paillierp.zkp.DecryptionZKP;
import utils.Constants;

/**
 * 
 * @author wangnan
 *
 */
public class User {

	private static final BigInteger TWO = BigInteger.valueOf(2);

	private final int id;

	private final Encrypter encrypter;

	private final Decrypter decrypter;

	// UFS
	private final List<BigInteger> occupancies = Lists.newArrayList();
	private final List<BigInteger> sharedSchedule = Lists.newArrayList();

	private int scaling;
	private BigInteger big_scaling;

	// CSS
	private List<Double> gabages = Lists.newArrayList();
	private double instantGabage;

	private final BigInteger n;

	public User(int id, Paillier paillier, PaillierPrivateThresholdKey key, Config config) {
		this.id = id;
		this.encrypter = new Encrypter(paillier);
		this.decrypter = new Decrypter(key);
		this.scaling = config.getScaling();
		this.n = paillier.getPublicKey().getN();
		this.big_scaling = BigInteger.valueOf(this.scaling);
	}

	public void initOccupancies() {
		for (int i = 0; i < Constants.NUM_SLOTS; i++) {
			this.occupancies.add(zeroOrOne());
		}
	}

	public int getId() {
		return id;
	}

	public List<BigInteger> getOccupancies() {
		return this.occupancies;
	}

	public static BigInteger zeroOrOne() {
		return Math.random() > 0.5 ? BigInteger.ONE : BigInteger.ZERO;
	}

	/**
	 * Encrypt occupancies of users
	 * 
	 * @return
	 */
	public List<BigInteger> UFS_encryptOccupancies() {
		return this.occupancies.stream().map(i -> this.encrypter.encrypt(i)).collect(Collectors.toList());
	}

	public DecryptionZKP UFS_decryptOccupancyShare(BigInteger cipher) {
		return this.decrypter.decryptProof(cipher);
	}

	/**
	 * Outer slots Inner random userIDs
	 * 
	 * @param shares
	 * @return
	 */
	public List<BigInteger> UFS_combineOccupancyShares(List<List<DecryptionZKP>> sharesList) {
		List<BigInteger> ret = Lists.newArrayList();
		for (int i = 0; i < sharesList.size(); i++) {
			BigInteger b = convertResult(this.decrypter.combineShares(sharesList.get(i)));
			if (this.occupancies.get(i).intValue() == 1) {
				ret.add(b);
			} else {
				ret.add(BigInteger.ZERO);
			}
		}

		this.sharedSchedule.addAll(ret);

		return ret;
	}

	public List<BigInteger> UFS_encryptCoarseOccupancies(List<BigInteger> randoms) {
		List<BigInteger> ret = Lists.newArrayList();
		for (int i = 0; i < Constants.NUM_SLOTS; i++) {
			if (this.occupancies.get(i).intValue() == 1) {
				ret.add(this.encrypter
						.encrypt(scale(Constants.P / this.sharedSchedule.get(i).doubleValue() + randoms.get(i).doubleValue())));
			} else {
				ret.add(this.encrypter.encrypt(scale(randoms.get(i))));
			}
		}

		return ret;
	}

	/**
	 * Outer -> userIDs Inner -> occupancies
	 * 
	 * @param ciphers
	 * @return
	 */
	public List<DecryptionZKP> UFS_decryptCoarseOccupancyShare(List<BigInteger> ciphers) {
		List<DecryptionZKP> ret = Lists.newArrayList();
		for (int i = 0; i < Constants.NUM_SLOTS; i++) {
			ret.add(this.decrypter.decryptProof(ciphers.get(i)));
		}

		return ret;
	}

	public List<BigInteger> UFS_combineCoarseOccupancyShares(List<List<DecryptionZKP>> shares) {
		List<BigInteger> ret = Lists.newArrayList();
		for (int i = 0; i < Constants.NUM_SLOTS; i++) {
			List<DecryptionZKP> list = Lists.newArrayList();
			for (List<DecryptionZKP> share : shares) {
				list.add(share.get(i));
			}
			// ret.add(convertResult(BigInteger
			// .valueOf((long)
			// Math.ceil(this.decrypter.combineShares(list).doubleValue() /
			// this.scaling))));
			ret.add(BigInteger.valueOf(
					(long) Math.ceil(convertResult(this.decrypter.combineShares(list)).doubleValue() / this.scaling)));

		}

		return ret;
	}

	/**
	 * CSS
	 * 
	 * @param num_users
	 * @return
	 */
	public BigInteger CSS_encryptInstantGabage(int num_users) {
		return this.encrypter.encrypt(scale(this.instantGabage - Constants.C / num_users));
	}

	public List<BigInteger> CSS_encryptGabage() {
		return this.gabages.stream().map(gabage -> this.encrypter.encrypt(scale(gabage))).collect(Collectors.toList());
	}

	public void CSS_generateGabage() {
		double amount = 10 + Math.random() * 10;
		this.instantGabage += amount;
	}

	public double getInstantGabage() {
		return this.instantGabage;
	}

	public void recordInstantGabages() {
		this.gabages.add(this.instantGabage);
		this.instantGabage = 0;
	}

	public List<Double> getGabages() {
		return gabages;
	}

	public DecryptionZKP CSS_decryptCipher(BigInteger cipher) {
		return this.decrypter.decryptProof(cipher);
	}

	public BigInteger CSS_combineAllShares1(List<DecryptionZKP> list) {
		return convertResult(this.decrypter.combineShares(list));
	}

	public List<BigInteger> CSS_combineAllShares2(List<List<DecryptionZKP>> list) {
		return list.stream().map(shares -> convertResult(this.decrypter.combineShares(shares)))
				.collect(Collectors.toList());
	}

	public BigInteger getStage1Ret(BigInteger b) {
		return b.divide(this.big_scaling);
	}

	public List<Double> getStage2Ret(List<BigInteger> list) {
		List<Double> ret = Lists.newArrayList();
		for (int i = 0; i < list.size(); i++) {
			double amount = list.get(i).doubleValue() / (Math.pow(this.scaling, 2) * this.gabages.get(i));
			ret.add(amount);
		}

		return ret;
	}

	public BigInteger convertResult(BigInteger ret) {
		if (ret.compareTo(this.n.divide(TWO)) == -1) {
			return ret;
		} else {
			return ret.subtract(this.n);
		}
	}

	public List<BigInteger> CSS_addRandomToCiphersFromOperator(List<BigInteger> ciphers) {
		List<BigInteger> list = Lists.newArrayList();
		for (int i = 0; i < ciphers.size(); i++) {
			BigInteger ret = this.encrypter.multiplyCiphers(ciphers.get(i), scale(this.gabages.get(i)));
			list.add(this.encrypter.addCiphers(ret, this.encrypter.encrypt(BigInteger.ZERO)));
		}

		return list;
	}

	public BigInteger scale(BigInteger b) {
		return b.multiply(this.big_scaling);
	}

	public BigInteger scale(double b) {
		return BigInteger.valueOf((int) (b * this.scaling));
	}
}

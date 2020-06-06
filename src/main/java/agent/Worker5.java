package agent;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

import com.google.common.collect.Lists;

import crypto.Encrypter;
import result.Worker125Result;

/**
 * 
 * @author wangnan
 *
 */
public class Worker5 implements Callable<Worker125Result> {

	private int id;
	private List<Integer> slots;
	private Map<Integer, List<BigInteger>> ciphers;
	private Map<Integer, List<BigInteger>> userCiphers;
	private Operator operator;
	private Encrypter encrypter;

	public Worker5(int id, List<Integer> slots, Map<Integer, List<BigInteger>> ciphers, Operator operator) {
		this.id = id;
		this.slots = slots;
		this.ciphers = ciphers;
		this.userCiphers = operator.getUserCiphers();
		this.operator = operator;
		this.encrypter = operator.getEncrypter();
	}

	@Override
	public Worker125Result call() throws Exception {
		long s = System.nanoTime();
		Map<Integer, List<BigInteger>> finalMap = new HashMap<>();
		this.ciphers.forEach((id, cipher) -> {
			List<BigInteger> result = Lists.newArrayList();
			for (int i = 0; i < this.slots.size(); i++) {
				int idx = this.slots.get(i);
				
				BigInteger oldCipher = this.userCiphers.get(id).get(idx);
				BigInteger negativeRandom = this.operator.scale(this.operator.getCss_randoms().get(idx)).negate();
				BigInteger multiplier = this.encrypter.multiplyCiphers(oldCipher, negativeRandom);
				result.add(this.encrypter.addCiphers(cipher.get(idx), multiplier));
			}
			finalMap.put(id, result);
		});
		long e = System.nanoTime();

		return new Worker125Result(this.id, finalMap, e - s);
	}
}

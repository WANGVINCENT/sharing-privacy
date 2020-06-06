package agent;

import java.math.BigInteger;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.Callable;

import com.google.common.collect.Lists;

import crypto.Encrypter;
import result.Worker34Result;

/**
 * 
 * @author wangnan
 *
 */
public class Worker4 implements Callable<Worker34Result> {

	private int id;
	private List<Integer> slots;

	private Collection<List<BigInteger>> ciphers;

	private Operator operator;
	private Encrypter encrypter;

	public Worker4(int id, List<Integer> slots, Collection<List<BigInteger>> ciphers, 
			Operator operator) {
		this.id = id;
		this.slots = slots;
		this.ciphers = ciphers;
		this.operator = operator;
		this.encrypter = operator.getEncrypter();
	}

	@Override
	public Worker34Result call() throws Exception {
		
		long s = System.nanoTime();
		List<BigInteger> finalRet = Lists.newArrayList();
		for (int i = 0; i < this.slots.size(); i++) {
			int idx = this.slots.get(i);
			
			Iterator<List<BigInteger>> it = this.ciphers.iterator();

			BigInteger ret = it.next().get(idx);
			while (it.hasNext()) {
				BigInteger nextCipher = it.next().get(idx);
				ret = this.encrypter.addCiphers(ret, nextCipher);
			}
			BigInteger encryptedRandom = this.encrypter.encrypt(this.operator.scale(this.operator.getCss_randoms().get(idx)));
			ret = this.encrypter.addCiphers(ret, encryptedRandom);

			finalRet.add(ret);
		}
		long e = System.nanoTime();

		return new Worker34Result(this.id, finalRet, e - s);
	}
}

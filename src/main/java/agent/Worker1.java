package agent;

import java.math.BigInteger;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.Callable;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;

import agent.Operator.UserInfo;
import crypto.Encrypter;
import result.Worker125Result;
import utils.Constants;

/**
 * 
 * @author wangnan
 *
 */
public class Worker1 implements Callable<Worker125Result> {

	private int id;
	private List<Integer> slots;
	private Map<Integer, UserInfo> users;
	private Encrypter encrypter;
	
	public Worker1(int id, List<Integer> slots, Operator operator) {
		this.id = id;
		this.users = operator.getUsers();
		this.slots = slots;
		this.encrypter = operator.getEncrypter();		
	}

	@Override
	public Worker125Result call() {
		
		long s = System.nanoTime();
		List<BigInteger> finalRet = Lists.newArrayList();
		for (int i = 0; i < this.slots.size(); i++) {
			int idx = this.slots.get(i);
			
			Iterator<UserInfo> it = this.users.values().iterator();
			BigInteger ret = it.next().getCiphers().get(idx);
			while (it.hasNext()) {
				BigInteger nextCiphers = it.next().getCiphers().get(idx);
				ret = this.encrypter.addCiphers(ret, nextCiphers);
			}
			
			finalRet.add(ret);
		}
		
		Map<Integer, List<BigInteger>> finalMap = Maps.newHashMap();
		this.users.forEach((uid, info) -> {
			List<BigInteger> ciphers = info.getCiphers();
			List<BigInteger> result = Lists.newArrayList();
			for (int i = 0; i < this.slots.size(); i++) {
				int idx = this.slots.get(i);
				
				BigInteger random = new BigInteger(Constants.BITS_SMALL_RANDOM, new Random());

				BigInteger ret = this.encrypter.addCiphers(finalRet.get(i), this.encrypter.encrypt(random));
				BigInteger exponential = this.encrypter.multiplyCiphers(ciphers.get(idx), random.negate());
				result.add(this.encrypter.addCiphers(ret, exponential));
			}
			finalMap.put(uid, result);
		});
		
		long e = System.nanoTime();
		
		return new Worker125Result(this.id, finalMap, e - s);
	}
}

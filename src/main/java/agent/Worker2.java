package agent;

import java.math.BigInteger;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.Callable;

import com.google.common.collect.Lists;

import agent.Operator.UserInfo;
import result.Worker125Result;
import utils.Constants;

/**
 * 
 * @author wangnan
 *
 */
public class Worker2 implements Callable<Worker125Result> {

	private int id;
	private int slotSize;
	private Collection<UserInfo> users;

	public Worker2(int id, int num_cores, Collection<UserInfo> users) {
		this.id = id;
		this.slotSize = Constants.NUM_SLOTS / num_cores;
		this.users = users;
	}

	@Override
	public Worker125Result call() throws Exception {
		long s = System.nanoTime();
		Map<Integer, List<BigInteger>> map = new HashMap<>();
		this.users.forEach(user -> {
			List<BigInteger> randoms = Lists.newArrayList();
			for (int i = 0; i < this.slotSize; i++) {
				randoms.add(new BigInteger(Constants.BITS_SMALL_RANDOM, new Random()));
			}
			map.put(user.getId(), randoms);
		});
		long e = System.nanoTime();

		return new Worker125Result(this.id, map, e-s);
	}
}

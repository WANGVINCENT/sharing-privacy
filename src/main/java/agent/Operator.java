package agent;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import com.google.common.collect.Lists;

import crypto.Encrypter;
import paillierp.Paillier;
import utils.Constants;

/**
 * 
 * @author wangnan
 *
 */
public class Operator {

	private final Map<Integer, UserInfo> users = new HashMap<>();

	private final Encrypter encrypter;

	private List<BigInteger> css_randoms = Lists.newArrayList();

	private int scaling;

	private BigInteger big_scaling;

	private final Map<Integer, List<BigInteger>> userCiphers = new HashMap<>();

	public Operator(Paillier paillier, Config config) {
		this.encrypter = new Encrypter(paillier);
		this.scaling = config.getScaling();
		this.big_scaling = BigInteger.valueOf(this.scaling);
	}

	public void initRandoms() {
		for (int i = 0; i < Constants.NUM_SLOTS; i++) {
			this.css_randoms.add(new BigInteger(Constants.BITS_SMALL_RANDOM, new Random()));
		}
	}

	public void cacheUserInfo(Map<Integer, List<BigInteger>> ciphersMap) {
		// store user info locally
		ciphersMap.forEach((id, ciphers) -> {
			this.users.put(id, new UserInfo(id, ciphers));
		});
	}
	
	public void cacheUserRandoms(Map<Integer, List<BigInteger>> randoms){
		for(UserInfo info : this.users.values()){
			int id = info.getId();
			info.setRandoms(randoms.get(id));
		}
	}
	
	public List<List<Integer>> divideSlots(int num_cores) {
		List<Integer> list = Lists.newArrayList();
		for (int i = 0; i < Constants.NUM_SLOTS; i++) {
			list.add(i);
		}

		return Lists.partition(list, Constants.NUM_SLOTS / num_cores);
	}
	
	public List<List<BigInteger>> divideRandoms(int num_cores) {
		return Lists.partition(this.css_randoms, Constants.NUM_SLOTS / num_cores);
	}

	public Set<Integer> generateRandomUserIDs(int max, int decrypt_number, int not_this_id) {

		int min = 0;
		int count = 0;
		Set<Integer> userIDs = new HashSet<>();
		Random rand = new Random();
		while (count < decrypt_number) {
			int id = 0;
			do {
				id = rand.nextInt(max - min) + min;
			} while (userIDs.contains(id) || id == not_this_id);
			userIDs.add(id);
			count++;
		}
		userIDs.add(not_this_id);
		
		return userIDs;
	}

	/**
	 * Update a new random integer for each user
	 * 
	 * @return
	 */
	public Map<Integer, List<BigInteger>> UFS_distributeRandomNumber() {
		Map<Integer, List<BigInteger>> map = new HashMap<>();
		this.users.values().forEach(user -> {
			List<BigInteger> randoms = Lists.newArrayList();
			for (int i = 0; i < Constants.NUM_SLOTS; i++) {
				randoms.add(new BigInteger(Constants.KEY_BITS_LENGTH, new Random()));
			}
			user.setRandoms(randoms);
			map.put(user.getId(), randoms);
		});

		return map;
	}

	public List<BigInteger> UFS_combineUserCiphers2(Map<Integer, List<BigInteger>> ciphers) {

		List<BigInteger> finalRet = Lists.newArrayList();
		for (int i = 0; i < Constants.NUM_SLOTS; i++) {
			Iterator<List<BigInteger>> it = ciphers.values().iterator();

			BigInteger ret = it.next().get(i);
			while (it.hasNext()) {
				BigInteger nextCipher = it.next().get(i);
				ret = this.encrypter.addCiphers(ret, nextCipher);
			}

			finalRet.add(ret);
		}

		return finalRet;
	}

	public List<BigInteger> UFS_getCoarseOccupancies(List<BigInteger> ciphers) {

		List<BigInteger> ret = Lists.newArrayList();
		for (int i = 0; i < Constants.NUM_SLOTS; i++) {
			Iterator<UserInfo> it = this.users.values().iterator();
			BigInteger sum = it.next().getRandoms().get(i);
			while (it.hasNext()) {
				BigInteger next = it.next().getRandoms().get(i);
				sum = sum.add(next);
			}
			
			ret.add(ciphers.get(i).subtract(sum));
		}

		return ret;
	}

	public BigInteger CSS_generateRandom() {
		BigInteger random = null;
		do {
			random = new BigInteger(Constants.BITS_SMALL_RANDOM, new Random());
			if (random.intValue() < 0) {
				random = random.negate();
			}
		} while (random.intValue() == 0);

		return random;
	}

	public BigInteger CSS_aggregateUserCiphers(List<BigInteger> ciphers) {
		return this.encrypter.addCiphers(ciphers);
	}

	public BigInteger scale(BigInteger b) {
		return b.multiply(this.big_scaling);
	}

	public Encrypter getEncrypter() {
		return encrypter;
	}

	public List<BigInteger> getCss_randoms() {
		return css_randoms;
	}

	public Map<Integer, UserInfo> getUsers() {
		return users;
	}
	
	public Map<Integer, List<BigInteger>> getUserCiphers() {
		return userCiphers;
	}
	
	public void setUserCiphers(Map<Integer, List<BigInteger>> ciphers) {
		this.userCiphers.putAll(ciphers);
	}
	
	
	
	/**
	 * User Information stored by the operator
	 * 
	 * @author wangnan
	 *
	 */
	public static class UserInfo {

		private final int id;
		private List<BigInteger> ciphers;
		private List<BigInteger> randoms;

		public UserInfo(int id, List<BigInteger> ciphers) {
			this.id = id;
			this.ciphers = ciphers;
		}

		public UserInfo(int id) {
			this.id = id;
		}

		public List<BigInteger> getCiphers() {
			return ciphers;
		}

		public void setCiphers(List<BigInteger> ciphers) {
			this.ciphers = ciphers;
		}

		public int getId() {
			return id;
		}

		public List<BigInteger> getRandoms() {
			return randoms;
		}

		public void setRandoms(List<BigInteger> randoms) {
			this.randoms = randoms;
		}
	}
}
